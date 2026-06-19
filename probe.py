#!/usr/bin/env python3
"""
AuditDeck — motor de red con sockets (probe.py)

Dos capacidades, ambas con la libreria estandar de Python:

  1. connect : cliente de socket crudo (TCP / TLS) interactivo. Te deja
     "hablar" un protocolo a mano (HTTP, SMTP, Redis, lo que sea) y ver la
     respuesta byte a byte. Perfecto para entender que viaja realmente por
     el cable y para banner grabbing.

  2. fuzz : prueba AUTOMATIZADA de variaciones. Toma una request con un
     marcador (FUZZ por defecto), substituye una lista de payloads, los
     envia por socket y compara cada variacion contra una baseline para
     resaltar anomalias: errores SQL/SSTI, reflexion (XSS), retardos
     (SQLi ciega por tiempo), diferencias de estado/longitud.

USO RESPONSABLE
---------------
Esto envia trafico real a un servidor. Usalo SOLO contra objetivos para los
que tengas permiso explicito: tus labs de PortSwigger / Web Security Academy,
CTFs, entornos propios o engagements autorizados por escrito. Hay un gate de
autorizacion antes de tocar la red.
"""
from __future__ import annotations

import ipaddress
import random
import re
import socket
import ssl
import string
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit

# ---------------------------------------------------------------------------
# Colores (reutiliza los del CLI si esta disponible; si no, no-op)
# ---------------------------------------------------------------------------
try:
    from auditdeck import bold, cyan, dim, green, red, yellow  # type: ignore
except Exception:  # pragma: no cover - fallback si se ejecuta aislado
    def _id(t: str) -> str:
        return t

    bold = cyan = dim = green = red = yellow = _id  # type: ignore


# ---------------------------------------------------------------------------
# Gate de autorizacion
# ---------------------------------------------------------------------------
# Dominios de practica conocidos donde el titular de la cuenta SI tiene permiso.
_LAB_DOMAIN_SUFFIXES = (
    ".web-security-academy.net",  # PortSwigger Web Security Academy
    ".localhost",
    ".lab",
    ".local",
    ".test",
    ".htb",          # Hack The Box
    ".thm",          # TryHackMe naming habitual
)
_LAB_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}


class AuthorizationError(RuntimeError):
    """Se lanza cuando el usuario no confirma autorizacion sobre el objetivo."""


def is_probably_lab_host(host: str) -> bool:
    """Heuristica: ¿parece un host de laboratorio/privado y por tanto 'seguro'?

    No es una garantia de permiso (eso es responsabilidad del usuario), solo
    decide si pedimos confirmacion suave o una mas explicita.
    """
    h = host.strip().lower().rstrip(".")
    if h in _LAB_HOSTNAMES:
        return True
    if any(h.endswith(suf) for suf in _LAB_DOMAIN_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def confirm_authorization(host: str, assume_yes: bool = False) -> None:
    """Pide confirmacion de autorizacion antes de enviar trafico.

    - Si assume_yes esta activo, solo imprime un recordatorio y sigue.
    - Para hosts que parecen de laboratorio: confirmacion suave (Enter / y).
    - Para el resto: hay que escribir literalmente el host para continuar.
    """
    lab = is_probably_lab_host(host)
    banner = yellow(
        "\n  ⚠  AuditDeck va a enviar TRAFICO REAL al objetivo.\n"
        "     Usalo solo contra sistemas con permiso explicito "
        "(tus labs, CTFs, engagements autorizados).\n"
    )
    print(banner, file=sys.stderr)

    if assume_yes:
        print(dim(f"     [--yes] Autorizacion asumida para {host}.\n"), file=sys.stderr)
        return

    if not sys.stdin.isatty():
        raise AuthorizationError(
            "No hay terminal interactiva para confirmar. Usa --yes solo si "
            "tienes permiso sobre el objetivo."
        )

    if lab:
        ans = input(f"  Objetivo {cyan(host)} parece un lab/host privado. ¿Continuar? [Y/n] ").strip().lower()
        if ans in ("", "y", "yes", "s", "si"):
            return
        raise AuthorizationError("Cancelado por el usuario.")

    print(
        red(
            f"  {host} NO parece un host de laboratorio. Para continuar, escribe el host\n"
            f"  exactamente, confirmando que tienes autorizacion para probarlo."
        ),
        file=sys.stderr,
    )
    typed = input(f"  Escribe '{host}' para confirmar: ").strip()
    if typed != host:
        raise AuthorizationError("Host no confirmado. Cancelado.")


# ---------------------------------------------------------------------------
# Socket crudo (TCP / TLS)
# ---------------------------------------------------------------------------
@dataclass
class RawResponse:
    data: bytes = b""
    elapsed_ms: float = 0.0
    error: str | None = None

    @property
    def text(self) -> str:
        return self.data.decode("utf-8", errors="replace")


def open_socket(host: str, port: int, use_tls: bool, timeout: float, sni: str | None = None):
    """Abre un socket TCP, opcionalmente envuelto en TLS. Devuelve el socket."""
    raw = socket.create_connection((host, port), timeout=timeout)
    if not use_tls:
        return raw
    ctx = ssl.create_default_context()
    # En labs es comun encontrar certificados que no validan; no rompemos por eso,
    # pero avisamos. El objetivo aqui es aprender, no MITM real.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(raw, server_hostname=sni or host)


def send_raw(
    host: str,
    port: int,
    payload: bytes,
    *,
    use_tls: bool = False,
    timeout: float = 8.0,
    read_limit: int = 65536,
) -> RawResponse:
    """Abre conexion, envia 'payload', lee la respuesta y mide el tiempo."""
    start = time.perf_counter()
    sock = None
    try:
        sock = open_socket(host, port, use_tls, timeout)
        sock.settimeout(timeout)
        if payload:
            sock.sendall(payload)
        chunks: list[bytes] = []
        total = 0
        while total < read_limit:
            try:
                chunk = sock.recv(min(8192, read_limit - total))
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        elapsed = (time.perf_counter() - start) * 1000
        return RawResponse(data=b"".join(chunks), elapsed_ms=elapsed)
    except (OSError, ssl.SSLError) as exc:
        elapsed = (time.perf_counter() - start) * 1000
        return RawResponse(elapsed_ms=elapsed, error=str(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def interactive_connect(
    host: str,
    port: int,
    *,
    use_tls: bool = False,
    timeout: float = 8.0,
) -> int:
    """Cliente de socket interactivo: escribe lineas, ve la respuesta cruda.

    Cada linea que escribes se envia con CRLF. Linea vacia = solo recibir.
    Escribe :quit (o Ctrl+D) para salir. Util para hablar HTTP/SMTP/etc a mano.
    """
    print(bold(cyan(f"\n  Conectando a {host}:{port}{' (TLS)' if use_tls else ''} ...")))
    try:
        sock = open_socket(host, port, use_tls, timeout)
    except (OSError, ssl.SSLError) as exc:
        print(red(f"  No se pudo conectar: {exc}"))
        return 1
    sock.settimeout(1.5)
    print(green("  Conectado.") + dim("  Escribe lineas (se envian con CRLF). :quit para salir.\n"))

    def drain() -> None:
        buf = []
        while True:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                break
            except OSError:
                break
            if not chunk:
                break
            buf.append(chunk)
        if buf:
            sys.stdout.write(b"".join(buf).decode("utf-8", errors="replace"))
            sys.stdout.write("\n")
            sys.stdout.flush()

    # Banner inicial si el servidor habla primero (SMTP, FTP, SSH...).
    drain()
    try:
        while True:
            try:
                line = input(dim("» "))
            except EOFError:
                break
            if line.strip() in (":quit", ":q", ":exit"):
                break
            try:
                sock.sendall((line + "\r\n").encode("utf-8", errors="replace"))
            except OSError as exc:
                print(red(f"  Conexion cerrada: {exc}"))
                break
            drain()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    print(dim("\n  Conexion cerrada.\n"))
    return 0


# ---------------------------------------------------------------------------
# Construccion / parsing de HTTP sobre socket crudo
# ---------------------------------------------------------------------------
def build_http_request(
    method: str,
    path: str,
    host_header: str,
    *,
    headers: dict[str, str] | None = None,
    body: str = "",
    http_version: str = "1.1",
) -> bytes:
    """Construye una request HTTP cruda como bytes (cierra conexion por defecto)."""
    headers = dict(headers or {})
    headers.setdefault("Host", host_header)
    headers.setdefault("User-Agent", "AuditDeck/1.0 (+labs only)")
    headers.setdefault("Accept", "*/*")
    headers.setdefault("Connection", "close")
    if body:
        headers["Content-Length"] = str(len(body.encode("utf-8")))
    lines = [f"{method.upper()} {path} HTTP/{http_version}"]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    raw = "\r\n".join(lines) + "\r\n\r\n" + body
    return raw.encode("utf-8", errors="replace")


@dataclass
class HttpResponse:
    status: int | None = None
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw_len: int = 0
    elapsed_ms: float = 0.0
    error: str | None = None

    @property
    def body_len(self) -> int:
        return len(self.body)

    @property
    def word_count(self) -> int:
        return len(self.body.split())


def parse_http_response(raw: bytes, elapsed_ms: float, error: str | None) -> HttpResponse:
    resp = HttpResponse(elapsed_ms=elapsed_ms, error=error, raw_len=len(raw))
    if error or not raw:
        return resp
    head, _, body = raw.partition(b"\r\n\r\n")
    text = head.decode("utf-8", errors="replace")
    lines = text.split("\r\n")
    if lines:
        m = re.match(r"HTTP/\d\.\d\s+(\d{3})\s*(.*)", lines[0])
        if m:
            resp.status = int(m.group(1))
            resp.reason = m.group(2).strip()
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            resp.headers[k.strip().lower()] = v.strip()
    resp.body = body.decode("utf-8", errors="replace")
    return resp


def request_from_url(url: str) -> tuple[str, int, bool, str, str]:
    """Descompone una URL en (host, port, use_tls, path_con_query, host_header)."""
    parts = urlsplit(url if "://" in url else "http://" + url)
    use_tls = parts.scheme == "https"
    host = parts.hostname or "127.0.0.1"
    port = parts.port or (443 if use_tls else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    host_header = host if (port in (80, 443)) else f"{host}:{port}"
    return host, port, use_tls, path, host_header


# ---------------------------------------------------------------------------
# Motor de fuzzing: variaciones contra baseline
# ---------------------------------------------------------------------------
# Firmas de error tipicas que delatan una vulnerabilidad al inyectar payloads.
ERROR_SIGNATURES: list[tuple[str, str]] = [
    (r"SQL syntax.*MySQL", "MySQL error"),
    (r"Warning.*mysqli?_", "MySQL warning"),
    (r"PostgreSQL.*ERROR", "PostgreSQL error"),
    (r"ORA-\d{5}", "Oracle error"),
    (r"Microsoft.*ODBC.*SQL Server", "MSSQL error"),
    (r"SQLite/JDBCDriver|SQLITE_ERROR|sqlite3\.OperationalError", "SQLite error"),
    (r"Unclosed quotation mark", "MSSQL quote error"),
    (r"quoted string not properly terminated", "Oracle quote error"),
    (r"java\.lang\.[A-Za-z.]*Exception", "Java stack trace"),
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"<b>Warning</b>:|<b>Fatal error</b>:", "PHP error"),
    (r"root:.*:0:0:", "/etc/passwd leak"),
    (r"\bON ERROR\b|Template parse error|jinja2\.exceptions", "Template engine error"),
]

# Tokens que, si aparecen reflejados intactos, sugieren XSS/inyeccion de contexto.
_REFLECT_MARKER = "ADxss"


@dataclass
class ProbeResult:
    payload: str
    label: str = ""
    status: int | None = None
    body_len: int = 0
    words: int = 0
    elapsed_ms: float = 0.0
    reflected: bool = False
    errors: list[str] = field(default_factory=list)
    transport_error: str | None = None
    score: float = 0.0
    notes: list[str] = field(default_factory=list)


def _detect_errors(body: str) -> list[str]:
    found = []
    for pattern, name in ERROR_SIGNATURES:
        if re.search(pattern, body, re.IGNORECASE):
            found.append(name)
    return found


def _rand_token(n: int = 6) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _encode_payload(payload: str, encode: str) -> str:
    """Codifica el payload segun el contexto de inyeccion."""
    if encode == "url":
        # safe='' codifica tambien / ? & = espacios — apto para valor de query.
        return quote(payload, safe="")
    return payload


def _send_one(
    host: str,
    port: int,
    use_tls: bool,
    request_template: bytes,
    marker: bytes,
    payload: str,
    timeout: float,
    delay_baseline_ms: float | None,
    encode: str = "none",
) -> ProbeResult:
    injected = _encode_payload(payload, encode)
    body_bytes = request_template.replace(marker, injected.encode("utf-8", errors="replace"))
    # Recalcular Content-Length si hay cuerpo (marker pudo cambiar su tamaño).
    body_bytes = _fix_content_length(body_bytes)
    raw = send_raw(host, port, body_bytes, use_tls=use_tls, timeout=timeout)
    parsed = parse_http_response(raw.data, raw.elapsed_ms, raw.error)
    res = ProbeResult(
        payload=payload,
        status=parsed.status,
        body_len=parsed.body_len,
        words=parsed.word_count,
        elapsed_ms=parsed.elapsed_ms,
        transport_error=parsed.error,
    )
    res.reflected = payload != "" and payload in parsed.body
    res.errors = _detect_errors(parsed.body)
    return res


def _fix_content_length(request: bytes) -> bytes:
    head, sep, body = request.partition(b"\r\n\r\n")
    if not sep or not body:
        return request
    new_len = str(len(body)).encode()
    if re.search(rb"(?im)^content-length:", head):
        head = re.sub(rb"(?im)^content-length:.*$", b"Content-Length: " + new_len, head)
    return head + sep + body


def run_fuzz(
    *,
    host: str,
    port: int,
    use_tls: bool,
    request_template: bytes,
    marker: str,
    payloads: list[tuple[str, str]],  # (payload, label)
    timeout: float = 8.0,
    throttle: float = 0.0,
    encode: str = "none",
    on_progress=None,
) -> list[ProbeResult]:
    """Envia baseline + cada payload y puntua anomalias.

    Devuelve la lista de ProbeResult ordenada por 'interestingness' (score).
    """
    marker_b = marker.encode()
    if marker_b not in request_template:
        raise ValueError(f"El marcador '{marker}' no aparece en la request.")

    # Baseline: un token benigno aleatorio para conocer la respuesta "normal".
    baseline_payload = _rand_token()
    baseline = _send_one(host, port, use_tls, request_template, marker_b, baseline_payload, timeout, None, encode)
    baseline.label = "baseline"
    base_len = baseline.body_len
    base_status = baseline.status
    base_time = baseline.elapsed_ms

    results: list[ProbeResult] = []
    for i, (payload, label) in enumerate(payloads, 1):
        res = _send_one(host, port, use_tls, request_template, marker_b, payload, timeout, base_time, encode)
        res.label = label
        res.score, res.notes = _score(res, base_len, base_status, base_time)
        results.append(res)
        if on_progress:
            on_progress(i, len(payloads), res)
        if throttle:
            time.sleep(throttle)

    results.sort(key=lambda r: -r.score)
    # Adjuntamos la baseline al final para referencia.
    results.append(baseline)
    return results


def _score(
    res: ProbeResult,
    base_len: int,
    base_status: int | None,
    base_time: float,
) -> tuple[float, list[str]]:
    """Heuristica de 'cuanto deberia mirar esto un humano'."""
    score = 0.0
    notes: list[str] = []

    if res.transport_error:
        notes.append(f"error de transporte: {res.transport_error}")
        return 1.0, notes

    if res.errors:
        score += 5.0 * len(res.errors)
        notes.append("firmas de error: " + ", ".join(res.errors))

    if res.reflected:
        score += 3.0
        notes.append("payload reflejado en la respuesta (posible XSS/inyeccion)")

    if base_status is not None and res.status is not None and res.status != base_status:
        score += 2.0
        notes.append(f"estado {res.status} != baseline {base_status}")

    if base_len:
        diff = abs(res.body_len - base_len)
        if diff > max(40, base_len * 0.10):
            score += 1.5
            notes.append(f"longitud {res.body_len} vs baseline {base_len} (Δ {diff})")

    # Retardo notable respecto a la baseline => posible SQLi/SSTI por tiempo.
    if base_time and res.elapsed_ms > max(2000.0, base_time * 3 + 1000):
        score += 4.0
        notes.append(f"tiempo {res.elapsed_ms:.0f}ms vs baseline {base_time:.0f}ms (posible blind/tiempo)")

    return score, notes
