#!/usr/bin/env python3
"""
AuditDeck — Tu copiloto de bolsillo para auditorias web y los labs de PortSwigger.

Base de conocimiento unificada de vulnerabilidades web: que buscar, como
detectarlo, pasos en Burp Suite, payloads, comandos y enlaces a los labs.

Uso responsable: usa esto solo contra sistemas para los que tengas permiso
explicito (tus labs de PortSwigger, CTFs, entornos propios o engagements
autorizados). Ver README.md.

Sin dependencias externas: solo la libreria estandar de Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"
VULNS_DIR = DATA_DIR / "vulns"
CHECKLISTS_DIR = DATA_DIR / "checklists"
CHEATSHEETS_DIR = DATA_DIR / "cheatsheets"

# ---------------------------------------------------------------------------
# Colores (se desactivan si no es un TTY o si NO_COLOR esta definido)
# ---------------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, code: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def bold(t: str) -> str:
    return _c(t, "1")


def cyan(t: str) -> str:
    return _c(t, "36")


def green(t: str) -> str:
    return _c(t, "32")


def yellow(t: str) -> str:
    return _c(t, "33")


def red(t: str) -> str:
    return _c(t, "31")


def dim(t: str) -> str:
    return _c(t, "2")


SEVERITY_COLORS = {
    "Critical": red,
    "High": red,
    "Medium": yellow,
    "Low": green,
    "Info": dim,
}


# ---------------------------------------------------------------------------
# Carga de datos
# ---------------------------------------------------------------------------
def load_vulns() -> list[dict]:
    vulns = []
    if not VULNS_DIR.is_dir():
        return vulns
    for path in sorted(VULNS_DIR.glob("*.json")):
        try:
            with path.open(encoding="utf-8") as fh:
                data = json.load(fh)
            data.setdefault("id", path.stem)
            vulns.append(data)
        except (json.JSONDecodeError, OSError) as exc:
            print(red(f"[!] No se pudo cargar {path.name}: {exc}"), file=sys.stderr)
    return vulns


def load_checklists() -> list[dict]:
    items = []
    if CHECKLISTS_DIR.is_dir():
        for path in sorted(CHECKLISTS_DIR.glob("*.json")):
            try:
                with path.open(encoding="utf-8") as fh:
                    items.append(json.load(fh))
            except (json.JSONDecodeError, OSError) as exc:
                print(red(f"[!] {path.name}: {exc}"), file=sys.stderr)
    return items


def load_cheatsheets() -> list[dict]:
    items = []
    if CHEATSHEETS_DIR.is_dir():
        for path in sorted(CHEATSHEETS_DIR.glob("*.json")):
            try:
                with path.open(encoding="utf-8") as fh:
                    items.append(json.load(fh))
            except (json.JSONDecodeError, OSError) as exc:
                print(red(f"[!] {path.name}: {exc}"), file=sys.stderr)
    return items


def find_vuln(vulns: list[dict], query: str) -> dict | None:
    q = query.strip().lower()
    # match exacto por id
    for v in vulns:
        if v.get("id", "").lower() == q:
            return v
    # match por nombre exacto
    for v in vulns:
        if v.get("name", "").lower() == q:
            return v
    # match por alias
    for v in vulns:
        for aka in v.get("aka", []):
            if aka.lower() == q:
                return v
    # match parcial por id/nombre
    candidates = [
        v
        for v in vulns
        if q in v.get("id", "").lower() or q in v.get("name", "").lower()
    ]
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        print(yellow(f"'{query}' es ambiguo. Coincidencias:"))
        for v in candidates:
            print(f"  - {cyan(v['id'])}  ({v.get('name','')})")
        return None
    return None


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
def _wrap(text: str, indent: str = "    ") -> str:
    width = min(os.environ.get("COLUMNS") and int(os.environ["COLUMNS"]) or 100, 100)
    return textwrap.fill(
        text,
        width=width,
        initial_indent=indent,
        subsequent_indent=indent,
    )


def severity_badge(sev: str) -> str:
    fn = SEVERITY_COLORS.get(sev, dim)
    return fn(f"[{sev}]")


def cmd_list(args) -> int:
    vulns = load_vulns()
    if not vulns:
        print(red("No hay vulnerabilidades cargadas. Revisa data/vulns/."))
        return 1

    by_cat: dict[str, list[dict]] = {}
    for v in vulns:
        by_cat.setdefault(v.get("category", "Otros"), []).append(v)

    print(bold(f"\nAuditDeck — {len(vulns)} temas en la base de conocimiento\n"))
    for cat in sorted(by_cat):
        print(bold(cyan(f"  {cat}")))
        for v in sorted(by_cat[cat], key=lambda x: x.get("name", "")):
            sev = severity_badge(v.get("severity", "Info"))
            print(f"    {green(v['id']):<34} {sev:<10} {v.get('name','')}")
        print()
    print(dim("  Usa:  auditdeck show <id>   |   auditdeck search <termino>\n"))
    return 0


def cmd_search(args) -> int:
    vulns = load_vulns()
    terms = [t.lower() for t in args.terms]

    results = []
    for v in vulns:
        haystack = json.dumps(v, ensure_ascii=False).lower()
        score = sum(haystack.count(t) for t in terms)
        if all(t in haystack for t in terms):
            results.append((score, v))

    if not results:
        print(yellow(f"Sin resultados para: {' '.join(args.terms)}"))
        return 1

    results.sort(key=lambda x: -x[0])
    print(bold(f"\n{len(results)} resultado(s) para: {cyan(' '.join(args.terms))}\n"))
    for score, v in results:
        sev = severity_badge(v.get("severity", "Info"))
        print(f"  {green(v['id']):<34} {sev:<10} {v.get('name','')}")
        # Muestra donde hizo match (en payloads / pasos)
        snippets = _match_snippets(v, terms)
        for s in snippets[:2]:
            print(dim(f"      … {s}"))
    print(dim("\n  Abre uno con:  auditdeck show <id>\n"))
    return 0


def _match_snippets(v: dict, terms: list[str], maxlen: int = 90) -> list[str]:
    out = []
    blocks = []
    blocks.extend(v.get("detection", []))
    blocks.extend(v.get("burp_steps", []))
    for group in v.get("payloads", {}).values():
        blocks.extend(group)
    for line in blocks:
        low = line.lower()
        if any(t in low for t in terms):
            s = line.strip().replace("\n", " ")
            if len(s) > maxlen:
                s = s[: maxlen - 1] + "…"
            out.append(s)
    return out


def _print_section(title: str, items, numbered: bool = False) -> None:
    if not items:
        return
    print(bold(yellow(f"\n  {title}")))
    for i, item in enumerate(items, 1):
        prefix = f"  {i}." if numbered else "   •"
        print(_wrap(f"{prefix} {item}", indent="      ").replace("      ", "   ", 1))


def cmd_show(args) -> int:
    vulns = load_vulns()
    v = find_vuln(vulns, args.id)
    if v is None:
        print(red(f"No encontrado: {args.id}"))
        print(dim("Lista los temas con:  auditdeck list"))
        return 1

    sev = severity_badge(v.get("severity", "Info"))
    print(bold(f"\n{cyan('═' * 70)}"))
    print(bold(f"  {v.get('name','')}  {sev}"))
    aka = v.get("aka", [])
    meta = f"  id: {v['id']}   categoria: {v.get('category','-')}"
    if aka:
        meta += f"   alias: {', '.join(aka)}"
    print(dim(meta))
    print(bold(cyan("═" * 70)))

    if v.get("summary"):
        print()
        print(_wrap(v["summary"], indent="  "))

    _print_section("Donde buscar", v.get("where_to_look", []))
    _print_section("Como detectar", v.get("detection", []))
    _print_section("Pasos en Burp Suite", v.get("burp_steps", []), numbered=True)

    payloads = v.get("payloads", {})
    if payloads:
        print(bold(yellow("\n  Payloads")))
        for group, items in payloads.items():
            print(f"   {bold(group)}")
            for p in items:
                print(green(f"      {p}"))

    commands = v.get("commands", [])
    if commands:
        print(bold(yellow("\n  Comandos")))
        for c in commands:
            print(dim(f"   # {c.get('desc','')}  ({c.get('tool','')})"))
            print(green(f"   $ {c.get('cmd','')}"))

    _print_section("Remediacion", v.get("remediation", []))

    labs = v.get("portswigger_labs", [])
    if labs:
        print(bold(yellow("\n  Labs de PortSwigger")))
        for lab in labs:
            tag = lab.get("difficulty", "")
            tag = f" [{tag}]" if tag else ""
            print(f"   • {lab.get('title','')}{dim(tag)}")
            print(cyan(f"     {lab.get('url','')}"))

    refs = v.get("references", [])
    if refs:
        print(bold(yellow("\n  Referencias")))
        for r in refs:
            print(f"   • {r.get('title','')}")
            print(cyan(f"     {r.get('url','')}"))
    print()
    return 0


def cmd_payloads(args) -> int:
    vulns = load_vulns()
    v = find_vuln(vulns, args.id)
    if v is None:
        print(red(f"No encontrado: {args.id}"))
        return 1
    payloads = v.get("payloads", {})
    if not payloads:
        print(yellow(f"{v['name']} no tiene payloads registrados."))
        return 0
    raw = args.raw
    if not raw:
        print(bold(f"\nPayloads — {v['name']}\n"))
    for group, items in payloads.items():
        if not raw:
            print(bold(yellow(f"  {group}")))
        for p in items:
            print(p if raw else green(f"   {p}"))
        if not raw:
            print()
    return 0


def cmd_labs(args) -> int:
    vulns = load_vulns()
    if args.id:
        v = find_vuln(vulns, args.id)
        if v is None:
            print(red(f"No encontrado: {args.id}"))
            return 1
        targets = [v]
    else:
        targets = vulns
    total = 0
    for v in targets:
        labs = v.get("portswigger_labs", [])
        if not labs:
            continue
        print(bold(cyan(f"\n{v['name']}")))
        for lab in labs:
            tag = lab.get("difficulty", "")
            tag = f" [{tag}]" if tag else ""
            print(f"  • {lab.get('title','')}{dim(tag)}")
            print(cyan(f"    {lab.get('url','')}"))
            total += 1
    print(dim(f"\n  {total} labs en total.\n"))
    return 0


def cmd_checklist(args) -> int:
    checklists = load_checklists()
    if not checklists:
        print(yellow("No hay checklists en data/checklists/."))
        return 1
    if args.name:
        q = args.name.lower()
        checklists = [
            c for c in checklists if q in c.get("name", "").lower() or q in c.get("id", "").lower()
        ]
        if not checklists:
            print(red(f"Checklist no encontrada: {args.name}"))
            return 1
    for c in checklists:
        print(bold(cyan(f"\n{c.get('name','Checklist')}")))
        if c.get("description"):
            print(_wrap(c["description"], indent="  "))
        for phase in c.get("phases", []):
            print(bold(yellow(f"\n  {phase.get('name','')}")))
            for item in phase.get("items", []):
                print(f"   [ ] {item}")
        print()
    return 0


def cmd_cheatsheet(args) -> int:
    sheets = load_cheatsheets()
    if not sheets:
        print(yellow("No hay cheatsheets en data/cheatsheets/."))
        return 1
    q = (args.topic or "").lower()
    for sheet in sheets:
        for section in sheet.get("sections", []):
            if q and q not in section.get("title", "").lower() and q not in json.dumps(
                section, ensure_ascii=False
            ).lower():
                continue
            print(bold(cyan(f"\n{section.get('title','')}")))
            for entry in section.get("entries", []):
                print(dim(f"  # {entry.get('desc','')}"))
                print(green(f"  $ {entry.get('cmd','')}"))
    print()
    return 0


def _flatten_payloads(v: dict) -> list[tuple[str, str]]:
    """Aplana los payloads de una vuln en (payload, etiqueta-de-grupo)."""
    out: list[tuple[str, str]] = []
    for group, items in v.get("payloads", {}).items():
        for p in items:
            out.append((p, group))
    return out


def _choose_vuln_payloads(vulns: list[dict]) -> list[tuple[str, str]] | None:
    """Selector interactivo: elige de que tema sacar los payloads a probar."""
    have = [v for v in vulns if v.get("payloads")]
    if not have:
        print(red("No hay temas con payloads en la base de conocimiento."))
        return None
    print(bold("\n  ¿Que payloads quieres probar?\n"))
    for i, v in enumerate(have, 1):
        n = sum(len(g) for g in v["payloads"].values())
        print(f"   {green(str(i)):>3}. {v.get('name',''):<28} {dim(f'({n} payloads)')}")
    print()
    try:
        raw = input("  Numero (o id): ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    chosen = None
    if raw.isdigit() and 1 <= int(raw) <= len(have):
        chosen = have[int(raw) - 1]
    else:
        chosen = find_vuln(have, raw)
    if chosen is None:
        print(red("Seleccion no valida."))
        return None
    return _flatten_payloads(chosen)


def cmd_connect(args) -> int:
    """Cliente de socket crudo (TCP/TLS) interactivo."""
    import probe

    host, port = args.host, args.port
    use_tls = args.tls or port == 443
    try:
        probe.confirm_authorization(host, assume_yes=args.yes)
    except probe.AuthorizationError as exc:
        print(red(f"  {exc}"), file=sys.stderr)
        return 2
    return probe.interactive_connect(host, port, use_tls=use_tls, timeout=args.timeout)


def cmd_fuzz(args) -> int:
    """Prueba automatizada: inyecta variaciones de payload y resalta anomalias."""
    import probe

    marker = args.marker

    # --- 1. Construir la request y averiguar a donde conectar ---
    if args.request:
        try:
            request_template = Path(args.request).read_bytes()
        except OSError as exc:
            print(red(f"No se pudo leer la request: {exc}"))
            return 1
        if not args.target:
            print(red("Con --request necesitas --target host[:port]."))
            return 1
        thost, _, tport = args.target.partition(":")
        host = thost
        use_tls = args.tls
        port = int(tport) if tport else (443 if use_tls else 80)
        # En request cruda el usuario controla la codificacion; no tocamos nada.
        encode = "url" if args.encode == "url" else "none"
    elif args.url:
        host, port, use_tls, path, host_header = probe.request_from_url(args.url)
        # En modo URL el payload va en la query: por defecto lo URL-encodeamos.
        encode = "none" if args.encode == "none" else "url"
        if marker not in path:
            print(red(f"El marcador '{marker}' debe aparecer en la URL. "
                      f"Ej: 'http://host/?q={marker}'"))
            return 1
        request_template = probe.build_http_request(args.method, path, host_header)
    else:
        print(red("Indica un objetivo: una URL con el marcador, o --request FILE + --target."))
        return 1

    # --- 2. Reunir los payloads a probar ---
    payloads: list[tuple[str, str]] = []
    if args.wordlist:
        try:
            for line in Path(args.wordlist).read_text(encoding="utf-8").splitlines():
                if line.strip():
                    payloads.append((line, "wordlist"))
        except OSError as exc:
            print(red(f"No se pudo leer la wordlist: {exc}"))
            return 1
    elif getattr(args, "from_vuln", None):
        v = find_vuln(load_vulns(), args.from_vuln)
        if v is None:
            print(red(f"Tema no encontrado: {args.from_vuln}"))
            return 1
        payloads = _flatten_payloads(v)
    else:
        chosen = _choose_vuln_payloads(load_vulns())
        if not chosen:
            return 1
        payloads = chosen

    if not payloads:
        print(red("No hay payloads que probar."))
        return 1

    # --- 3. Gate de autorizacion ---
    try:
        probe.confirm_authorization(host, assume_yes=args.yes)
    except probe.AuthorizationError as exc:
        print(red(f"  {exc}"), file=sys.stderr)
        return 2

    # --- 4. Ejecutar ---
    print(bold(cyan(
        f"\n  Fuzzing {host}:{port}{' (TLS)' if use_tls else ''} — "
        f"{len(payloads)} variaciones + baseline\n")))

    def progress(i, total, res):
        mark = red("!") if res.score >= 3 else (yellow("·") if res.score > 0 else dim("."))
        sys.stdout.write(f"\r  [{i}/{total}] {mark} ")
        sys.stdout.flush()

    try:
        results = probe.run_fuzz(
            host=host, port=port, use_tls=use_tls,
            request_template=request_template, marker=marker,
            payloads=payloads, timeout=args.timeout, throttle=args.throttle,
            encode=encode, on_progress=progress,
        )
    except ValueError as exc:
        print(red(f"\n{exc}"))
        return 1
    sys.stdout.write("\r" + " " * 40 + "\r")

    # --- 5. Reportar ---
    baseline = next((r for r in results if r.label == "baseline"), None)
    findings = [r for r in results if r.label != "baseline"]
    interesting = [r for r in findings if r.score > 0]

    if baseline:
        print(dim(f"  baseline → status {baseline.status} · "
                  f"{baseline.body_len} bytes · {baseline.elapsed_ms:.0f}ms\n"))

    print(bold(f"  {len(interesting)} variacion(es) interesante(s) de {len(findings)}:\n"))
    top = interesting[: args.top] if interesting else []
    if not top:
        print(dim("  Nada destaco sobre la baseline. Prueba otros payloads/parametros.\n"))
    for r in top:
        sev = red("ALTO") if r.score >= 5 else (yellow("medio") if r.score >= 2 else dim("bajo"))
        st = r.status if r.status is not None else "—"
        head = (f"  [{sev}] status {st} · {r.body_len}b · {r.elapsed_ms:.0f}ms"
                f"  {dim('(' + r.label + ')')}")
        print(head)
        payload_show = r.payload if len(r.payload) <= 70 else r.payload[:69] + "…"
        print(green(f"      {payload_show}"))
        for note in r.notes:
            print(dim(f"        → {note}"))
        print()
    print(dim("  Recuerda: confirma manualmente cada hallazgo antes de reportarlo.\n"))
    return 0


def cmd_serve(args) -> int:
    """Lanza la interfaz web local."""
    import http.server
    import socketserver
    import webbrowser

    web_dir = Path(__file__).resolve().parent / "web"
    if not web_dir.is_dir():
        print(red("No existe la carpeta web/."))
        return 1

    # Construye el bundle de datos en memoria
    bundle = {
        "vulns": load_vulns(),
        "checklists": load_checklists(),
        "cheatsheets": load_cheatsheets(),
    }
    bundle_bytes = json.dumps(bundle, ensure_ascii=False).encode("utf-8")

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(web_dir), **kw)

        def do_GET(self):  # noqa: N802
            if self.path.rstrip("/") in ("/auditdeck-data.json", "/data.json"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(bundle_bytes)))
                self.end_headers()
                self.wfile.write(bundle_bytes)
                return
            return super().do_GET()

        def log_message(self, *a):  # silenciar logs
            pass

    addr = ("127.0.0.1", args.port)
    try:
        with socketserver.TCPServer(addr, Handler) as httpd:
            url = f"http://127.0.0.1:{args.port}/"
            print(bold(green(f"\n  AuditDeck web en {cyan(url)}")))
            print(dim("  Ctrl+C para detener.\n"))
            if not args.no_browser:
                try:
                    webbrowser.open(url)
                except Exception:
                    pass
            httpd.serve_forever()
    except OSError as exc:
        print(red(f"No se pudo abrir el puerto {args.port}: {exc}"))
        return 1
    except KeyboardInterrupt:
        print(dim("\n  Detenido.\n"))
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="auditdeck",
        description="Copiloto de auditoria web / PortSwigger Web Security Academy.",
        epilog="Uso solo en sistemas autorizados (tus labs, CTFs, engagements con permiso).",
    )
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("list", aliases=["ls"], help="Lista todos los temas")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("search", help="Busca en toda la base de conocimiento")
    sp.add_argument("terms", nargs="+", help="Termino(s) a buscar")
    sp.set_defaults(func=cmd_search)

    sp = sub.add_parser("show", help="Muestra la ficha completa de un tema")
    sp.add_argument("id", help="id o nombre (ej. sql-injection)")
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("payloads", help="Solo los payloads de un tema")
    sp.add_argument("id")
    sp.add_argument("--raw", action="store_true", help="Sin formato, util para pipes")
    sp.set_defaults(func=cmd_payloads)

    sp = sub.add_parser("labs", help="Enlaces a labs de PortSwigger")
    sp.add_argument("id", nargs="?", help="id de un tema (opcional)")
    sp.set_defaults(func=cmd_labs)

    sp = sub.add_parser("checklist", help="Metodologia paso a paso")
    sp.add_argument("name", nargs="?", help="Nombre de checklist (opcional)")
    sp.set_defaults(func=cmd_checklist)

    sp = sub.add_parser("cheatsheet", aliases=["cheat"], help="Comandos rapidos por herramienta")
    sp.add_argument("topic", nargs="?", help="Filtra por tema/herramienta")
    sp.set_defaults(func=cmd_cheatsheet)

    sp = sub.add_parser("serve", help="Abre la interfaz web local")
    sp.add_argument("--port", type=int, default=8777)
    sp.add_argument("--no-browser", action="store_true")
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser(
        "connect",
        help="Cliente de socket crudo (TCP/TLS) interactivo — habla protocolos a mano",
    )
    sp.add_argument("host", help="host o IP del objetivo (autorizado)")
    sp.add_argument("port", type=int, help="puerto")
    sp.add_argument("--tls", action="store_true", help="envuelve la conexion en TLS")
    sp.add_argument("--timeout", type=float, default=8.0)
    sp.add_argument("--yes", action="store_true", help="asume autorizacion (solo si la tienes)")
    sp.set_defaults(func=cmd_connect)

    sp = sub.add_parser(
        "fuzz",
        help="Prueba automatizada de variaciones de payload sobre un objetivo autorizado",
        description="Inyecta una lista de payloads en el marcador (FUZZ) de una request, "
                    "los envia por socket y compara cada variacion contra una baseline.",
    )
    sp.add_argument("url", nargs="?", help="URL con el marcador, ej: 'http://localhost/?q=FUZZ'")
    sp.add_argument("--request", help="fichero con una request HTTP cruda que contiene el marcador")
    sp.add_argument("--target", help="con --request: host[:port] al que conectar")
    sp.add_argument("--marker", default="FUZZ", help="marcador a sustituir (def. FUZZ)")
    sp.add_argument("--encode", choices=["auto", "url", "none"], default="auto",
                    help="codificacion del payload: url-encode en modo URL por defecto")
    sp.add_argument("--method", default="GET", help="metodo HTTP en modo URL (def. GET)")
    sp.add_argument("--tls", action="store_true", help="usa TLS (auto si la URL es https)")
    sp.add_argument("--from", dest="from_vuln", help="usa los payloads de un tema (ej. sql-injection)")
    sp.add_argument("--wordlist", help="fichero con un payload por linea")
    sp.add_argument("--timeout", type=float, default=8.0)
    sp.add_argument("--throttle", type=float, default=0.0, help="segundos de espera entre requests")
    sp.add_argument("--top", type=int, default=15, help="cuantos hallazgos mostrar (def. 15)")
    sp.add_argument("--yes", action="store_true", help="asume autorizacion (solo si la tienes)")
    sp.set_defaults(func=cmd_fuzz)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        print()
        return cmd_list(args)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
