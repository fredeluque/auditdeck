# AuditDeck

**Tu copiloto de bolsillo para auditorías web y los labs de PortSwigger Web Security Academy.**

¿Pierdes tiempo saltando entre PortSwigger, OWASP, PayloadsAllTheThings, tus notas y mil pestañas para recordar qué payload probar o qué pasos seguir en Burp? AuditDeck unifica todo eso en una única base de conocimiento que puedes consultar **desde el terminal** mientras haces un lab, o **desde una web local** para navegar con calma.

> ⚠️ **Uso responsable**: esta herramienta es para aprendizaje y auditoría **autorizada**: tus propios labs de PortSwigger, CTFs, entornos de práctica o engagements con permiso explícito por escrito. No la uses contra sistemas que no te pertenezcan o para los que no tengas autorización.

---

## Qué incluye

Para cada vulnerabilidad encontrarás, en un mismo sitio:

- **Dónde buscar** — qué parámetros y funcionalidades suelen ser vulnerables.
- **Cómo detectar** — señales y pruebas rápidas para confirmarla.
- **Pasos en Burp Suite** — el flujo concreto (Repeater, Intruder, Collaborator, extensiones).
- **Payloads** — agrupados por contexto/técnica, listos para copiar.
- **Comandos** — sqlmap, ffuf, hydra, hashcat, etc. con el ejemplo de uso.
- **Remediación** — para entender la causa y poder reportarla.
- **Labs de PortSwigger** — enlaces directos a los laboratorios relacionados.
- **Referencias** — PortSwigger / OWASP para profundizar.

Temas cubiertos actualmente: SQL injection, XSS, CSRF, SSRF, XXE, OS command injection,
path traversal, broken access control / IDOR, autenticación, JWT, SSTI, file upload,
CORS, business logic, HTTP request smuggling, deserialización insegura e information disclosure.

Además: una **metodología paso a paso** (checklist) y un **cheatsheet de comandos** por fase.

---

## Requisitos

- Python 3.8 o superior. **Sin dependencias externas** (solo librería estándar).

## Instalación

```bash
git clone <este-repo>
cd auditdeck
python3 auditdeck.py list
```

Opcional — crea un alias para tenerlo a mano:

```bash
alias auditdeck='python3 /ruta/a/auditdeck/auditdeck.py'
```

---

## Uso (CLI)

```bash
# Listar todos los temas por categoría
auditdeck list

# Buscar en TODA la base de conocimiento (payloads, pasos, comandos…)
auditdeck search ssrf collaborator

# Ver la ficha completa de un tema
auditdeck show sql-injection

# Solo los payloads (con --raw para usarlo en pipes / Intruder)
auditdeck payloads xss
auditdeck payloads xss --raw > xss-payloads.txt

# Enlaces a labs de PortSwigger (de un tema o de todos)
auditdeck labs jwt

# Metodología paso a paso
auditdeck checklist

# Cheatsheet de comandos (opcionalmente filtrado por tema)
auditdeck cheatsheet recon
```

### Interfaz web local

```bash
auditdeck serve          # abre http://127.0.0.1:8777 en tu navegador
auditdeck serve --port 9000 --no-browser
```

La web es buscable, funciona **offline** y permite copiar payloads/comandos con un clic.
No expone nada a Internet: escucha solo en `127.0.0.1`.

---

## Cómo está organizado

```
auditdeck/
├── auditdeck.py              # CLI (Python puro)
├── data/
│   ├── vulns/*.json          # una ficha por vulnerabilidad
│   ├── checklists/*.json     # metodologías paso a paso
│   └── cheatsheets/*.json    # comandos por fase/herramienta
└── web/                      # interfaz web local (HTML/CSS/JS)
```

Todo el conocimiento vive en **JSON**, así que la herramienta es solo el motor: el valor está en los datos y **ampliarlos es trivial**.

## Añadir o editar contenido

Crea un archivo en `data/vulns/` (el nombre del archivo es el `id`). Estructura mínima:

```json
{
  "name": "Nombre de la vulnerabilidad",
  "category": "Injection",
  "severity": "High",
  "aka": ["alias1", "alias2"],
  "summary": "Descripción breve.",
  "where_to_look": ["..."],
  "detection": ["..."],
  "burp_steps": ["..."],
  "payloads": { "Grupo de payloads": ["payload1", "payload2"] },
  "commands": [{ "tool": "sqlmap", "desc": "qué hace", "cmd": "sqlmap -r req.txt" }],
  "remediation": ["..."],
  "portswigger_labs": [{ "title": "...", "difficulty": "APPRENTICE", "url": "https://..." }],
  "references": [{ "title": "...", "url": "https://..." }]
}
```

`severity` admite: `Critical`, `High`, `Medium`, `Low`, `Info`. Todos los campos salvo
`name` son opcionales: pon solo lo que tengas y ve enriqueciéndolo según avances en la academia.

Idea: convierte tus propias notas de cada lab que superes en una entrada nueva. La herramienta crece contigo.

---

## Roadmap (ideas)

- Más temas: NoSQL injection, GraphQL, OAuth, web cache poisoning, prototype pollution, race conditions, WebSockets, clickjacking.
- Marcar labs como completados y llevar progreso.
- Exportar una ficha a Markdown para pegar en el reporte.
- Importar/sincronizar payloads desde PayloadsAllTheThings.

## Licencia y descargo

Material educativo para seguridad ofensiva **autorizada**. El autor no se responsabiliza
del uso indebido. Comprueba siempre que tienes permiso antes de probar nada fuera de un lab.
