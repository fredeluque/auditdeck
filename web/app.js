"use strict";

let DATA = { vulns: [], checklists: [], cheatsheets: [] };
let view = "vulns";
let selectedId = null;
let filter = "";

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, html) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html !== undefined) e.innerHTML = html;
  return e;
};
const esc = (s) =>
  String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

async function boot() {
  try {
    const res = await fetch("auditdeck-data.json");
    DATA = await res.json();
  } catch (e) {
    $("#content").innerHTML =
      '<div class="empty">No se pudieron cargar los datos. Lanza la app con <code>python auditdeck.py serve</code>.</div>';
    return;
  }
  wireEvents();
  render();
}

function wireEvents() {
  $("#search").addEventListener("input", (e) => {
    filter = e.target.value.toLowerCase().trim();
    render();
  });
  document.querySelectorAll(".tab").forEach((t) =>
    t.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
      t.classList.add("active");
      view = t.dataset.view;
      selectedId = null;
      render();
    })
  );
}

function matchesFilter(v) {
  if (!filter) return true;
  const hay = JSON.stringify(v).toLowerCase();
  return filter.split(/\s+/).every((t) => hay.includes(t));
}

function render() {
  if (view === "vulns") return renderVulns();
  if (view === "checklist") return renderChecklist();
  if (view === "cheatsheet") return renderCheatsheet();
}

/* ---------------- Vulnerabilidades ---------------- */
function renderVulns() {
  const sidebar = $("#sidebar");
  sidebar.innerHTML = "";
  const list = DATA.vulns.filter(matchesFilter);

  const byCat = {};
  list.forEach((v) => {
    (byCat[v.category || "Otros"] ||= []).push(v);
  });

  Object.keys(byCat)
    .sort()
    .forEach((cat) => {
      sidebar.appendChild(el("div", "cat-label", esc(cat)));
      byCat[cat]
        .sort((a, b) => (a.name > b.name ? 1 : -1))
        .forEach((v) => {
          const item = el("div", "item" + (v.id === selectedId ? " active" : ""));
          item.appendChild(el("span", "name", esc(v.name)));
          item.appendChild(el("span", "badge sev-" + (v.severity || "Info"), esc(v.severity || "Info")));
          item.addEventListener("click", () => {
            selectedId = v.id;
            renderVulns();
          });
          sidebar.appendChild(item);
        });
    });

  if (!list.length) sidebar.appendChild(el("div", "empty", "Sin resultados"));

  if (!selectedId && list.length) selectedId = list[0].id;
  const v = DATA.vulns.find((x) => x.id === selectedId);
  $("#content").innerHTML = v ? vulnHtml(v) : '<div class="empty">Elige un tema a la izquierda.</div>';
  attachCopy();
}

function listSection(title, items, ordered) {
  if (!items || !items.length) return "";
  const tag = ordered ? "ol" : "ul";
  return `<div class="section"><h3>${esc(title)}</h3><${tag}>${items
    .map((i) => `<li>${esc(i)}</li>`)
    .join("")}</${tag}></div>`;
}

function vulnHtml(v) {
  let h = `<h2>${esc(v.name)}</h2>`;
  const aka = (v.aka || []).join(", ");
  h += `<div class="meta">id: ${esc(v.id)} · categoría: ${esc(v.category || "-")}${
    aka ? " · alias: " + esc(aka) : ""
  }</div>`;
  if (v.summary) h += `<div class="summary">${esc(v.summary)}</div>`;

  h += listSection("Dónde buscar", v.where_to_look);
  h += listSection("Cómo detectar", v.detection);
  h += listSection("Pasos en Burp Suite", v.burp_steps, true);

  if (v.payloads && Object.keys(v.payloads).length) {
    h += '<div class="section"><h3>Payloads</h3>';
    for (const [group, items] of Object.entries(v.payloads)) {
      h += `<div class="payload-group"><div class="gname">${esc(group)}</div>`;
      h += items.map((p) => codeBlock(p)).join("");
      h += "</div>";
    }
    h += "</div>";
  }

  if (v.commands && v.commands.length) {
    h += '<div class="section"><h3>Comandos</h3>';
    h += v.commands
      .map(
        (c) =>
          `<div class="cmd-desc"># ${esc(c.desc || "")} (${esc(c.tool || "")})</div>${codeBlock(c.cmd)}`
      )
      .join("");
    h += "</div>";
  }

  h += listSection("Remediación", v.remediation);

  if (v.portswigger_labs && v.portswigger_labs.length) {
    h += '<div class="section"><h3>Labs de PortSwigger</h3>';
    h += v.portswigger_labs
      .map(
        (l) =>
          `<div class="lab"><a href="${esc(l.url)}" target="_blank" rel="noopener">${esc(
            l.title
          )}</a>${l.difficulty ? `<span class="diff">${esc(l.difficulty)}</span>` : ""}</div>`
      )
      .join("");
    h += "</div>";
  }

  if (v.references && v.references.length) {
    h += '<div class="section"><h3>Referencias</h3>';
    h += v.references
      .map((r) => `<div class="lab"><a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.title)}</a></div>`)
      .join("");
    h += "</div>";
  }
  return h;
}

function codeBlock(text) {
  return `<div class="code" data-copy="${esc(text)}">${esc(text)}<span class="copy-hint">click = copiar</span></div>`;
}

function attachCopy() {
  document.querySelectorAll(".code").forEach((c) => {
    c.addEventListener("click", () => {
      const txt = c.getAttribute("data-copy");
      navigator.clipboard?.writeText(txt).then(() => {
        c.classList.add("copied");
        setTimeout(() => c.classList.remove("copied"), 700);
      });
    });
  });
}

/* ---------------- Metodología ---------------- */
function renderChecklist() {
  $("#sidebar").innerHTML = "";
  DATA.checklists.forEach((c, idx) => {
    const item = el("div", "item");
    item.appendChild(el("span", "name", esc(c.name)));
    item.addEventListener("click", () => {
      document.getElementById("cl-" + idx)?.scrollIntoView({ behavior: "smooth" });
    });
    $("#sidebar").appendChild(item);
  });

  let h = "";
  DATA.checklists.forEach((c, idx) => {
    h += `<div id="cl-${idx}"><h2>${esc(c.name)}</h2>`;
    if (c.description) h += `<div class="summary">${esc(c.description)}</div>`;
    (c.phases || []).forEach((p) => {
      h += `<div class="section"><h3>${esc(p.name)}</h3>`;
      h += (p.items || [])
        .map(
          (i) =>
            `<label class="checkitem"><input type="checkbox"><span>${esc(i)}</span></label>`
        )
        .join("");
      h += "</div>";
    });
    h += "</div>";
  });
  $("#content").innerHTML = h || '<div class="empty">Sin checklists.</div>';
}

/* ---------------- Cheatsheet ---------------- */
function renderCheatsheet() {
  $("#sidebar").innerHTML = "";
  const sheets = DATA.cheatsheets;
  let h = "";
  sheets.forEach((sheet) => {
    (sheet.sections || []).forEach((sec, idx) => {
      const matched = !filter || JSON.stringify(sec).toLowerCase().includes(filter);
      if (!matched) return;
      const item = el("div", "item");
      item.appendChild(el("span", "name", esc(sec.title)));
      item.addEventListener("click", () =>
        document.getElementById("cs-" + idx)?.scrollIntoView({ behavior: "smooth" })
      );
      $("#sidebar").appendChild(item);

      h += `<div id="cs-${idx}" class="section"><h3>${esc(sec.title)}</h3>`;
      h += (sec.entries || [])
        .map((e) => `<div class="cmd-desc"># ${esc(e.desc || "")}</div>${codeBlock(e.cmd)}`)
        .join("");
      h += "</div>";
    });
  });
  $("#content").innerHTML = h || '<div class="empty">Sin comandos.</div>';
  attachCopy();
}

boot();
