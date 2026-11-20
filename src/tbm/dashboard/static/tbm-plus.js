/* threeblindmice · interação da v0.9: busca (Ctrl+K), notificações, modo simples/técnico,
   menu recolhível, comemoração, números animados e atualização de trechos sem recarregar. */
(function () {
  "use strict";
  const tr = s => (window.TBM_I18N || {})[s] || s;
  const store = {
    get(k, d) { try { return localStorage.getItem(k) ?? d; } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* sem armazenamento */ } },
  };
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ── trocar só um pedaço da página pelo que o servidor desenha agora (sem recarregar tudo) ── */
  window.tbmRefresh = async function (selectors) {
    const html = await (await fetch(location.href, { headers: { "X-TBM-Fragment": "1" } })).text();
    const doc = new DOMParser().parseFromString(html, "text/html");
    for (const sel of [].concat(selectors)) {
      const fresh = doc.querySelectorAll(sel), current = document.querySelectorAll(sel);
      current.forEach((el, i) => { if (fresh[i]) el.replaceWith(document.importNode(fresh[i], true)); else el.remove(); });
    }
    const count = doc.querySelector(".side-nav .count"), mine = document.querySelector('.side-nav a[data-nav="/inventory"]');
    if (mine) { mine.querySelector(".count")?.remove(); if (count) mine.appendChild(document.importNode(count, true)); }
  };

  /* ── aviso com botão (ex.: Desfazer) ── */
  window.tbmToastAction = function (text, label, fn, kind) {
    tbmToast(text, kind || "ok");
    const t = document.querySelector(".toasts .toast:last-child");
    if (!t) return;
    const b = document.createElement("button");
    b.className = "btn sm subtle"; b.type = "button"; b.textContent = label;
    b.addEventListener("click", async () => { t.remove(); await fn(); });
    t.appendChild(b);
  };

  /* ── aparelhos: renomear e aprovar sem recarregar, com Desfazer ── */
  const deviceSel = identity => [`[data-card="${CSS.escape(identity)}"]`, "#device"];
  window.tbmRenameDevice = async function (identity, current) {
    const alias = await tbmPrompt(tr("Nome do aparelho"), tr("Como você chama este aparelho? Deixe vazio para voltar ao nome detectado."), current);
    if (alias === null) return;
    try {
      const r = await tbmPost("/api/device", { identity, alias });
      await tbmRefresh(deviceSel(identity));
      tbmToastAction(tr("Nome salvo"), tr("Desfazer"), async () => {
        await tbmPost("/api/device", { identity, alias: (r.before && r.before.alias) || "" });
        await tbmRefresh(deviceSel(identity));
      });
    } catch (e) { tbmToast(e.message, "error"); }
  };
  window.tbmTrustDevice = async function (identity, trusted) {
    try {
      await tbmPost("/api/device", { identity, trusted });
      await tbmRefresh(deviceSel(identity));
      tbmToastAction(trusted ? tr("Aparelho aprovado: não vai mais alertar como desconhecido") : tr("Aprovação removida"),
        tr("Desfazer"), async () => { await tbmPost("/api/device", { identity, trusted: !trusted }); await tbmRefresh(deviceSel(identity)); });
    } catch (e) { tbmToast(e.message, "error"); }
  };

  /* ── modo simples / técnico ── */
  function paintMode() {
    const m = document.documentElement.getAttribute("data-mode") || "tech", b = document.getElementById("mode-toggle");
    if (b) { b.textContent = m === "simple" ? b.dataset.simple : b.dataset.tech; b.setAttribute("aria-pressed", m === "simple"); }
  }
  window.tbmToggleMode = function () {
    const next = (document.documentElement.getAttribute("data-mode") || "tech") === "tech" ? "simple" : "tech";
    document.documentElement.setAttribute("data-mode", next);
    store.set("tbm-mode", next);
    paintMode();
  };

  /* ── menu lateral recolhível ── */
  window.tbmToggleSidebar = function () {
    const app = document.getElementById("app");
    app.classList.toggle("collapsed");
    store.set("tbm-sidebar", app.classList.contains("collapsed") ? "collapsed" : "open");
  };

  /* ── notificações ── */
  async function refreshCount() {
    const badge = document.getElementById("notif-count");
    if (!badge || !window.TBM_GUI) return;
    try {
      const { unread } = await (await fetch("/api/notifications/count")).json();
      badge.textContent = unread > 9 ? "9+" : unread; badge.hidden = !unread;
    } catch (e) { /* servidor reiniciando */ }
  }
  window.tbmNotifications = async function () {
    const panel = document.getElementById("notif-panel");
    if (!panel) return;
    if (!panel.hidden) { panel.hidden = true; return; }
    panel.innerHTML = '<div class="skeleton line"></div><div class="skeleton line"></div><div class="skeleton line"></div>';
    panel.hidden = false;
    panel.innerHTML = await (await fetch("/partials/notifications")).text();
    refreshCount();
  };
  document.addEventListener("click", e => {
    const panel = document.getElementById("notif-panel");
    if (panel && !panel.hidden && !panel.contains(e.target) && !e.target.closest(".bell")) panel.hidden = true;
  });

  /* ── busca global (Ctrl+K) ── */
  let items = null;
  const norm = s => (s || "").normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
  window.tbmPalette = async function () {
    let d = document.querySelector("dialog.palette");
    if (!d) {
      d = document.createElement("dialog"); d.className = "palette";
      d.innerHTML = `<input type="search" autocomplete="off" spellcheck="false"><ul role="listbox"></ul>
        <footer><span><kbd>↑</kbd> <kbd>↓</kbd></span><span><kbd>Enter</kbd></span><span><kbd>Esc</kbd></span></footer>`;
      d.querySelector("input").setAttribute("placeholder", tr("Buscar aparelho, achado ou página…"));
      d.querySelector("input").setAttribute("aria-label", tr("Buscar aparelho, achado ou página…"));
      d.addEventListener("close", () => setTimeout(() => d.remove(), 50));
      document.body.appendChild(d);
      const input = d.querySelector("input"), ul = d.querySelector("ul");
      let sel = 0, shown = [];
      const draw = () => {
        const q = norm(input.value).trim();
        shown = (items || []).filter(it => !q || q.split(/\s+/).every(w => norm(it.title + " " + it.sub + " " + (it.keys || "")).includes(w))).slice(0, 40);
        sel = Math.min(sel, Math.max(shown.length - 1, 0));
        ul.innerHTML = "";
        let group = null;
        shown.forEach((it, i) => {
          if (it.group !== group) { group = it.group; const g = document.createElement("li"); g.className = "group"; g.textContent = group; ul.appendChild(g); }
          const li = document.createElement("li"), a = document.createElement("a");
          a.href = it.href; a.setAttribute("role", "option"); a.setAttribute("aria-selected", i === sel);
          a.innerHTML = '<svg class="icon" aria-hidden="true"><use/></svg><span class="t"></span><span class="hint"></span>';
          a.querySelector("use").setAttribute("href", "#i-" + (it.icon || "arrow"));
          a.querySelector(".t").textContent = it.title; a.querySelector(".hint").textContent = it.sub || "";
          li.appendChild(a); ul.appendChild(li);
        });
        if (!shown.length) { const li = document.createElement("li"); li.className = "empty-row"; li.textContent = items ? tr("Nada encontrado") : tr("Carregando…"); ul.appendChild(li); }
        ul.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: "nearest" });
      };
      input.addEventListener("input", () => { sel = 0; draw(); });
      input.addEventListener("keydown", e => {
        if (e.key === "ArrowDown") { e.preventDefault(); sel = Math.min(sel + 1, shown.length - 1); draw(); }
        else if (e.key === "ArrowUp") { e.preventDefault(); sel = Math.max(sel - 1, 0); draw(); }
        else if (e.key === "Enter" && shown[sel]) { e.preventDefault(); location.href = shown[sel].href; }
      });
      draw();
      d.showModal(); input.focus();
      if (!items) { try { items = (await (await fetch("/api/search")).json()).items; } catch (e) { items = []; } draw(); }
    }
  };

  /* ── atalhos de teclado ── */
  let lastG = 0;
  document.addEventListener("keydown", e => {
    const typing = e.target.closest("input, textarea, select, [contenteditable]");
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); tbmPalette(); return; }
    if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key === "/") { e.preventDefault(); tbmPalette(); }
    else if (e.key === "n" && window.TBM_GUI) location.href = "/scan";
    else if (e.key === "g") lastG = Date.now();
    else if (Date.now() - lastG < 800) {
      const to = { h: "/", f: "/findings", m: "/map", d: "/inventory", a: "/alerts" }[e.key];
      if (to) location.href = to;
    }
  });

  /* ── comemoração ── */
  window.tbmConfetti = function () {
    if (reduced) return;
    const box = document.createElement("div"); box.className = "confetti"; box.setAttribute("aria-hidden", "true");
    const colors = ["var(--accent)", "var(--good)", "var(--medium)", "var(--low)", "var(--accent-2)"];
    for (let i = 0; i < 70; i++) {
      const p = document.createElement("i");
      p.style.left = Math.random() * 100 + "vw"; p.style.background = colors[i % colors.length];
      p.style.animationDelay = Math.random() * .5 + "s"; p.style.animationDuration = 1.2 + Math.random() * .9 + "s";
      box.appendChild(p);
    }
    document.body.appendChild(box);
    setTimeout(() => box.remove(), 2600);
  };

  /* ── números que contam até o valor ── */
  function countUp(el) {
    const end = +el.dataset.count;
    if (reduced || !isFinite(end) || end <= 0) return;
    const t0 = performance.now(), dur = 900;
    const step = t => { const k = Math.min((t - t0) / dur, 1); el.textContent = Math.round(end * (1 - Math.pow(1 - k, 3))); if (k < 1) requestAnimationFrame(step); };
    el.textContent = "0"; requestAnimationFrame(step);
  }

  document.addEventListener("DOMContentLoaded", () => {
    paintMode();
    refreshCount();
    if (window.TBM_GUI) setInterval(refreshCount, 30000);
    document.querySelectorAll("[data-count]").forEach(countUp);
    // a nota subiu desde o scan anterior? comemora uma vez por scan
    const c = document.getElementById("celebrate-slot");
    if (c && +c.dataset.delta > 0 && store.get("tbm-celebrated") !== c.dataset.scan) {
      store.set("tbm-celebrated", c.dataset.scan);
      const b = document.createElement("div"); b.className = "celebrate"; b.setAttribute("role", "status");
      b.innerHTML = '<svg class="icon lg" aria-hidden="true"><use href="#i-sparkle"/></svg><span></span>';
      b.querySelector("span").textContent = c.dataset.text;
      c.appendChild(b); tbmConfetti();
    }
  });
})();
