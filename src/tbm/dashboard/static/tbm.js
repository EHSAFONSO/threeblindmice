/* threeblindmice · comportamento compartilhado da interface (sem dependências externas). */
(function () {
  "use strict";

  /* ── tema: auto (segue o sistema), claro ou escuro; lembrado só neste navegador ── */
  const THEMES = ["auto", "light", "dark"];
  function applyTheme(t) {
    if (t === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", t);
    document.querySelectorAll("[data-theme-label]").forEach(el => {
      el.textContent = {auto: "Automático", light: "Claro", dark: "Escuro"}[t];
    });
  }
  function getTheme() { try { return localStorage.getItem("tbm-theme") || "auto"; } catch (e) { return "auto"; } }
  applyTheme(getTheme());
  window.tbmCycleTheme = function () {
    const next = THEMES[(THEMES.indexOf(getTheme()) + 1) % THEMES.length];
    try { localStorage.setItem("tbm-theme", next); } catch (e) { /* armazenamento indisponível */ }
    applyTheme(next);
    tbmToast("Tema: " + {auto: "automático", light: "claro", dark: "escuro"}[next]);
  };

  /* ── ações autenticadas (o token vem da própria página; outro site não consegue lê-lo) ── */
  window.tbmPost = async function (url, data) {
    const meta = document.querySelector('meta[name="tbm-token"]');
    const r = await fetch(url, {method: "POST", headers: {"Content-Type": "application/json",
      "X-TBM-Token": meta ? meta.content : ""}, body: JSON.stringify(data || {})});
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.error || ("HTTP " + r.status));
    return body;
  };

  /* ── avisos (substituem alert) ── */
  window.tbmToast = function (text, kind) {
    let box = document.querySelector(".toasts");
    if (!box) { box = document.createElement("div"); box.className = "toasts"; box.setAttribute("role", "status");
                box.setAttribute("aria-live", "polite"); document.body.appendChild(box); }
    const t = document.createElement("div");
    t.className = "toast " + (kind || "");
    t.textContent = text;
    box.appendChild(t);
    setTimeout(() => t.remove(), kind === "error" ? 7000 : 3800);
  };

  /* ── confirmação (substitui confirm) ── */
  window.tbmConfirm = function (title, text, okLabel, danger) {
    return new Promise(resolve => {
      const d = document.createElement("dialog");
      d.className = "tbm";
      d.innerHTML = `<h3></h3><p class="muted" style="margin:10px 0 18px"></p>
        <div class="row" style="justify-content:flex-end"><button class="btn subtle" value="no">Cancelar</button>
        <button class="btn ${danger ? "danger" : ""}" value="yes"></button></div>`;
      d.querySelector("h3").textContent = title;
      d.querySelector("p").textContent = text || "";
      d.querySelector('[value="yes"]').textContent = okLabel || "Confirmar";
      d.addEventListener("click", e => { const v = e.target.closest("button")?.value; if (v) { d.close(); resolve(v === "yes"); } });
      d.addEventListener("cancel", () => resolve(false));
      d.addEventListener("close", () => setTimeout(() => d.remove(), 50));
      document.body.appendChild(d);
      d.showModal();
      d.querySelector('[value="yes"]').focus();
    });
  };

  /* ── painel lateral ── */
  let lastFocus = null;
  window.tbmDrawer = async function (url) {
    let back = document.querySelector(".drawer-backdrop"), drawer = document.querySelector(".drawer");
    if (!drawer) {
      back = document.createElement("div"); back.className = "drawer-backdrop";
      drawer = document.createElement("aside"); drawer.className = "drawer"; drawer.setAttribute("role", "dialog");
      drawer.setAttribute("aria-modal", "true"); drawer.tabIndex = -1;
      back.addEventListener("click", tbmCloseDrawer);
      document.body.append(back, drawer);
    }
    lastFocus = document.activeElement;
    drawer.innerHTML = '<p class="muted">Carregando…</p>';
    back.classList.add("open"); drawer.classList.add("open"); drawer.focus();
    try {
      const r = await fetch(url);
      drawer.innerHTML = r.ok ? await r.text() : `<p class="error">Erro ${r.status}</p>`;
      init(drawer);
    } catch (e) { drawer.innerHTML = '<p class="error">Falha ao carregar.</p>'; }
  };
  window.tbmCloseDrawer = function () {
    document.querySelector(".drawer")?.classList.remove("open");
    document.querySelector(".drawer-backdrop")?.classList.remove("open");
    if (lastFocus) lastFocus.focus();
  };
  document.addEventListener("keydown", e => { if (e.key === "Escape") tbmCloseDrawer(); });

  /* ── dicas flutuantes (gráfico, mapa) ── */
  let tip = null;
  function showTip(el, x, y) {
    if (!tip) { tip = document.createElement("div"); tip.className = "tooltip"; tip.setAttribute("role", "tooltip"); document.body.appendChild(tip); }
    tip.innerHTML = el.dataset.tip;
    tip.hidden = false;
    const w = tip.offsetWidth, h = tip.offsetHeight;
    tip.style.left = Math.min(window.innerWidth - w - 8, Math.max(8, x - w / 2)) + "px";
    tip.style.top = (y - h - 14 < 8 ? y + 18 : y - h - 14) + "px";
  }
  document.addEventListener("mouseover", e => { const el = e.target.closest("[data-tip]"); if (el) showTip(el, e.clientX, e.clientY); });
  document.addEventListener("mousemove", e => { const el = e.target.closest("[data-tip]"); if (el && tip && !tip.hidden) showTip(el, e.clientX, e.clientY); });
  document.addEventListener("mouseout", e => { if (e.target.closest("[data-tip]") && tip) tip.hidden = true; });
  document.addEventListener("focusin", e => { const el = e.target.closest("[data-tip]"); if (el) { const r = el.getBoundingClientRect(); showTip(el, r.left + r.width / 2, r.top); } });
  document.addEventListener("focusout", () => { if (tip) tip.hidden = true; });

  /* ── carregador de fragmentos: [data-get] busca a URL e coloca em [data-target] ── */
  async function load(el) {
    const target = document.querySelector(el.dataset.target) || el;
    el.classList.add("loading");
    try {
      const r = await fetch(el.dataset.get);
      target.innerHTML = r.ok ? await r.text() : '<p class="muted">Erro ' + r.status + "</p>";
      init(target);
    } catch (e) { target.innerHTML = '<p class="muted">Falha ao carregar.</p>'; }
    finally { el.classList.remove("loading"); }
  }
  function init(root) { root.querySelectorAll('[data-get][data-trigger="load"]').forEach(load); }
  document.addEventListener("click", e => {
    const drawer = e.target.closest("[data-drawer]");
    const inner = e.target.closest("a, button");
    // um link/botão *dentro* de um cartão clicável segue o seu próprio caminho
    if (drawer && !(inner && inner !== drawer && drawer.contains(inner))) {
      e.preventDefault(); tbmDrawer(drawer.dataset.drawer); return;
    }
    const el = e.target.closest("[data-get]");
    if (el && el.dataset.trigger !== "load") { e.preventDefault(); load(el); }
  });
  document.addEventListener("keydown", e => {
    if ((e.key === "Enter" || e.key === " ") && e.target.matches("[data-drawer]:not(a):not(button)")) {
      e.preventDefault(); tbmDrawer(e.target.dataset.drawer);
    }
  });
  document.addEventListener("DOMContentLoaded", () => {
    init(document);
    // medidores animam do zero até a nota
    document.querySelectorAll(".gauge .value[data-offset]").forEach(c => requestAnimationFrame(() => {
      c.style.strokeDashoffset = c.dataset.offset;
    }));
  });
})();
