"""Visão geral: painel, linha do tempo, relatórios, comparação, busca, idioma e métricas."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from tbm import i18n
from tbm.dashboard.charts import sparkline
from tbm.dashboard.icons import device_icon
from tbm.dashboard.routes import Ctx
from tbm.dashboard.templating import action_title
from tbm.dashboard.views import health, timeline
from tbm.models import ScanResult
from tbm.squeak import diff_scans, render_html


def build(ctx: Ctx) -> APIRouter:
    r = APIRouter()
    store, render, gui = ctx.store, ctx.render, ctx.gui

    @r.get("/lang/{code}")
    def set_language(code: str, request: Request) -> RedirectResponse:
        from urllib.parse import urlparse

        lang = i18n.normalize(code) or i18n.DEFAULT
        # volta para a página de onde veio (só o caminho: nunca redireciona para outro site)
        ref = urlparse(request.headers.get("referer", ""))
        target = ref.path if ref.path.startswith("/") and not ref.path.startswith("//") else "/"
        if ref.query:
            target += "?" + ref.query
        resp = RedirectResponse(target, status_code=303)
        resp.set_cookie(i18n.COOKIE, lang, max_age=365 * 86400, samesite="strict", httponly=False)
        return resp

    @r.get("/api/search")
    def search(q: str = "") -> JSONResponse:
        """Itens para a busca Ctrl+K: páginas, aparelhos e ações (filtrados no navegador)."""
        items: list[dict] = []
        pages = [("/", "gauge", "Visão geral"), ("/findings", "list", "Achados"), ("/map", "map", "Mapa"),
                 ("/inventory", "grid", "Dispositivos")]
        if gui is not None:
            pages += [("/scan", "plus", "Novo scan"), ("/alerts", "bell", "Alertas"), ("/watch", "eye", "Vigia"),
                      ("/features", "book", "Funcionalidades")]
        for href, icon, text in pages:
            items.append({"group": i18n.gettext("Páginas"), "title": i18n.gettext(text), "href": href,
                          "icon": icon, "sub": ""})
        for row in store.labels():
            scan = store.latest(row["label"])
            if scan is None:
                continue
            label = scan.label
            for h in scan.hosts:
                sub = " · ".join(x for x in (h.address, h.mac, h.vendor, i18n.device_type(h.device_type)) if x)
                title = h.name or i18n.device_type(h.device_type) or h.address
                keys = " ".join(x for x in (h.hostname, h.device_name) if x)
                items.append({"group": i18n.gettext("Dispositivos"), "title": title, "sub": sub, "keys": keys,
                              "href": f"/device/{label}/{h.address}", "icon": device_icon(h.device_type)})
            from tbm.squeak.actions import build_actions

            for a in build_actions(scan):
                items.append({"group": i18n.gettext("Ações"), "title": action_title(a), "sub": label,
                              "href": f"/fix/{label}/{a.key}", "icon": "tool",
                              "keys": " ".join(f.title for f in a.findings)})
        return JSONResponse({"items": items[:500]})

    @r.get("/", response_class=HTMLResponse)
    def index(request: Request, label: str | None = None):
        chosen = label or ctx.latest_label()
        if chosen is None:
            if gui is not None:
                return RedirectResponse("/welcome", status_code=303)
            return render("index.html.j2", h=None, sparks={})
        data = health(store, chosen)
        if data is None:
            raise HTTPException(404, "rótulo sem scans")
        sparks = {lb: sparkline([r["score"] or 0 for r in reversed(store.list(lb, 20))]) for lb in data.labels}
        return render("index.html.j2", h=data, sparks=sparks)

    @r.get("/partials/label/{label}", response_class=HTMLResponse)
    def label_panel(label: str) -> HTMLResponse:
        rows = store.list(label, 30)
        if not rows:
            raise HTTPException(404, "rótulo sem scans")
        return render("label.html.j2", label=label, rows=rows, t=timeline(store, label))

    @r.get("/partials/diff/{new_id}", response_class=HTMLResponse)
    def diff_panel(new_id: str) -> HTMLResponse:
        new = store.get(new_id)
        if new is None:
            raise HTTPException(404, "scan não encontrado")
        old = store.latest(new.label, exclude=new.scan_id, before=new.started_at.isoformat())
        return render("diff.html.j2", d=diff_scans(old, new), new=new)

    @r.get("/scan/{scan_id}", response_class=HTMLResponse)
    def scan_report(scan_id: str) -> HTMLResponse:
        try:
            result = store.get(scan_id)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        if result is None:
            raise HTTPException(404, "scan não encontrado")
        previous = store.latest(result.label, exclude=result.scan_id, before=result.started_at.isoformat())
        return HTMLResponse(render_html(result, diff_scans(previous, result)))

    @r.get("/api/scans")
    def api_scans(label: str | None = None, limit: int = 50) -> JSONResponse:
        return JSONResponse([dict(row) for row in store.list(label, min(limit, 500))])

    @r.get("/report/{label}", response_class=HTMLResponse)
    def family_report(label: str) -> HTMLResponse:
        data = health(store, label)
        if data is None:
            raise HTTPException(404, "rótulo sem scans")
        return render("family.html.j2", h=data, now=ScanResult().started_at)

    @r.get("/compare/{label}", response_class=HTMLResponse)
    def compare(label: str) -> HTMLResponse:
        rows = store.list(label, 60)
        if len(rows) < 2:
            raise HTTPException(404, "precisa de pelo menos dois scans")
        return render("compare.html.j2", label=label, rows=rows)

    @r.get("/partials/compare/{a}/{b}", response_class=HTMLResponse)
    def compare_pair(a: str, b: str) -> HTMLResponse:
        old, new = store.get(a), store.get(b)
        if old is None or new is None:
            raise HTTPException(404, "scan não encontrado")
        if old.started_at > new.started_at:
            old, new = new, old
        return render("compare_pair.html.j2", old=old, new=new, d=diff_scans(old, new))

    @r.get("/metrics")
    def metrics() -> Response:
        from tbm.dashboard.metrics import render_metrics

        return Response(render_metrics(store), media_type="text/plain; version=0.0.4")

    if gui is not None:
        from tbm.dashboard.features import TOOLS, catalog

        @r.get("/features", response_class=HTMLResponse)
        def features() -> HTMLResponse:
            return render("features.html.j2", checks=catalog(), tools=TOOLS)

    return r
