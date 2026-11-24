from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

import models
import wiki
from database import get_db
from deps import get_site_context, templates

router = APIRouter()

SERVICOS_ORDEM = ["linux", "firewall", "docker", "virtualizacao", "desenvolvimento", "desktop"]
SERVICOS = set(SERVICOS_ORDEM)


@router.get("/")
def home(request: Request, db: Session = Depends(get_db), ctx: dict = Depends(get_site_context)):
    return templates.TemplateResponse(
        request, "index.html", {**ctx, "projetos": db.query(models.Projeto).order_by(models.Projeto.id.desc()).all()}
    )


@router.get("/servicos/{slug}")
def servico(request: Request, slug: str, ctx: dict = Depends(get_site_context)):
    if slug not in SERVICOS:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(request, f"{slug}.html", ctx)


@router.get("/google{codigo}.html", include_in_schema=False)
def verificacao_google(codigo: str):
    """Arquivo de verificação do Google Search Console (static/verificacao/google<código>.html)."""
    import re
    from pathlib import Path
    from fastapi.responses import FileResponse
    if not re.fullmatch(r"[0-9a-f]{16}", codigo):
        raise HTTPException(status_code=404)
    arquivo = Path("static/verificacao") / f"google{codigo}.html"
    if not arquivo.is_file():
        raise HTTPException(status_code=404)
    return FileResponse(arquivo, media_type="text/html; charset=utf-8")


@router.get("/robots.txt")
def robots(request: Request):
    return templates.TemplateResponse(request, "robots.txt", {}, media_type="text/plain")


@router.get("/{chave}.txt", include_in_schema=False)
def indexnow_chave(chave: str):
    """Arquivo de verificação do IndexNow (/<chave>.txt)."""
    from fastapi.responses import PlainTextResponse
    from appsettings import cfg
    if not cfg.INDEXNOW_KEY or chave != cfg.INDEXNOW_KEY:
        raise HTTPException(status_code=404)
    return PlainTextResponse(cfg.INDEXNOW_KEY)


@router.get("/sitemap.xml")
def sitemap(request: Request):
    """Mapa do site para os buscadores: páginas fixas + todos os artigos da Base de Conhecimento (com lastmod)."""
    entradas = [("", None, "weekly", "1.0")]
    if wiki.configurada():
        try:
            paginas = wiki.livro()["paginas"]
            datas = [p["atualizado"] or p["publicado"] for p in paginas if p["atualizado"] or p["publicado"]]
            entradas.append(("conhecimento", max(datas) if datas else None, "daily", "0.9"))
            entradas += [(f"conhecimento/{p['slug']}", p["atualizado"] or p["publicado"], "monthly", "0.7")
                         for p in paginas]
        except Exception:
            entradas.append(("conhecimento", None, "daily", "0.9"))
    entradas += [(f"servicos/{s}", None, "monthly", "0.8") for s in SERVICOS_ORDEM]
    entradas.append(("contato", None, "yearly", "0.6"))
    return templates.TemplateResponse(request, "sitemap.xml", {"entradas": entradas}, media_type="application/xml")
