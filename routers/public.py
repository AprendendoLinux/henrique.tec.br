from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

import models
import wiki
from database import get_db
from deps import get_site_context, templates

router = APIRouter()

SERVICOS = {"linux", "firewall", "desktop", "docker", "virtualizacao", "desenvolvimento"}


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


@router.get("/sitemap.xml")
def sitemap(request: Request):
    artigos = []
    if wiki.configurada():
        try:
            artigos = ["conhecimento"] + [f"conhecimento/{p['slug']}" for p in wiki.livro()["paginas"]]
        except Exception:
            artigos = ["conhecimento"]
    return templates.TemplateResponse(request, "sitemap.xml", {"artigos": artigos}, media_type="application/xml")
