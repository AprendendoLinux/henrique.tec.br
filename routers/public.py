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
        request, "index.html", {**ctx, "projetos": db.query(models.Projeto).all()}
    )


@router.get("/servicos/{slug}")
def servico(request: Request, slug: str, ctx: dict = Depends(get_site_context)):
    if slug not in SERVICOS:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse(request, f"{slug}.html", ctx)


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
