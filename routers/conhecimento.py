from fastapi import APIRouter, Depends, HTTPException, Request

import wiki
from deps import get_site_context, templates

router = APIRouter()


def _exige_wiki():
    if not wiki.configurada():
        raise HTTPException(status_code=404)


@router.get("/conhecimento", dependencies=[Depends(_exige_wiki)])
def indice(request: Request, ctx: dict = Depends(get_site_context)):
    try:
        info, erro = wiki.livro(), None
    except Exception:
        info, erro = None, True
    return templates.TemplateResponse(request, "conhecimento.html", {**ctx, "livro": info, "erro": erro},
                                      status_code=503 if erro else 200)


@router.get("/conhecimento/{slug}", dependencies=[Depends(_exige_wiki)])
def artigo(request: Request, slug: str, ctx: dict = Depends(get_site_context)):
    try:
        pagina = wiki.pagina(slug)
    except LookupError:
        raise HTTPException(status_code=404)
    except Exception:
        return templates.TemplateResponse(request, "conhecimento.html", {**ctx, "livro": None, "erro": True},
                                          status_code=503)
    return templates.TemplateResponse(request, "artigo.html", {**ctx, "pagina": pagina})
