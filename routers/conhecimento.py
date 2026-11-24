from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

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
        wiki.aquecer_indice()  # deixa o conteúdo pronto para a busca
    except Exception:
        info, erro = None, True
    return templates.TemplateResponse(request, "conhecimento.html", {**ctx, "livro": info, "erro": erro},
                                      status_code=503 if erro else 200)


@router.get("/conhecimento/busca", dependencies=[Depends(_exige_wiki)])
def busca(q: str = Query("", max_length=100)):
    """Busca no título e no conteúdo dos artigos. Usada pela caixa de busca de /conhecimento."""
    if len(q.strip()) < 2:
        return {"resultados": []}
    try:
        return {"resultados": wiki.buscar(q)}
    except Exception:
        return JSONResponse({"resultados": [], "erro": "indisponivel"}, status_code=503)


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
