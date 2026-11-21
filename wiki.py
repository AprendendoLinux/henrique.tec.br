"""Integração com a wiki BookStack: lê, em tempo (quase) real, as páginas de um livro público pela API.

As respostas ficam em cache por poucos segundos para não sobrecarregar a wiki; se ela ficar fora do ar,
o último conteúdo obtido continua sendo servido (cache "stale") até a wiki voltar.
"""
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

import nh3

from appsettings import cfg

logger = logging.getLogger(__name__)

CACHE_TTL = 30  # segundos
TIMEOUT = 6
SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,190}$")


class WikiIndisponivel(Exception):
    pass


_cache: dict[str, tuple[float, object]] = {}
_lock = threading.Lock()


def limpar_cache() -> None:
    with _lock:
        _cache.clear()


def configurada() -> bool:
    return bool(cfg.WIKI_URL and cfg.WIKI_TOKEN_ID and cfg.WIKI_TOKEN_SECRET and cfg.WIKI_BOOK_SLUG)


def _api(caminho: str, params: dict | None = None) -> dict:
    url = cfg.WIKI_URL.rstrip("/") + "/api/" + caminho
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={
        "Authorization": f"Token {cfg.WIKI_TOKEN_ID}:{cfg.WIKI_TOKEN_SECRET}",
        "Accept": "application/json",
        "User-Agent": "henrique.tec.br-site",
    })
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise LookupError(caminho) from exc
        raise WikiIndisponivel(f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise WikiIndisponivel(type(exc).__name__) from exc


def _cacheado(chave: str, produzir):
    agora = time.monotonic()
    with _lock:
        item = _cache.get(chave)
    if item and agora - item[0] < CACHE_TTL:
        return item[1]
    try:
        valor = produzir()
    except WikiIndisponivel as exc:
        if item:
            logger.warning("Wiki indisponível (%s); servindo conteúdo em cache.", exc)
            return item[1]
        raise
    with _lock:
        _cache[chave] = (agora, valor)
    return valor


def _data(iso: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat((iso or "").replace("Z", "+00:00"))
    except ValueError:
        return None


def livro() -> dict:
    """Retorna {nome, descricao, paginas:[{slug,nome,resumo,atualizado,capitulo}]} do livro configurado."""
    def produzir():
        achados = _api("books", {"filter[slug]": cfg.WIKI_BOOK_SLUG, "count": 1}).get("data") or []
        if not achados:
            raise WikiIndisponivel("livro não encontrado")
        dados = _api(f"books/{achados[0]['id']}")
        paginas = []

        def add(p, capitulo=None):
            if p.get("draft"):
                return
            paginas.append({"id": p["id"], "slug": p["slug"], "nome": p["name"], "capitulo": capitulo,
                            "atualizado": _data(p.get("updated_at"))})

        for item in dados.get("contents") or []:
            if item.get("type") == "chapter":
                for p in item.get("pages") or []:
                    add(p, item.get("name"))
            elif item.get("type") == "page":
                add(item)
        return {"id": dados["id"], "nome": dados.get("name") or "Base de Conhecimento",
                "descricao": dados.get("description") or "", "paginas": paginas}
    return _cacheado("livro", produzir)


ATRIBUTOS = {
    "*": {"id", "class", "title", "align", "dir", "lang"},
    "a": {"href"},
    "img": {"src", "alt", "width", "height", "loading"},
    "td": {"colspan", "rowspan"}, "th": {"colspan", "rowspan", "scope"},
    "ol": {"start", "type"}, "li": {"value"},
    "input": {"type", "checked"},
    "details": {"open"},
}
TAGS = {"p", "br", "hr", "h1", "h2", "h3", "h4", "h5", "h6", "strong", "b", "em", "i", "u", "s", "del", "ins",
        "sub", "sup", "mark", "small", "code", "pre", "kbd", "blockquote", "ul", "ol", "li", "a", "img", "figure",
        "figcaption", "table", "thead", "tbody", "tfoot", "tr", "td", "th", "caption", "colgroup", "col", "div",
        "span", "details", "summary", "input"}


def _sanitizar(html: str, paginas_por_slug: dict) -> str:
    base = cfg.WIKI_URL.rstrip("/")
    prefixo_livro = f"{base}/books/{cfg.WIKI_BOOK_SLUG}/page/"

    def atributo(tag, nome, valor):
        if tag == "input":  # só checkboxes de listas de tarefas, sempre desabilitados
            return valor if nome != "type" or valor == "checkbox" else None
        if nome in ("href", "src"):
            if valor.startswith("/") and not valor.startswith("//"):
                valor = base + valor
            if tag == "a" and valor.startswith(prefixo_livro):
                slug = valor[len(prefixo_livro):].split("#")[0].split("?")[0].strip("/")
                if slug in paginas_por_slug:
                    resto = valor[len(prefixo_livro) + len(slug):]
                    return f"/conhecimento/{slug}{resto if resto.startswith('#') else ''}"
        return valor

    limpo = nh3.clean(html, tags=TAGS, attributes=ATRIBUTOS, url_schemes={"http", "https", "mailto"},
                      attribute_filter=atributo, link_rel="noopener noreferrer")
    # Links externos abrem em nova aba; os internos (/conhecimento, #ancora) não.
    limpo = re.sub(r'<a ([^>]*?)href="(https?://)', r'<a target="_blank" \1href="\2', limpo)
    limpo = limpo.replace("<input ", '<input disabled ')
    return limpo


def pagina(slug: str) -> dict:
    """Retorna a página do livro público (já sanitizada). LookupError se não pertencer ao livro."""
    if not SLUG_RE.match(slug):
        raise LookupError(slug)
    info = livro()
    por_slug = {p["slug"]: p for p in info["paginas"]}
    if slug not in por_slug:
        raise LookupError(slug)
    meta = por_slug[slug]

    def produzir():
        dados = _api(f"pages/{meta['id']}")
        if dados.get("book_id") != info["id"] or dados.get("draft"):
            raise LookupError(slug)
        return {**meta, "nome": dados.get("name") or meta["nome"], "atualizado": _data(dados.get("updated_at")),
                "html": _sanitizar(dados.get("html") or "", por_slug),
                "url_wiki": f"{cfg.WIKI_URL.rstrip('/')}/books/{cfg.WIKI_BOOK_SLUG}/page/{slug}"}
    return _cacheado(f"pagina:{meta['id']}", produzir)


def testar() -> str:
    """Usado pelo botão de teste do painel. Retorna uma mensagem de sucesso ou levanta exceção."""
    limpar_cache()
    info = livro()
    return f"Conectado: livro '{info['nome']}' com {len(info['paginas'])} página(s)."
