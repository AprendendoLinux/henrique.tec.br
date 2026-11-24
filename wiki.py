"""Integração com a wiki BookStack: lê, em tempo (quase) real, as páginas de um livro público pela API.

As respostas ficam em cache por poucos segundos para não sobrecarregar a wiki; se ela ficar fora do ar,
o último conteúdo obtido continua sendo servido (cache "stale") até a wiki voltar.
"""
import html as html_lib
import json
import logging
import re
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import nh3

from appsettings import cfg

logger = logging.getLogger(__name__)

CACHE_TTL = 30  # segundos
TIMEOUT = 6
BRT = timezone(timedelta(hours=-3), "BRT")  # Brasil sem horário de verão desde 2019
SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,190}$")


class WikiIndisponivel(Exception):
    pass


_cache: dict[str, tuple[float, object]] = {}
_lock = threading.Lock()


def limpar_cache() -> None:
    with _lock:
        _cache.clear()
    with _indice_lock:
        _indice.clear()


def configurada() -> bool:
    return bool(cfg.WIKI_URL and cfg.WIKI_TOKEN_ID and cfg.WIKI_TOKEN_SECRET and cfg.WIKI_BOOK_SLUG)


def _api(caminho: str, params: dict | None = None) -> dict:
    # Chamada pela rede interna (ex.: http://bookstack na rede echelon) quando configurada: evita DNS, TLS e proxy.
    url = (cfg.WIKI_API_URL or cfg.WIKI_URL).rstrip("/") + "/api/" + caminho
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
        return datetime.fromisoformat((iso or "").replace("Z", "+00:00")).astimezone(BRT)
    except ValueError:
        return None


def livro() -> dict:
    """Retorna {nome, descricao, paginas:[{slug,nome,capitulo,publicado,atualizado}]} do livro configurado,
    com as páginas da publicação mais recente para a mais antiga."""
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
                            "publicado": _data(p.get("created_at")), "atualizado": _data(p.get("updated_at"))})

        for item in dados.get("contents") or []:
            if item.get("type") == "chapter":
                for p in item.get("pages") or []:
                    add(p, item.get("name"))
            elif item.get("type") == "page":
                add(item)
        minimo = datetime.min.replace(tzinfo=BRT)
        paginas.sort(key=lambda p: p["publicado"] or minimo, reverse=True)
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
        return {**meta, "nome": dados.get("name") or meta["nome"], "atualizado": _data(dados.get("updated_at")) or meta["atualizado"],
                "html": _sanitizar(dados.get("html") or "", por_slug),
                "url_wiki": f"{cfg.WIKI_URL.rstrip('/')}/books/{cfg.WIKI_BOOK_SLUG}/page/{slug}"}
    return _cacheado(f"pagina:{meta['id']}", produzir)


# ---------------------------------------------------------------- busca no conteúdo
# Índice em memória: id da página -> (updated_at, texto puro). Uma página só é baixada de novo quando
# a data de atualização (que vem da listagem do livro, renovada a cada CACHE_TTL) muda.
_indice: dict[int, tuple[str, str, str]] = {}  # id -> (updated_at, texto, texto normalizado)
_indice_lock = threading.Lock()
_atualizacao_lock = threading.Lock()  # uma indexação por vez: chamadas simultâneas esperam e reaproveitam
TRECHO = 80  # caracteres de contexto em cada lado do termo encontrado


def _normalizar(texto: str) -> tuple[str, list[int]]:
    """Minúsculas e sem acentos, devolvendo também o mapa posição normalizada -> posição original."""
    saida, mapa = [], []
    for i, ch in enumerate(texto):
        for n in unicodedata.normalize("NFD", ch.lower()):
            if not unicodedata.combining(n):
                saida.append(n)
                mapa.append(i)
    return "".join(saida), mapa


def _texto_puro(html: str) -> str:
    sem_tags = nh3.clean(re.sub(r"<(br|/p|/h\d|/li|/pre|/tr|/div)[^>]*>", " \\g<0>", html), tags=set())
    return re.sub(r"\s+", " ", html_lib.unescape(sem_tags)).strip()


def _atualizar_indice(paginas: list[dict]) -> None:
    with _atualizacao_lock:
        _atualizar_indice_sem_lock(paginas)


def _atualizar_indice_sem_lock(paginas: list[dict]) -> None:
    def chave(p):
        return p["atualizado"].isoformat() if p["atualizado"] else ""

    with _indice_lock:
        pendentes = [p for p in paginas if _indice.get(p["id"], ("",))[0] != chave(p) or p["id"] not in _indice]

    def baixar(p):
        try:
            return p, _texto_puro(_api(f"pages/{p['id']}").get("html") or "")
        except (WikiIndisponivel, LookupError) as exc:
            logger.warning("Busca: não foi possível indexar a página %s (%s)", p["id"], exc)
            return p, None

    if pendentes:
        with ThreadPoolExecutor(max_workers=8) as pool:
            for p, texto in pool.map(baixar, pendentes):
                if texto is not None:
                    with _indice_lock:
                        _indice[p["id"]] = (chave(p), texto, _normalizar(texto)[0])
    ids = {p["id"] for p in paginas}
    with _indice_lock:
        for antigo in set(_indice) - ids:  # páginas removidas do livro
            del _indice[antigo]


def aquecer_indice() -> None:
    """Indexa em segundo plano (chamado ao abrir /conhecimento), para a primeira busca já ser rápida."""
    def tarefa():
        try:
            _atualizar_indice(livro()["paginas"])
        except Exception as exc:  # noqa: BLE001 - nunca derruba a página
            logger.warning("Busca: falha ao aquecer o índice (%s)", exc)
    threading.Thread(target=tarefa, daemon=True).start()


def _trecho(texto: str, termos: list[str]) -> str:
    norm, mapa = _normalizar(texto)
    pos = min((norm.find(t) for t in termos if norm.find(t) >= 0), default=-1)
    if pos < 0:
        return ""
    ini_o = mapa[max(0, pos - TRECHO)]
    fim_n = min(len(norm), pos + TRECHO)
    fim_o = mapa[fim_n - 1] + 1 if fim_n else 0
    # ajusta para não cortar palavras
    while ini_o > 0 and not texto[ini_o - 1].isspace():
        ini_o -= 1
    while fim_o < len(texto) and not texto[fim_o].isspace():
        fim_o += 1
    janela = texto[ini_o:fim_o]
    jn, jmapa = _normalizar(janela)
    marcas = []
    for t in termos:
        for m in re.finditer(re.escape(t), jn):
            marcas.append((jmapa[m.start()], jmapa[m.end() - 1] + 1))
    marcas.sort()
    partes, cursor = [], 0
    for a, b in marcas:
        if a < cursor:
            continue
        partes.append(html_lib.escape(janela[cursor:a]))
        partes.append("<mark>" + html_lib.escape(janela[a:b]) + "</mark>")
        cursor = b
    partes.append(html_lib.escape(janela[cursor:]))
    return ("… " if ini_o > 0 else "") + "".join(partes) + (" …" if fim_o < len(texto) else "")


def buscar(consulta: str) -> list[dict]:
    """Artigos do livro em que TODAS as palavras aparecem no título, capítulo ou conteúdo (sem diferenciar
    acentos e maiúsculas). Retorna [{slug, trecho}] na ordem do livro; trecho vem em HTML seguro com <mark>."""
    termos = [t for t in _normalizar(consulta)[0].split() if t][:8]
    if not termos:
        return []
    paginas = livro()["paginas"]
    _atualizar_indice(paginas)
    with _indice_lock:
        textos = {pid: (txt, norm) for pid, (_, txt, norm) in _indice.items()}
    resultados = []
    for p in paginas:
        conteudo, conteudo_norm = textos.get(p["id"], ("", ""))
        titulo_norm = _normalizar(f'{p["nome"]} {p["capitulo"] or ""}')[0]
        if all(t in titulo_norm or t in conteudo_norm for t in termos):
            no_titulo = all(t in titulo_norm for t in termos)
            resultados.append({"slug": p["slug"], "trecho": "" if no_titulo else _trecho(conteudo, termos)})
    return resultados


def testar() -> str:
    """Usado pelo botão de teste do painel. Retorna uma mensagem de sucesso ou levanta exceção."""
    limpar_cache()
    info = livro()
    return f"Conectado: livro '{info['nome']}' com {len(info['paginas'])} página(s)."
