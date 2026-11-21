import pytest

import database
import models
import wiki
from appsettings import store
from tests.conftest import login_admin, post

LIVRO = {"id": 7, "name": "Público", "description": "Meus tutoriais", "contents": [
    {"type": "page", "id": 1, "slug": "chroot", "name": "Fazer chroot", "updated_at": "2026-10-01T10:00:00.000000Z"},
    {"type": "chapter", "name": "Redes", "pages": [
        {"id": 2, "slug": "wireguard", "name": "Túnel WireGuard", "updated_at": "2026-11-01T10:00:00.000000Z"}]},
    {"type": "page", "id": 3, "slug": "rascunho", "name": "Rascunho", "draft": True},
]}
PAGINAS = {
    1: {"id": 1, "book_id": 7, "name": "Fazer chroot", "updated_at": "2026-10-01T10:00:00Z",
        "html": '<h2 id="a">Passo</h2><script>alert(1)</script><p onclick="x()">ok <a href="https://wiki.henrique.tec.br/books/publico/page/wireguard#s">wg</a> '
                '<a href="https://debian.org">debian</a> <img src="/uploads/images/x.png"></p>'
                '<pre><code class="language-bash">chroot /mnt</code></pre><iframe src="https://evil"></iframe>'},
    2: {"id": 2, "book_id": 7, "name": "Túnel WireGuard", "updated_at": "2026-11-01T10:00:00Z", "html": "<p>wg</p>"},
}


@pytest.fixture()
def wiki_on(monkeypatch):
    for k, v in {"wiki_url": "https://wiki.henrique.tec.br", "wiki_book_slug": "publico",
                 "wiki_token_id": "abcdefgh12", "wiki_token_secret": "segredo1234"}.items():
        monkeypatch.setitem(store._v, k, v)
    chamadas = []

    def api(caminho, params=None):
        chamadas.append(caminho)
        if api.fora:
            raise wiki.WikiIndisponivel("down")
        if caminho == "books":
            return {"data": [{"id": 7}]} if params["filter[slug]"] == "publico" else {"data": []}
        if caminho == "books/7":
            return LIVRO
        if caminho.startswith("pages/"):
            return PAGINAS[int(caminho.split("/")[1])]
        raise LookupError(caminho)
    api.fora = False
    api.chamadas = chamadas
    monkeypatch.setattr(wiki, "_api", api)
    wiki.limpar_cache()
    yield api
    wiki.limpar_cache()


def test_sem_configuracao_nao_aparece(client):
    assert client.get("/conhecimento").status_code == 404
    assert "./conhecimento" not in client.get("/").text


def test_logo_com_cursor_piscando(client):
    html = client.get("/").text
    assert 'class="hk-logo"' in html and '<span class="hk-cursor">_</span>' in html


def test_indice_lista_paginas_publicadas(client, wiki_on):
    home = client.get("/").text
    assert 'href="/conhecimento"' in home
    r = client.get("/conhecimento")
    assert r.status_code == 200
    assert "Fazer chroot" in r.text and "Túnel WireGuard" in r.text and "Redes" in r.text
    assert "Rascunho" not in r.text and "Meus tutoriais" in r.text


def test_pagina_sanitizada_e_links_reescritos(client, wiki_on):
    r = client.get("/conhecimento/chroot")
    assert r.status_code == 200
    html = r.text.split('class="kb-conteudo">')[1].split("</article>")[0]
    assert "<script>alert" not in html and "onclick" not in html and "<iframe" not in html
    assert 'href="/conhecimento/wireguard#s"' in html
    assert 'target="_blank"' in html and 'href="https://debian.org"' in html
    assert 'src="https://wiki.henrique.tec.br/uploads/images/x.png"' in html
    assert 'class="language-bash"' in html


def test_pagina_fora_do_livro_e_rascunho_dao_404(client, wiki_on):
    assert client.get("/conhecimento/nao-existe").status_code == 404
    assert client.get("/conhecimento/rascunho").status_code == 404
    assert client.get("/conhecimento/..%2Fadmin").status_code == 404


def test_cache_e_wiki_fora_do_ar(client, wiki_on):
    assert client.get("/conhecimento/chroot").status_code == 200
    n = len(wiki_on.chamadas)
    client.get("/conhecimento/chroot")
    assert len(wiki_on.chamadas) == n  # veio do cache
    wiki_on.fora = True
    wiki._cache.update({k: (0, v) for k, (_, v) in wiki._cache.items()})  # expira o cache
    assert client.get("/conhecimento/chroot").status_code == 200  # serve o conteúdo antigo
    wiki.limpar_cache()
    assert client.get("/conhecimento").status_code == 503


def test_sitemap_inclui_artigos(client, wiki_on):
    xml = client.get("/sitemap.xml").text
    assert "conhecimento/chroot" in xml and "conhecimento/wireguard" in xml


def test_admin_salva_config_wiki_com_segredo_criptografado(client, monkeypatch):
    for k in ("wiki_url", "wiki_book_slug", "wiki_token_id", "wiki_token_secret"):
        monkeypatch.setitem(store._v, k, store.get(k))
    login_admin(client)
    dash = "/admin/dashboard"
    r = post(client, "/admin/config/wiki", {"wiki_url": "https://wiki.exemplo.com/", "wiki_book_slug": "Publico",
                                           "wiki_token_id": "TokenId123", "wiki_token_secret": "Segredo12345"}, page=dash)
    assert r.status_code == 302
    assert store.get("wiki_url") == "https://wiki.exemplo.com" and store.get("wiki_book_slug") == "publico"
    db = database.SessionLocal()
    try:
        row = db.get(models.Setting, "wiki_token_secret")
        assert row.is_secret and "Segredo" not in row.value
    finally:
        db.close()
    assert post(client, "/admin/config/wiki", {"wiki_url": "javascript:alert(1)", "wiki_book_slug": "publico",
                                              "wiki_token_id": "", "wiki_token_secret": ""}, page=dash).status_code == 400
    # limpa para não afetar outros testes
    post(client, "/admin/config/wiki", {"wiki_url": "https://wiki.henrique.tec.br", "wiki_book_slug": "publico",
                                       "wiki_token_id": "", "wiki_token_secret": ""}, page=dash)
