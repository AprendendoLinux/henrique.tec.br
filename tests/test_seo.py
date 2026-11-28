import json
import re

import indexnow
import wiki
from appsettings import store
from tests.conftest import login_admin, post
from tests.test_wiki import PAGINAS, wiki_on  # noqa: F401 - fixture reutilizada

DASH = "/admin/dashboard"


def _jsonld(html):
    return [json.loads(b) for b in re.findall(r'<script type="application/ld\+json">(.*?)</script>', html, re.S)]


def _meta(html, chave, valor):
    m = re.search(rf'<meta {chave}="{re.escape(valor)}" content="([^"]*)"', html)
    return m.group(1) if m else None


def test_home_tem_canonica_descricao_e_dados_estruturados(client):
    html = client.get("/").text
    assert '<link rel="canonical" href="http://testserver/">' in html
    assert _meta(html, "name", "description").startswith("Henrique Fagundes: projetos de ponta a ponta")
    assert _meta(html, "name", "robots").startswith("index, follow")
    grafo = _jsonld(html)[0]["@graph"]
    tipos = [g["@type"] for g in grafo]
    assert "WebSite" in tipos and ["Person", "ProfessionalService"] in tipos
    site = next(g for g in grafo if g["@type"] == "WebSite")
    assert site["potentialAction"]["target"].endswith("conhecimento?q={search_term_string}")


def test_paginas_de_servico_tem_titulo_e_descricao_proprios(client):
    html = client.get("/servicos/firewall").text
    assert _meta(html, "property", "og:title") == "Firewall e Segurança | Henrique Fagundes"
    assert "MikroTik" in _meta(html, "name", "description")
    assert '<link rel="canonical" href="http://testserver/servicos/firewall">' in html


def test_artigo_tem_descricao_do_conteudo_e_techarticle(client, wiki_on):
    PAGINAS[1]["html"] = '<p id="x"><strong>Fazer chroot</strong></p>\n<p>' + "Como reparar o sistema usando chroot a partir de um live USB. " * 6 + "</p>"
    wiki.limpar_cache()
    html = client.get("/conhecimento/chroot").text
    desc = _meta(html, "name", "description")
    assert desc.startswith("Como reparar o sistema usando chroot") and desc.endswith("…") and len(desc) <= 160
    assert _meta(html, "property", "og:type") == "article"
    assert _meta(html, "property", "article:published_time").startswith("2026-01-10T12:30")
    blocos = _jsonld(html)
    artigo = next(g for b in blocos for g in b.get("@graph", []) if g["@type"] == "TechArticle")
    assert artigo["headline"] == "Fazer chroot" and artigo["url"] == "http://testserver/conhecimento/chroot"
    assert artigo["datePublished"].startswith("2026-01-10") and artigo["wordCount"] > 50
    trilha = next(g for b in blocos for g in b.get("@graph", []) if g["@type"] == "BreadcrumbList")
    assert [i["name"] for i in trilha["itemListElement"]] == ["Início", "Base de Conhecimento", "Fazer chroot"]


def test_admin_e_404_fora_do_indice(client):
    assert _meta(client.get("/admin").text, "name", "robots") == "noindex, nofollow"
    r = client.get("/nao-existe")
    assert r.status_code == 404 and _meta(r.text, "name", "robots") == "noindex, nofollow"


def test_sitemap_com_lastmod_e_robots(client, wiki_on):
    xml = client.get("/sitemap.xml").text
    assert "<loc>http://testserver/conhecimento/wireguard</loc>" in xml
    assert re.search(r"<loc>http://testserver/conhecimento/chroot</loc>\s*<lastmod>2026-10-01T07:00:00-03:00</lastmod>", xml)
    assert "<loc>http://testserver/servicos/linux</loc>" in xml and "<loc>http://testserver/contato</loc>" in xml
    robots = client.get("/robots.txt").text
    assert "Disallow: /conhecimento/busca" in robots and "Sitemap: http://testserver/sitemap.xml" in robots


def test_chave_do_indexnow_publicada(client, monkeypatch):
    monkeypatch.setitem(store._v, "indexnow_key", "a1b2c3d4e5f6a7b8")
    r = client.get("/a1b2c3d4e5f6a7b8.txt")
    assert r.status_code == 200 and r.text == "a1b2c3d4e5f6a7b8"
    assert client.get("/outra-chave.txt").status_code == 404
    assert client.get("/robots.txt").status_code == 200  # rota fixa continua tendo prioridade


def test_indexnow_envia_tudo_na_primeira_vez_e_depois_so_diferencas(monkeypatch, wiki_on):
    enviados = []
    monkeypatch.setenv("SITE_AMBIENTE", "producao")
    monkeypatch.setattr(indexnow, "enviar", lambda urls: (enviados.append(list(urls)), (True, "HTTP 200"))[1])
    monkeypatch.setattr(indexnow, "_salvar", lambda mapa: store._v.update(mapa))
    for k, v in {"indexnow_ativo": "true", "indexnow_estado": "", "site_url": "https://henrique.tec.br",
                 "indexnow_key": "k" * 16}.items():
        monkeypatch.setitem(store._v, k, v)
    paginas = wiki.livro()["paginas"]
    assert "ok" in indexnow.sincronizar(paginas)
    assert "https://henrique.tec.br/conhecimento/chroot" in enviados[0] and "https://henrique.tec.br/" in enviados[0]
    assert indexnow.sincronizar(paginas) is None  # nada mudou
    from datetime import datetime, timezone
    alterado = [dict(p) for p in paginas if p["slug"] != "wireguard-cWb"]  # um removido
    alterado[0]["atualizado"] = datetime(2026, 12, 1, tzinfo=timezone.utc)  # um atualizado
    indexnow.sincronizar(alterado)
    assert set(enviados[-1]) == {f"https://henrique.tec.br/conhecimento/{alterado[0]['slug']}",
                                 "https://henrique.tec.br/conhecimento/wireguard-cWb",
                                 "https://henrique.tec.br/conhecimento", "https://henrique.tec.br/sitemap.xml"}
    monkeypatch.setitem(store._v, "indexnow_ativo", "false")
    assert indexnow.sincronizar(paginas, forcar=True) is None
    monkeypatch.setitem(store._v, "indexnow_ativo", "true")
    monkeypatch.setenv("SITE_AMBIENTE", "dev")
    assert indexnow.sincronizar(paginas, forcar=True) is None  # nunca envia a partir da dev


def test_codigos_de_verificacao_no_head(client, monkeypatch):
    for k in ("site_url", "google_site_verification", "bing_site_verification", "indexnow_ativo"):
        monkeypatch.setitem(store._v, k, store.get(k))
    login_admin(client)
    r = post(client, "/admin/config/seo", {
        "site_url": "https://henrique.tec.br/",
        "google_site_verification": '<meta name="google-site-verification" content="AbC123_googleCode-xyz" />',
        "bing_site_verification": "0123456789ABCDEF0123456789ABCDEF", "indexnow_ativo": "on"}, page=DASH)
    assert r.status_code == 302
    html = client.get("/").text
    assert '<meta name="google-site-verification" content="AbC123_googleCode-xyz">' in html
    assert '<meta name="msvalidate.01" content="0123456789ABCDEF0123456789ABCDEF">' in html
    assert post(client, "/admin/config/seo", {"google_site_verification": "<script>x</script>"},
                page=DASH).status_code == 400


def test_head_responde_como_get(client):
    for caminho, tipo in (("/", "text/html"), ("/sitemap.xml", "application/xml"), ("/robots.txt", "text/plain")):
        r = client.head(caminho)
        assert r.status_code == 200 and r.headers["content-type"].startswith(tipo), caminho
    assert client.head("/nao-existe").status_code == 404


def test_icones_do_site(client):
    html = client.get("/").text
    for tag in ('<link rel="icon" href="/favicon.ico" sizes="48x48">', '<link rel="apple-touch-icon" href="/apple-touch-icon.png">',
                '<link rel="manifest" href="/static/icones/site.webmanifest">', '<meta name="theme-color" content="#050505">'):
        assert tag in html
    ico = client.get("/favicon.ico")
    assert ico.status_code == 200 and ico.headers["content-type"] == "image/x-icon" and ico.content[:4] == b"\x00\x00\x01\x00"
    apple = client.get("/apple-touch-icon.png")
    assert apple.status_code == 200 and apple.content[:8] == b"\x89PNG\r\n\x1a\n"
    assert client.get("/static/icones/favicon.svg").headers["content-type"].startswith("image/svg+xml")
    manifesto = client.get("/static/icones/site.webmanifest")
    assert manifesto.headers["content-type"].startswith("application/manifest+json")
    assert {i["sizes"] for i in manifesto.json()["icons"]} == {"192x192", "512x512", "any"}


def test_pagina_404_nao_usa_o_banco_dentro_do_event_loop(client, monkeypatch):
    import asyncio

    import app as aplicacao
    chamadas = []
    original = aplicacao.site_context

    def espiao(db=None):
        try:
            asyncio.get_running_loop()
            chamadas.append("event loop")  # bloquearia o servidor inteiro com o pool cheio
        except RuntimeError:
            chamadas.append("thread")
        return original(db)

    monkeypatch.setattr(aplicacao, "site_context", espiao)
    assert client.get("/wp-includes/wlwmanifest.xml").status_code == 404
    assert chamadas == ["thread"]


def test_contexto_publico_em_cache_e_atualizado_ao_salvar_no_painel(client):
    import database
    import models
    client.get("/")  # contexto em cache
    db = database.SessionLocal()
    try:
        db.add(models.Contato(nome="Sem painel", url="https://exemplo.invalid/direto", icone="fa-solid fa-link"))
        db.commit()
        assert "exemplo.invalid/direto" not in client.get("/").text  # servido do cache, sem consultar o banco
        login_admin(client)
        post(client, "/admin/contatos/add", {"nome": "Pelo painel", "url": "https://exemplo.invalid/painel", "icone": "fa-solid fa-globe"}, page=DASH)
        html = client.get("/").text
        assert "exemplo.invalid/painel" in html and "exemplo.invalid/direto" in html  # salvar no painel limpa o cache
    finally:
        for c in db.query(models.Contato).filter(models.Contato.url.like("https://exemplo.invalid/%")).all():
            db.delete(c)
        db.commit()
        db.close()
        import deps
        deps.limpar_contexto()


def test_indexnow_nunca_envia_fora_da_producao(monkeypatch):
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("chamou a rede")))
    monkeypatch.setenv("SITE_AMBIENTE", "teste")
    assert indexnow.enviar(["https://henrique.tec.br/"]) == (False, "fora da produção: nada enviado")
