from tests.conftest import login_admin, post


def test_projetos_mais_recentes_primeiro(client):
    login_admin(client)
    for titulo in ("Projeto Antigo", "Projeto Meio", "Projeto Novo"):
        r = post(client, "/admin/projetos/add", {"titulo": titulo, "descricao": "d", "categoria": "Web"},
                 page="/admin/dashboard")
        assert r.status_code == 302
    for pagina in ("/", "/admin/dashboard"):
        html = client.get(pagina).text
        pos = [html.index(t) for t in ("Projeto Novo", "Projeto Meio", "Projeto Antigo")]
        assert pos == sorted(pos), pagina


def test_card_social_e_sitemap_usam_https_atras_do_proxy():
    from fastapi.testclient import TestClient
    from app import app
    with TestClient(app, client=("127.0.0.1", 5000)) as via_proxy:
        html = via_proxy.get("/", headers={"x-forwarded-proto": "https"}).text
        assert '<meta property="og:image" content="https://testserver/static/social-card.jpg?v=2">' in html
        assert '<meta property="og:url" content="https://testserver/">' in html
        assert 'og:image:width" content="1200"' in html and 'og:image:height" content="630"' in html
        assert "<loc>https://testserver/</loc>" in via_proxy.get("/sitemap.xml", headers={"x-forwarded-proto": "https"}).text
    with TestClient(app, client=("200.10.20.30", 5000)) as direto:  # cliente não confiável não força https
        html = direto.get("/", headers={"x-forwarded-proto": "https"}).text
        assert 'og:image" content="http://testserver/static/social-card.jpg?v=2"' in html


def test_card_social_existe_e_tem_1200x630(client):
    r = client.get("/static/social-card.jpg")
    assert r.status_code == 200 and r.headers["content-type"] == "image/jpeg"
    dados = r.content
    # Lê as dimensões do marcador SOF do JPEG
    i = 2
    while i < len(dados):
        marcador, tamanho = dados[i + 1], int.from_bytes(dados[i + 2:i + 4], "big")
        if marcador in (0xC0, 0xC2):
            altura, largura = int.from_bytes(dados[i + 5:i + 7], "big"), int.from_bytes(dados[i + 7:i + 9], "big")
            break
        i += 2 + tamanho
    assert (largura, altura) == (1200, 630)
