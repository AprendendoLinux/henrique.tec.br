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
