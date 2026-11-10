import pyotp
import pytest
from itsdangerous import TimestampSigner

import database
import models
from security import decrypt_secret
from tests.conftest import ADMIN_PW, csrf_from, login_admin, post


def test_cookie_forjado_nao_autentica(client):
    for nome in ("session_token", "session", "trusted_device", "pre_auth_user"):
        client.cookies.set(nome, "admin")
    r = client.get("/admin/dashboard")
    assert r.status_code == 302 and r.headers["location"] == "/admin"


def test_sessao_assinada_com_outra_chave_rejeitada(client):
    import base64, json
    payload = base64.b64encode(json.dumps({"uid": 1, "pv": "x"}).encode())
    forjado = TimestampSigner("outra-chave-qualquer" * 3).sign(payload).decode()
    client.cookies.set("session", forjado)
    assert client.get("/admin/dashboard").status_code == 302


def test_admin_exige_2fa(client):
    r = post(client, "/admin/login", {"username": "admin", "password": ADMIN_PW})
    assert r.headers["location"] in ("/admin/2fa-setup", "/admin/2fa-verify")
    assert client.get("/admin/dashboard").status_code == 302


def test_login_completo_com_2fa(client):
    login_admin(client)
    assert client.get("/admin/dashboard").status_code == 200


def test_login_sem_csrf_bloqueado(client):
    client.get("/admin")
    r = client.post("/admin/login", data={"username": "admin", "password": ADMIN_PW})
    assert r.status_code == 403


def test_acoes_destrutivas_nao_aceitam_get(client):
    login_admin(client)
    for url in ("/admin/projetos/delete/1", "/admin/contatos/delete/1",
                "/admin/usuarios/delete/2", "/admin/usuarios/disable_2fa/2", "/admin/logout"):
        assert client.get(url).status_code in (404, 405)


def test_post_sem_csrf_bloqueado(client):
    login_admin(client)
    r = client.post("/admin/projetos/add", data={"titulo": "x", "descricao": "y", "categoria": "z"})
    assert r.status_code == 403


def test_rate_limit_login(client):
    for _ in range(5):
        r = post(client, "/admin/login", {"username": "admin", "password": "errada"})
        assert r.status_code == 401
    r = post(client, "/admin/login", {"username": "admin", "password": ADMIN_PW})
    assert r.status_code == 429


def test_url_javascript_rejeitada(client):
    login_admin(client)
    r = post(client, "/admin/projetos/add", {
        "titulo": "t", "descricao": "d", "categoria": "c", "link_projeto": "javascript:alert(1)",
    }, page="/admin/dashboard")
    assert r.status_code == 400


def test_icone_e_cor_fora_da_lista_rejeitados(client):
    login_admin(client)
    r = post(client, "/admin/contatos/add", {
        "nome": "n", "url": "https://exemplo.com", "icone": "x\" onload=\"alert(1)", "cor_icone": "text-white",
        "cor_hover": "hover:border-white hover:text-white",
    }, page="/admin/dashboard")
    assert r.status_code == 400


def test_totp_armazenado_criptografado(client):
    login_admin(client)
    db = database.SessionLocal()
    try:
        admin = db.query(models.Usuario).filter_by(username="admin").first()
        assert admin.totp_secret.startswith("gAAAA")
        assert len(decrypt_secret(admin.totp_secret)) == 32
    finally:
        db.close()


def test_senha_trocada_invalida_sessao(client):
    from security import get_password_hash
    login_admin(client)
    assert client.get("/admin/dashboard").status_code == 200
    db = database.SessionLocal()
    try:
        admin = db.query(models.Usuario).filter_by(username="admin").first()
        admin.password_hash = get_password_hash(ADMIN_PW)
        db.commit()
    finally:
        db.close()
    assert client.get("/admin/dashboard").status_code == 302


def test_botao_telegram_so_aparece_se_habilitado(client):
    assert "t.me/" not in client.get("/").text
    login_admin(client)
    r = post(client, "/admin/telegram/edit", {"usuario": "@caradolinux", "ativo": "on"}, page="/admin/dashboard")
    assert r.status_code == 302
    assert "https://t.me/caradolinux" in client.get("/").text
    post(client, "/admin/telegram/edit", {"usuario": "caradolinux"}, page="/admin/dashboard")
    assert "t.me/caradolinux" not in client.get("/").text


def test_telegram_usuario_invalido(client):
    login_admin(client)
    r = post(client, "/admin/telegram/edit", {"usuario": "a b<script>", "ativo": "on"}, page="/admin/dashboard")
    assert r.status_code == 400


def test_botao_whatsapp_respeita_checkbox(client):
    login_admin(client)
    dados = {"numero": "5521999999999", "mensagem": "Olá"}
    post(client, "/admin/whatsapp/edit", {**dados, "ativo": "on"}, page="/admin/dashboard")
    assert "api.whatsapp.com/send?phone=5521999999999" in client.get("/").text
    post(client, "/admin/whatsapp/edit", dados, page="/admin/dashboard")
    assert "api.whatsapp.com" not in client.get("/").text
