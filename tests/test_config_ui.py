import pytest

import database
import models
from appsettings import SECRETS, store
from tests.conftest import ADMIN_PW, login_admin, post

DASH = "/admin/dashboard"


def test_segredos_ficam_criptografados_no_banco(client):
    login_admin(client)
    r = post(client, "/admin/config/telegram-bot",
             {"telegram_bot_token": "123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "telegram_chat_id": "42"}, page=DASH)
    assert r.status_code == 302
    db = database.SessionLocal()
    try:
        row = db.get(models.Setting, "telegram_bot_token")
        assert row.is_secret and "123456789:" not in row.value and row.value.startswith("gAAAA")
        assert db.get(models.Setting, "secret_key").value.startswith("gAAAA")
    finally:
        db.close()
    assert store.get("telegram_bot_token").startswith("123456789:")


def test_smtp_salvo_no_banco_e_senha_em_branco_mantem(client):
    login_admin(client)
    base = {"smtp_host": "smtp.novo.local", "smtp_port": "465", "smtp_security": "ssl", "smtp_user": "u@novo.local",
            "smtp_password": "SenhaNova#1", "smtp_from": "site@novo.local", "smtp_from_name": "Site",
            "smtp_verify_tls": "on", "contact_to": "dest@novo.local"}
    assert post(client, "/admin/config/smtp", base, page=DASH).status_code == 302
    assert store.get("smtp_host") == "smtp.novo.local" and store.get("smtp_password") == "SenhaNova#1"
    post(client, "/admin/config/smtp", {**base, "smtp_password": ""}, page=DASH)
    assert store.get("smtp_password") == "SenhaNova#1"
    post(client, "/admin/config/smtp", {**base, "smtp_user": "", "smtp_password": "", "smtp_port": "25", "smtp_security": "none"}, page=DASH)
    assert store.get("smtp_user") == "" and store.get("smtp_password") == ""
    import mailer
    assert mailer.smtp_security() == "none"


@pytest.mark.parametrize("url,dados", [
    ("/admin/config/smtp", {"smtp_host": "bad host!", "smtp_port": "25", "smtp_security": "none"}),
    ("/admin/config/smtp", {"smtp_host": "ok.local", "smtp_port": "99999", "smtp_security": "none"}),
    ("/admin/config/smtp", {"smtp_host": "ok.local", "smtp_port": "25", "smtp_security": "hack"}),
    ("/admin/config/telegram-bot", {"telegram_bot_token": "invalido", "telegram_chat_id": "1"}),
    ("/admin/config/rede", {"trusted_proxies": "999.1.1.1/8", "client_ip_headers": ""}),
    ("/admin/config/rede", {"trusted_proxies": "10.0.0.0/8", "client_ip_headers": "host"}),
    ("/admin/config/recaptcha", {"recaptcha_enabled": "on", "recaptcha_site_key": "", "recaptcha_secret": ""}),
])
def test_validacao_das_configuracoes(client, url, dados):
    login_admin(client)
    r = post(client, url, dados, page=DASH)
    assert r.status_code in (400, 422)


def test_config_so_para_admin_e_exige_csrf(client):
    assert client.post("/admin/config/smtp", data={"smtp_host": "x"}).status_code in (302, 403)
    login_admin(client)
    assert client.post("/admin/config/smtp", data={"smtp_host": "x.local"}).status_code == 403


def test_trocar_minha_senha(client):
    from security import verify_password
    login_admin(client)
    r = post(client, "/admin/conta/senha", {"senha_atual": "errada", "password": "Nova@Senha123", "confirm_password": "Nova@Senha123"}, page=DASH)
    assert r.status_code == 302
    db = database.SessionLocal()
    try:
        assert verify_password(ADMIN_PW, db.query(models.Usuario).filter_by(username="admin").first().password_hash)
    finally:
        db.close()
    post(client, "/admin/conta/senha", {"senha_atual": ADMIN_PW, "password": "Nova@Senha123", "confirm_password": "Nova@Senha123"}, page=DASH)
    assert client.get(DASH).status_code == 200
    db = database.SessionLocal()
    try:
        a = db.query(models.Usuario).filter_by(username="admin").first()
        assert verify_password("Nova@Senha123", a.password_hash)
    finally:
        db.close()
    post(client, "/admin/conta/senha", {"senha_atual": "Nova@Senha123", "password": ADMIN_PW, "confirm_password": ADMIN_PW}, page=DASH)


def test_cookie_secure_por_configuracao_e_https(client):
    r = client.get("/admin")
    assert "secure" not in r.headers["set-cookie"].lower()
    store.save(database.SessionLocal(), {"cookie_secure": "true"})
    try:
        client.cookies.clear()
        assert "secure" in client.get("/admin").headers["set-cookie"].lower()
    finally:
        store.save(database.SessionLocal(), {"cookie_secure": "false"})
    from fastapi.testclient import TestClient
    from app import app
    with TestClient(app, client=("172.18.0.5", 5000)) as proxy_client:
        r = proxy_client.get("/admin", headers={"x-forwarded-proto": "https"})
        assert "secure" in r.headers["set-cookie"].lower()
    with TestClient(app, client=("200.10.20.30", 5000)) as direto:
        r = direto.get("/admin", headers={"x-forwarded-proto": "https"})
        assert "secure" not in r.headers["set-cookie"].lower()


def test_botao_unico_fica_na_posicao_original(client):
    login_admin(client)
    dados = {"numero": "5521999999999", "mensagem": "Oi"}
    post(client, "/admin/whatsapp/edit", dados, page=DASH)  # whatsapp desligado
    post(client, "/admin/telegram/edit", {"usuario": "caradolinux", "ativo": "on"}, page="/admin/dashboard")
    html = client.get("/").text
    assert "bottom-6 right-6 z-50 bg-[#229ED9]" in html
    post(client, "/admin/whatsapp/edit", {**dados, "ativo": "on"}, page=DASH)
    assert "bottom-24 right-6 z-50 bg-[#229ED9]" in client.get("/").text
    post(client, "/admin/telegram/edit", {"usuario": "caradolinux"}, page=DASH)


def test_segredos_nunca_aparecem_na_pagina(client):
    login_admin(client)
    html = client.get(DASH).text
    for chave in SECRETS:
        valor = store.get(chave)
        if valor:
            assert valor not in html
