import os
import re

os.environ.update({
    "DATABASE_URL": "sqlite://",
    "DB_PASSWORD": "senha-de-teste-123",
    "SECRET_KEY": "x" * 48,
    "ADMIN_PASSWORD": "Admin@2026!ok",
    "COOKIE_SECURE": "false",
    "SMTP_HOST": "smtp.teste.local",
    "SMTP_FROM": "site@teste.local",
    "CONTACT_TO": "dest@teste.local",
})

import pytest
from fastapi.testclient import TestClient

import database
import mailer
import models
import security
from security import decrypt_secret
from app import app

ADMIN_PW = os.environ["ADMIN_PASSWORD"]


def csrf_from(html: str) -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


@pytest.fixture()
def client():
    security.login_limiter._hits.clear()
    security.contact_limiter._hits.clear()
    with TestClient(app, follow_redirects=False) as c:
        yield c


@pytest.fixture()
def enviados(monkeypatch):
    caixa = []
    monkeypatch.setattr(mailer, "enviar_email", lambda a, c, reply_to=None, reply_to_nome=None: caixa.append((a, c, reply_to)))
    return caixa


def post(client, url, data, page="/admin"):
    token = csrf_from(client.get(page).text)
    return client.post(url, data={**data, "csrf_token": token})


def login_user(client, username, password):
    import pyotp
    r = post(client, "/admin/login", {"username": username, "password": password})
    assert r.status_code == 302, r.status_code
    if r.headers["location"] == "/admin/2fa-setup":
        page = client.get("/admin/2fa-setup")
        secret = re.search(r'id="secret-key"[^>]*>([A-Z2-7]+)<', page.text).group(1)
        r = client.post("/admin/2fa-setup", data={"code": pyotp.TOTP(secret).now(), "csrf_token": csrf_from(page.text)})
    if r.headers["location"] == "/admin/2fa-verify":
        page = client.get("/admin/2fa-verify")
        db = database.SessionLocal()
        try:
            user = db.query(models.Usuario).filter_by(username=username).first()
            secret = decrypt_secret(user.totp_secret)
        finally:
            db.close()
        r = client.post("/admin/2fa-verify", data={"code": pyotp.TOTP(secret).now(), "csrf_token": csrf_from(page.text)})
    assert r.headers["location"] == "/admin/dashboard"
    return client


def login_admin(client):
    return login_user(client, "admin", ADMIN_PW)
