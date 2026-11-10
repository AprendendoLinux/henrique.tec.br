from fastapi.testclient import TestClient

import database
import models
from app import app
from tests.conftest import login_admin, login_user, post

DASH = "/admin/dashboard"
SENHA = "Colega@Senha123"


def _id(username):
    db = database.SessionLocal()
    try:
        return db.query(models.Usuario).filter_by(username=username).first().id
    finally:
        db.close()


def _limpar(client, username):
    uid = _id(username)
    if uid:
        post(client, f"/admin/usuarios/delete/{uid}", {}, page=DASH)


def test_admin_promove_e_rebaixa_usuario(client):
    login_admin(client)
    post(client, "/admin/usuarios/add", {"username": "colega", "password": SENHA, "confirm_password": SENHA}, page=DASH)
    uid = _id("colega")
    try:
        with TestClient(app, follow_redirects=False) as outro:
            login_user(outro, "colega", SENHA)
            assert outro.get(DASH).status_code == 200
            assert "Apenas o administrador" in outro.get(DASH).text
            r = post(outro, "/admin/config/smtp", {"smtp_host": "x.local"}, page=DASH)
            assert r.status_code == 403

            post(client, f"/admin/usuarios/toggle_admin/{uid}", {}, page=DASH)
            assert "Apenas o administrador altera as configurações" not in outro.get(DASH).text
            assert post(outro, "/admin/telegram/edit", {"usuario": "caradolinux"}, page=DASH).status_code == 302

            post(client, f"/admin/usuarios/toggle_admin/{uid}", {}, page=DASH)
            assert post(outro, "/admin/config/smtp", {"smtp_host": "x.local"}, page=DASH).status_code == 403
    finally:
        _limpar(client, "colega")


def test_nao_admin_nao_promove_ninguem(client):
    login_admin(client)
    post(client, "/admin/usuarios/add", {"username": "colega2", "password": SENHA, "confirm_password": SENHA}, page=DASH)
    uid = _id("colega2")
    try:
        with TestClient(app, follow_redirects=False) as outro:
            login_user(outro, "colega2", SENHA)
            assert post(outro, f"/admin/usuarios/toggle_admin/{uid}", {}, page=DASH).status_code == 403
            assert post(outro, "/admin/usuarios/add", {"username": "x1x1x", "password": SENHA, "confirm_password": SENHA}, page=DASH).status_code == 403
    finally:
        _limpar(client, "colega2")


def test_admin_principal_e_o_proprio_perfil_sao_protegidos(client):
    login_admin(client)
    assert post(client, f"/admin/usuarios/toggle_admin/{_id('admin')}", {}, page=DASH).status_code == 302
    db = database.SessionLocal()
    try:
        assert db.query(models.Usuario).filter_by(username="admin").first().is_admin is True
    finally:
        db.close()


def test_admin_secundario_nao_remove_o_principal_nem_a_si(client):
    login_admin(client)
    post(client, "/admin/usuarios/add", {"username": "colega3", "password": SENHA, "confirm_password": SENHA}, page=DASH)
    uid = _id("colega3")
    post(client, f"/admin/usuarios/toggle_admin/{uid}", {}, page=DASH)
    try:
        with TestClient(app, follow_redirects=False) as outro:
            login_user(outro, "colega3", SENHA)
            post(outro, f"/admin/usuarios/delete/{_id('admin')}", {}, page=DASH)
            post(outro, f"/admin/usuarios/delete/{uid}", {}, page=DASH)
            post(outro, f"/admin/usuarios/toggle_admin/{uid}", {}, page=DASH)
            assert _id("admin") and _id("colega3")
            db = database.SessionLocal()
            try:
                assert db.query(models.Usuario).filter_by(username="colega3").first().is_admin is True
            finally:
                db.close()
    finally:
        _limpar(client, "colega3")
