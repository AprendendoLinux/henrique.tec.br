import base64
import time
from io import BytesIO

import pyotp
import qrcode
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

import config
from appsettings import cfg
import models
from database import get_db
from session import _https
from deps import (
    current_user_or_none, get_site_context, recaptcha_context, templates, verify_recaptcha,
)
from security import (
    client_ip, csrf_protect, decrypt_secret, encrypt_secret, login_limiter,
    make_trusted_token, trusted_token_valid, user_fingerprint, verify_dummy, verify_password,
)

router = APIRouter(prefix="/admin")

JANELA = 900
LIMITE_IP = 20
LIMITE_USUARIO = 5
PRE_AUTH_TTL = 300
TRUSTED_COOKIE = "trusted_device"


def _redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url=url, status_code=302)


def _login_page(request, ctx, status_code=200, erro_msg=None):
    return templates.TemplateResponse(
        request, "admin_login.html",
        {**ctx, **recaptcha_context(), "erro": bool(erro_msg), "erro_msg": erro_msg},
        status_code=status_code,
    )


def _qr_base64(uri: str) -> str:
    buffer = BytesIO()
    qrcode.make(uri).save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("utf-8")


def _pre_auth_user(request: Request, db: Session):
    uid = request.session.get("pre_uid")
    if not uid or time.time() - request.session.get("pre_ts", 0) > PRE_AUTH_TTL:
        request.session.pop("pre_uid", None)
        return None
    return db.query(models.Usuario).filter(models.Usuario.id == uid).first()


def _complete_login(request: Request, user, trust_device: bool = False) -> RedirectResponse:
    request.session.clear()
    request.session["uid"] = user.id
    request.session["pv"] = user_fingerprint(user)
    response = _redirect("/admin/dashboard")
    if trust_device:
        response.set_cookie(
            TRUSTED_COOKIE, make_trusted_token(user),
            max_age=config.TRUSTED_DEVICE_DAYS * 86400,
            httponly=True, secure=cfg.COOKIE_SECURE or _https(request.scope), samesite="lax",
        )
    return response


def _setup_page(request, user, secret, erro=False, status_code=200):
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="Henrique.tec.br")
    return templates.TemplateResponse(
        request, "admin_2fa_setup.html",
        {"qr_code": _qr_base64(uri), "secret": secret, "erro": erro, "version": config.APP_VERSION},
        status_code=status_code,
    )


def _check_2fa_limit(request: Request, user) -> bool:
    return login_limiter.blocked(f"2fa:{user.id}", LIMITE_USUARIO, JANELA)


@router.get("")
def login_page(request: Request, user=Depends(current_user_or_none), ctx: dict = Depends(get_site_context)):
    if user:
        return _redirect("/admin/dashboard")
    return _login_page(request, ctx)


@router.post("/login", dependencies=[Depends(csrf_protect)])
def login_post(
    request: Request,
    username: str = Form(..., max_length=50),
    password: str = Form(..., max_length=128),
    recaptcha: str | None = Form(None, alias="g-recaptcha-response"),
    db: Session = Depends(get_db),
    ctx: dict = Depends(get_site_context),
):
    ip_key, user_key = f"login:ip:{client_ip(request)}", f"login:user:{username.lower()}"
    if login_limiter.blocked(ip_key, LIMITE_IP, JANELA) or login_limiter.blocked(user_key, LIMITE_USUARIO, JANELA):
        return _login_page(request, ctx, 429, "Muitas tentativas. Aguarde alguns minutos.")

    erro = verify_recaptcha(recaptcha)
    user = db.query(models.Usuario).filter(models.Usuario.username == username).first()
    senha_ok = verify_password(password, user.password_hash) if user else (verify_dummy(password) or False)

    if erro or not senha_ok:
        login_limiter.hit(ip_key, JANELA)
        login_limiter.hit(user_key, JANELA)
        return _login_page(request, ctx, 401, erro or "Credenciais inválidas.")

    login_limiter.reset(user_key)
    if trusted_token_valid(request.cookies.get(TRUSTED_COOKIE), user):
        return _complete_login(request, user)

    request.session.clear()
    request.session["pre_uid"] = user.id
    request.session["pre_ts"] = time.time()
    return _redirect("/admin/2fa-verify" if user.is_2fa_enabled else "/admin/2fa-setup")


@router.get("/2fa-setup")
def twofa_setup(request: Request, db: Session = Depends(get_db)):
    user = _pre_auth_user(request, db)
    if not user:
        return _redirect("/admin")
    if user.is_2fa_enabled:
        return _redirect("/admin/2fa-verify")
    secret = decrypt_secret(user.totp_secret)
    if not secret:
        secret = pyotp.random_base32()
        user.totp_secret = encrypt_secret(secret)
        db.commit()
    return _setup_page(request, user, secret)


@router.post("/2fa-setup", dependencies=[Depends(csrf_protect)])
def twofa_setup_post(
    request: Request,
    code: str = Form(..., max_length=10),
    trust_device: str | None = Form(None),
    db: Session = Depends(get_db),
):
    user = _pre_auth_user(request, db)
    if not user or user.is_2fa_enabled:
        return _redirect("/admin")
    secret = decrypt_secret(user.totp_secret)
    if not secret:
        return _redirect("/admin/2fa-setup")
    if _check_2fa_limit(request, user):
        request.session.clear()
        return _redirect("/admin")

    if pyotp.TOTP(secret).verify(code.strip(), valid_window=1):
        login_limiter.reset(f"2fa:{user.id}")
        user.is_2fa_enabled = True
        db.commit()
        return _complete_login(request, user, trust_device == "on")

    login_limiter.hit(f"2fa:{user.id}", JANELA)
    return _setup_page(request, user, secret, erro=True, status_code=401)


@router.get("/2fa-verify")
def twofa_verify(request: Request, db: Session = Depends(get_db)):
    user = _pre_auth_user(request, db)
    if not user:
        return _redirect("/admin")
    if not user.is_2fa_enabled:
        return _redirect("/admin/2fa-setup")
    return templates.TemplateResponse(request, "admin_2fa_verify.html", {"version": config.APP_VERSION})


@router.post("/2fa-verify", dependencies=[Depends(csrf_protect)])
def twofa_verify_post(
    request: Request,
    code: str = Form(..., max_length=10),
    trust_device: str | None = Form(None),
    db: Session = Depends(get_db),
):
    user = _pre_auth_user(request, db)
    if not user or not user.is_2fa_enabled:
        return _redirect("/admin")
    if _check_2fa_limit(request, user):
        request.session.clear()
        return _redirect("/admin")

    secret = decrypt_secret(user.totp_secret)
    if secret and pyotp.TOTP(secret).verify(code.strip(), valid_window=1):
        login_limiter.reset(f"2fa:{user.id}")
        return _complete_login(request, user, trust_device == "on")

    login_limiter.hit(f"2fa:{user.id}", JANELA)
    return templates.TemplateResponse(
        request, "admin_2fa_verify.html", {"erro": True, "version": config.APP_VERSION}, status_code=401
    )


@router.post("/logout", dependencies=[Depends(csrf_protect)])
def logout(request: Request):
    request.session.clear()
    return _redirect("/admin")
