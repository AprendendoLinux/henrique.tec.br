import json
import logging
import urllib.parse
import urllib.request

from fastapi import Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

import config
from appsettings import cfg
import models
from database import get_db
from security import csrf_input, csrf_protect, user_fingerprint

logger = logging.getLogger(__name__)

templates = Jinja2Templates(directory="templates")
templates.env.globals["csrf_input"] = csrf_input


class RedirectToLogin(Exception):
    pass


def get_whatsapp_url(db: Session) -> str | None:
    wp = db.query(models.WhatsappConfig).first()
    if wp and wp.ativo and wp.numero:
        numero = "".join(filter(str.isdigit, wp.numero))
        msg = urllib.parse.quote(wp.mensagem or "")
        return f"https://api.whatsapp.com/send?phone={numero}&text={msg}"
    return None


def get_telegram_url(db: Session) -> str | None:
    tg = db.query(models.TelegramConfig).first()
    if tg and tg.ativo and tg.usuario:
        return f"https://t.me/{tg.usuario}"
    return None


def site_context(db: Session) -> dict:
    return {
        "contatos": db.query(models.Contato).limit(10).all(),
        "whatsapp_url": get_whatsapp_url(db),
        "telegram_url": get_telegram_url(db),
        "version": config.APP_VERSION,
    }


def get_site_context(db: Session = Depends(get_db)) -> dict:
    return site_context(db)


def current_user_or_none(request: Request, db: Session = Depends(get_db)):
    uid = request.session.get("uid")
    if not uid:
        return None
    user = db.query(models.Usuario).filter(models.Usuario.id == uid).first()
    if not user or request.session.get("pv") != user_fingerprint(user):
        request.session.clear()
        return None
    return user


def require_user(user=Depends(current_user_or_none)):
    if not user:
        raise RedirectToLogin()
    return user


def require_admin(user=Depends(require_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Apenas o administrador pode executar esta ação.")
    return user


async def admin_guard(request: Request, user=Depends(require_user)):
    if request.method == "POST":
        await csrf_protect(request)
    return user


def verify_recaptcha(token: str | None) -> str | None:
    if not cfg.ENABLE_RECAPTCHA:
        return None
    if not token:
        return "Por favor, marque a caixa 'Não sou um robô'."
    data = urllib.parse.urlencode(
        {"secret": cfg.RECAPTCHA_SECRET_KEY, "response": token}
    ).encode("utf-8")
    req = urllib.request.Request("https://www.google.com/recaptcha/api/siteverify", data=data)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if not json.loads(response.read().decode()).get("success"):
                return "Falha na validação do reCAPTCHA."
    except Exception as exc:
        logger.error("Erro reCAPTCHA: %s", exc)
        return "Erro interno ao validar o reCAPTCHA."
    return None


def recaptcha_context() -> dict:
    return {"enable_recaptcha": cfg.ENABLE_RECAPTCHA, "recaptcha_site_key": cfg.RECAPTCHA_SITE_KEY}
