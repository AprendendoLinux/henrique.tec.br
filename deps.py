import json
import logging
import threading
import time
import urllib.parse
import urllib.request
from types import SimpleNamespace

from fastapi import Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

import config
from appsettings import cfg
import models
import wiki
from database import SessionLocal, get_db
from security import csrf_input, csrf_protect, user_fingerprint

logger = logging.getLogger(__name__)

templates = Jinja2Templates(directory="templates")
templates.env.globals["csrf_input"] = csrf_input


def base_publica(request: Request) -> str:
    """URL base pública (com barra final). Atrás do proxy reverso, usa https quando o proxy confiável informa."""
    from session import _https
    base = str(request.base_url)
    if _https(request.scope) and base.startswith("http://"):
        base = "https://" + base[len("http://"):]
    return base


templates.env.globals["base_publica"] = base_publica


def _brt(dt, fmt: str = "%d/%m/%Y %H:%M") -> str:
    """Horário gravado em UTC (sem fuso) exibido no horário de Brasília."""
    if not dt:
        return "-"
    from datetime import timedelta
    return (dt - timedelta(hours=3)).strftime(fmt)


templates.env.filters["brt"] = _brt


def _links_perfil(contatos) -> list[str]:
    """URLs públicas (https) dos perfis/redes do rodapé, para o sameAs do Schema.org."""
    return [c.url for c in (contatos or []) if (c.url or "").startswith("https://")]


def _seo_verificacao() -> dict:
    """Códigos de verificação do Google Search Console e do Bing Webmaster (configurados no painel)."""
    return {"google": cfg.GOOGLE_SITE_VERIFICATION, "bing": cfg.BING_SITE_VERIFICATION}


templates.env.globals["links_perfil"] = _links_perfil
templates.env.globals["seo_verificacao"] = _seo_verificacao


def _bandeira(pais: str | None):
    """Bandeira do país (imagem pequena; emojis de bandeira não aparecem no Windows)."""
    from markupsafe import Markup
    if not pais or len(pais) != 2 or not pais.isalpha():
        return Markup('<i class="fa-solid fa-globe text-gray-600"></i>')
    cod = pais.lower()
    return Markup(f'<img class="sg-flag" src="https://flagcdn.com/16x12/{cod}.png" alt="{pais.upper()}" '
                  f'title="{pais.upper()}" loading="lazy">')


templates.env.filters["bandeira"] = _bandeira


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


# Contexto comum das páginas públicas (rodapé, botões flutuantes) em cache: as páginas públicas não seguram
# conexão do banco durante a requisição. Numa rajada de robôs, cada página segurando uma conexão esgotava o pool
# e travava o site. Alterações no painel limpam o cache (ver limpar_contexto no middleware do app).
CONTEXTO_TTL = 60
_contexto: tuple[float, dict] | None = None
_contexto_lock = threading.Lock()


def _instantaneo(obj) -> SimpleNamespace:
    """Cópia das colunas do registro, independente da sessão do banco."""
    return SimpleNamespace(**{c.key: getattr(obj, c.key) for c in obj.__table__.columns})


def limpar_contexto() -> None:
    global _contexto
    _contexto = None


def site_context(db: Session | None = None) -> dict:
    global _contexto
    item = _contexto
    if item is None or time.monotonic() - item[0] >= CONTEXTO_TTL:
        with _contexto_lock:  # uma consulta por vez; quem chega junto reaproveita o resultado
            item = _contexto
            if item is None or time.monotonic() - item[0] >= CONTEXTO_TTL:
                proprio = db is None
                db = db or SessionLocal()
                try:
                    dados = {"contatos": [_instantaneo(c) for c in db.query(models.Contato).limit(10).all()],
                             "whatsapp_url": get_whatsapp_url(db), "telegram_url": get_telegram_url(db)}
                finally:
                    if proprio:
                        db.close()
                item = _contexto = (time.monotonic(), dados)
    return {**item[1], "contatos": list(item[1]["contatos"]), "version": config.APP_VERSION,
            "wiki_ativa": wiki.configurada()}


def get_site_context() -> dict:
    return site_context()


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


def require_admin(request: Request, user=Depends(require_user)):
    if not user.is_admin:
        import monitor
        from security import client_ip
        monitor.registrar_evento(client_ip(request), "acesso_negado", user.username, request.url.path,
                                 "Ação exclusiva de administrador")
        raise HTTPException(status_code=403, detail="Apenas o administrador pode executar esta ação.")
    return user


async def admin_guard(request: Request, user=Depends(require_user)):
    if request.method == "POST":
        await csrf_protect(request)
    return user


def verify_recaptcha(token: str | None, login: bool = False) -> str | None:
    if not (cfg.RECAPTCHA_LOGIN if login else cfg.ENABLE_RECAPTCHA):
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


def recaptcha_context(login: bool = False) -> dict:
    return {"enable_recaptcha": cfg.RECAPTCHA_LOGIN if login else cfg.ENABLE_RECAPTCHA,
            "recaptcha_site_key": cfg.RECAPTCHA_SITE_KEY}
