import logging
import os
import secrets
import time

from alembic import command
from alembic.config import Config as AlembicConfig
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import RedirectResponse

import config
import models
from database import SessionLocal, engine
from appsettings import store
from deps import RedirectToLogin, site_context, templates
from session import DynamicSessionMiddleware
from routers import admin, auth, contact, public
from security import decrypt_secret, encrypt_secret, get_password_hash, is_encrypted, validar_senha_forte

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def wait_for_db(retries: int = 60, delay: int = 3) -> None:
    for restantes in range(retries, 0, -1):
        try:
            with engine.connect():
                logger.info("[OK] Conexão com o banco de dados estabelecida.")
                return
        except Exception as exc:
            logger.warning("[AGUARDANDO] Banco iniciando (%s restantes): %s", restantes - 1, type(exc).__name__)
            time.sleep(delay)
    raise RuntimeError("Não foi possível conectar ao banco de dados.")


def run_migrations() -> None:
    if engine.dialect.name == "sqlite":
        models.Base.metadata.create_all(bind=engine)
        return
    command.upgrade(AlembicConfig("alembic.ini"), "head")


def senha_inicial() -> str:
    legada = os.getenv("ADMIN_PASSWORD", "")
    if legada and validar_senha_forte(legada):
        return legada
    return "Aa1!" + secrets.token_urlsafe(12)


def seed() -> None:
    db = SessionLocal()
    try:
        store.seed(db)

        mestre = db.query(models.Usuario).filter(models.Usuario.username == "admin").first()
        if mestre:
            mestre.is_admin = True
        else:
            senha = senha_inicial()
            db.add(models.Usuario(username="admin", password_hash=get_password_hash(senha), is_admin=True))
            if not os.getenv("ADMIN_PASSWORD"):
                logger.warning("=" * 60)
                logger.warning("PRIMEIRO ACESSO - usuário: admin | senha inicial: %s", senha)
                logger.warning("Entre, configure o 2FA e troque a senha em 'Minha Conta'.")
                logger.warning("=" * 60)

        for user in db.query(models.Usuario).filter(models.Usuario.totp_secret.isnot(None)):
            if not is_encrypted(user.totp_secret):
                segredo = decrypt_secret(user.totp_secret)
                user.totp_secret = encrypt_secret(segredo) if segredo else None

        if not db.query(models.TelegramConfig).first():
            db.add(models.TelegramConfig(usuario=None, ativo=False))

        if not db.query(models.WhatsappConfig).first():
            db.add(models.WhatsappConfig(
                numero="5500000000000", mensagem="Olá! Gostaria de falar sobre Infraestrutura e Sistemas."
            ))
        db.commit()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    wait_for_db()
    run_migrations()
    seed()
    yield


app = FastAPI(title="Henrique.tec.br", description="Infraestrutura e Sistemas", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)

app.add_middleware(DynamicSessionMiddleware, max_age=config.SESSION_MAX_AGE)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if request.url.path.startswith("/admin"):
        response.headers["Cache-Control"] = "no-store"
    return response


app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(public.router)
app.include_router(contact.router)
app.include_router(auth.router)
app.include_router(admin.router)


@app.exception_handler(RedirectToLogin)
async def redirect_to_login(request: Request, exc: RedirectToLogin):
    return RedirectResponse(url="/admin", status_code=302)


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404:
        db = SessionLocal()
        try:
            return templates.TemplateResponse(request, "404.html", site_context(db), status_code=404)
        finally:
            db.close()
    from fastapi.exception_handlers import http_exception_handler
    return await http_exception_handler(request, exc)
