import logging
import mimetypes
import os
import secrets
import time

from alembic import command
from alembic.config import Config as AlembicConfig
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import RedirectResponse

import config
import models
from database import SessionLocal, engine
from appsettings import store
from deps import RedirectToLogin, limpar_contexto, site_context, templates
from session import DynamicSessionMiddleware
import monitor
import wiki
from routers import admin, auth, conhecimento, contact, public, seguranca
from security import client_ip, decrypt_secret, encrypt_secret, get_password_hash, is_encrypted, validar_senha_forte

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
    if wiki.configurada():
        wiki.aquecer_indice()  # índice da busca da Base de Conhecimento pronto antes do primeiro visitante
    if engine.dialect.name != "sqlite":
        wiki.iniciar_atualizacao_periodica()  # novos artigos entram na busca e no IndexNow sem depender de visitas
    monitor.iniciar()  # gravação de acessos/eventos e geolocalização em segundo plano
    if engine.dialect.name != "sqlite":
        import cloudflare
        cloudflare.iniciar()  # bloqueios feitos pela Cloudflare (WAF/bots) entram nos eventos de segurança
    import indexnow
    indexnow.garantir_chave()
    yield


app = FastAPI(title="Henrique.tec.br", description="Infraestrutura e Sistemas", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)

app.add_middleware(DynamicSessionMiddleware, max_age=config.SESSION_MAX_AGE)


class HeadComoGet:
    """Responde HEAD como GET (sem corpo): robôs e monitores usam HEAD; o FastAPI responderia 405.
    O servidor (uvicorn) vê o método original HEAD e não envia o corpo."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["method"] == "HEAD":
            scope = dict(scope, method="GET")
        await self.app(scope, receive, send)


app.add_middleware(HeadComoGet)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    inicio = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        if request.method == "POST" and request.url.path.startswith("/admin"):
            limpar_contexto()  # contatos/WhatsApp/Telegram alterados no painel aparecem na hora
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        if request.url.path.startswith("/admin"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Robots-Tag"] = "noindex, nofollow"
        return response
    finally:
        try:
            monitor.registrar_acesso(
                client_ip(request), request.method, request.url.path, status,
                int((time.perf_counter() - inicio) * 1000), request.headers.get("user-agent"),
                request.headers.get("referer"), monitor.geo_dos_cabecalhos(request.headers))
        except Exception as exc:  # noqa: BLE001 - monitoramento nunca derruba o site
            logging.getLogger(__name__).error("Monitor: %s", exc)


mimetypes.add_type("image/webp", ".webp")  # imagens slim não trazem esse tipo
mimetypes.add_type("application/manifest+json", ".webmanifest")
mimetypes.add_type("image/svg+xml", ".svg")
app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(public.router)
app.include_router(contact.router)
app.include_router(conhecimento.router)
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(seguranca.router)


@app.exception_handler(RedirectToLogin)
async def redirect_to_login(request: Request, exc: RedirectToLogin):
    return RedirectResponse(url="/admin", status_code=302)


def _pagina_404(request: Request):
    return templates.TemplateResponse(request, "404.html", site_context(), status_code=404)


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404:
        # Fora do event loop: com o pool de conexões cheio (ex.: rajada de robôs de varredura), esperar uma
        # conexão aqui travava o loop inteiro, e as requisições que deveriam devolver as conexões também
        # (deadlock de 30 s por 404 na fila, o site parava por minutos).
        return await run_in_threadpool(_pagina_404, request)
    from fastapi.exception_handlers import http_exception_handler
    return await http_exception_handler(request, exc)
