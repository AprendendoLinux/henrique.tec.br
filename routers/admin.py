from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

import config
import ipaddress
import logging
import re

import mailer
import models
import notify
from appsettings import SECRETS, cfg, store
from database import get_db
from deps import admin_guard, require_admin, templates
from security import (
    CORES_HOVER, CORES_ICONE, EMAIL_RE, ICONES, TELEGRAM_RE, USERNAME_RE, get_password_hash,
    login_limiter, normalizar_url, user_fingerprint, validar_opcao, validar_senha_forte, verify_password,
)

router = APIRouter(prefix="/admin", dependencies=[Depends(admin_guard)])
admin_only = [Depends(require_admin)]

MAX_CONTATOS = 10


def _back(url: str = "/admin/dashboard") -> RedirectResponse:
    return RedirectResponse(url=url, status_code=302)


def _get_or_404(db: Session, model, obj_id: int):
    obj = db.get(model, obj_id)
    if not obj:
        raise HTTPException(status_code=404)
    return obj


@router.get("/dashboard")
def dashboard(request: Request, user=Depends(admin_guard), db: Session = Depends(get_db)):
    is_admin = bool(user.is_admin)
    return templates.TemplateResponse(request, "admin_dashboard.html", {
        "projetos": db.query(models.Projeto).all(),
        "contatos": db.query(models.Contato).limit(MAX_CONTATOS).all(),
        "usuarios": db.query(models.Usuario).all() if is_admin else [],
        "flash": request.session.pop("flash", None),
        "c": config_view() if is_admin else {},
        "wp_config": db.query(models.WhatsappConfig).first(),
        "tg_config": db.query(models.TelegramConfig).first(),
        "current_user": user.username,
        "is_admin": is_admin,
        "version": config.APP_VERSION,
    })


HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
RECAPTCHA_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{20,100}$")
TG_TOKEN_RE = re.compile(r"^\d{6,12}:[A-Za-z0-9_-]{30,50}$")
TG_CHAT_RE = re.compile(r"^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$")
CABECALHOS_IP = ["cf-connecting-ip", "true-client-ip", "x-real-ip", "x-forwarded-for"]


def config_view() -> dict:
    nomes = ("cookie_secure", "trusted_proxies", "client_ip_headers", "recaptcha_enabled", "recaptcha_site_key",
             "telegram_chat_id", "smtp_host", "smtp_port", "smtp_security", "smtp_user", "smtp_from",
             "smtp_from_name", "smtp_verify_tls", "contact_to")
    view = {n: store.get(n) for n in nomes}
    for n in ("cookie_secure", "recaptcha_enabled", "smtp_verify_tls"):
        view[n] = store.flag(n)
    for n in SECRETS - {"secret_key"}:
        view[n + "_set"] = bool(store.get(n))
    return view


def _flash(request: Request, ok: bool, msg: str) -> RedirectResponse:
    request.session["flash"] = {"ok": ok, "msg": msg}
    return _back()


def _email_ou_vazio(valor: str) -> str:
    valor = valor.strip()
    if valor and not EMAIL_RE.match(valor):
        raise HTTPException(status_code=400, detail="E-mail inválido.")
    return valor


@router.post("/config/smtp", dependencies=admin_only)
def config_smtp(
    request: Request, smtp_host: str = Form("", max_length=253), smtp_port: int = Form(587, ge=1, le=65535),
    smtp_security: str = Form("starttls"), smtp_user: str = Form("", max_length=254),
    smtp_password: str = Form("", max_length=200), smtp_from: str = Form("", max_length=254),
    smtp_from_name: str = Form("", max_length=60), smtp_verify_tls: str | None = Form(None),
    contact_to: str = Form("", max_length=254), db: Session = Depends(get_db),
):
    host = smtp_host.strip()
    if host and not HOST_RE.match(host):
        raise HTTPException(status_code=400, detail="Servidor SMTP inválido.")
    usuario = smtp_user.strip()
    mapa = {
        "smtp_host": host, "smtp_port": smtp_port,
        "smtp_security": validar_opcao(smtp_security, {"starttls", "ssl", "none"}),
        "smtp_user": usuario, "smtp_from": _email_ou_vazio(smtp_from),
        "smtp_from_name": smtp_from_name.strip(), "smtp_verify_tls": "true" if smtp_verify_tls == "on" else "false",
        "contact_to": _email_ou_vazio(contact_to),
    }
    if not usuario:
        mapa["smtp_password"] = ""
    elif smtp_password:
        mapa["smtp_password"] = smtp_password
    store.save(db, mapa)
    return _flash(request, True, "Configurações de e-mail salvas.")


@router.post("/config/telegram-bot", dependencies=admin_only)
def config_telegram_bot(
    request: Request, telegram_bot_token: str = Form("", max_length=100),
    telegram_chat_id: str = Form("", max_length=40), db: Session = Depends(get_db),
):
    chat = telegram_chat_id.strip()
    if chat and not TG_CHAT_RE.match(chat):
        raise HTTPException(status_code=400, detail="ID do chat inválido.")
    mapa = {"telegram_chat_id": chat}
    token = telegram_bot_token.strip()
    if token:
        if not TG_TOKEN_RE.match(token):
            raise HTTPException(status_code=400, detail="Token do bot inválido.")
        mapa["telegram_bot_token"] = token
    if not chat:
        mapa["telegram_bot_token"] = ""
    store.save(db, mapa)
    return _flash(request, True, "Notificações do Telegram salvas.")


@router.post("/config/recaptcha", dependencies=admin_only)
def config_recaptcha(
    request: Request, recaptcha_enabled: str | None = Form(None), recaptcha_site_key: str = Form("", max_length=100),
    recaptcha_secret: str = Form("", max_length=100), db: Session = Depends(get_db),
):
    site, segredo = recaptcha_site_key.strip(), recaptcha_secret.strip()
    if site and not RECAPTCHA_KEY_RE.match(site) or segredo and not RECAPTCHA_KEY_RE.match(segredo):
        raise HTTPException(status_code=400, detail="Chave do reCAPTCHA inválida.")
    ativo = recaptcha_enabled == "on"
    if ativo and (not site or not (segredo or store.get("recaptcha_secret"))):
        raise HTTPException(status_code=400, detail="Informe as duas chaves para ativar o reCAPTCHA.")
    mapa = {"recaptcha_enabled": "true" if ativo else "false", "recaptcha_site_key": site}
    if segredo:
        mapa["recaptcha_secret"] = segredo
    store.save(db, mapa)
    return _flash(request, True, "Configurações do reCAPTCHA salvas.")


@router.post("/config/rede", dependencies=admin_only)
def config_rede(
    request: Request, trusted_proxies: str = Form("", max_length=2000),
    client_ip_headers: str = Form("", max_length=200), cookie_secure: str | None = Form(None),
    db: Session = Depends(get_db),
):
    redes = [p.strip() for p in re.split(r"[,\s]+", trusted_proxies) if p.strip()]
    if len(redes) > 50:
        raise HTTPException(status_code=400, detail="Máximo de 50 redes.")
    try:
        for rede in redes:
            ipaddress.ip_network(rede, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="Rede/CIDR inválido em 'Proxies de confiança'.")
    cabecalhos = [h.strip().lower() for h in client_ip_headers.split(",") if h.strip()]
    if any(h not in CABECALHOS_IP for h in cabecalhos):
        raise HTTPException(status_code=400, detail="Cabeçalho de IP não permitido.")
    store.save(db, {
        "trusted_proxies": ",".join(redes), "client_ip_headers": ",".join(cabecalhos),
        "cookie_secure": "true" if cookie_secure == "on" else "false",
    })
    return _flash(request, True, "Configurações de rede salvas.")


@router.post("/config/test-email", dependencies=admin_only)
def test_email(request: Request, admin=Depends(require_admin)):
    if not mailer.smtp_configurado():
        return _flash(request, False, "Configure servidor, remetente e destinatário antes de testar.")
    try:
        mailer.enviar_email("[Teste] Configuração de e-mail", "Este é um e-mail de teste enviado pelo painel admin.")
    except Exception as exc:
        logging.getLogger(__name__).error("Teste de e-mail falhou: %s", exc)
        return _flash(request, False, f"Falha no envio: {type(exc).__name__}: {str(exc)[:160]}")
    return _flash(request, True, f"E-mail de teste enviado para {cfg.CONTACT_TO}.")


@router.post("/config/test-telegram", dependencies=admin_only)
def test_telegram(request: Request):
    if not notify.telegram_configurado():
        return _flash(request, False, "Configure o token e o ID do chat antes de testar.")
    try:
        notify.enviar_telegram("✅ Teste: notificação enviada pelo painel admin.")
    except Exception as exc:
        return _flash(request, False, f"Falha no envio: {type(exc).__name__}")
    return _flash(request, True, "Mensagem de teste enviada ao Telegram.")


@router.post("/conta/senha")
def alterar_minha_senha(
    request: Request, senha_atual: str = Form(..., max_length=128), password: str = Form(..., max_length=128),
    confirm_password: str = Form(..., max_length=128), user=Depends(admin_guard), db: Session = Depends(get_db),
):
    chave = f"pw:{user.id}"
    if login_limiter.blocked(chave, 5, 900):
        return _flash(request, False, "Muitas tentativas. Aguarde alguns minutos.")
    if not verify_password(senha_atual, user.password_hash):
        login_limiter.hit(chave, 900)
        return _flash(request, False, "Senha atual incorreta.")
    if password != confirm_password:
        return _flash(request, False, "As senhas não conferem.")
    if not validar_senha_forte(password):
        return _flash(request, False, "A senha deve ter 8+ caracteres, maiúscula, número e símbolo.")
    user.password_hash = get_password_hash(password)
    db.commit()
    request.session["pv"] = user_fingerprint(user)
    login_limiter.reset(chave)
    return _flash(request, True, "Senha alterada com sucesso.")


@router.post("/whatsapp/edit")
def edit_whatsapp(
    numero: str = Form(..., max_length=50), mensagem: str = Form(..., max_length=255),
    ativo: str | None = Form(None), db: Session = Depends(get_db),
):
    wp = db.query(models.WhatsappConfig).first() or models.WhatsappConfig()
    wp.numero, wp.mensagem, wp.ativo = numero.strip(), mensagem.strip(), ativo == "on"
    db.add(wp)
    db.commit()
    return _back()


@router.post("/telegram/edit")
def edit_telegram(
    usuario: str = Form("", max_length=80), ativo: str | None = Form(None),
    db: Session = Depends(get_db),
):
    usuario = usuario.strip().removeprefix("https://t.me/").removeprefix("t.me/").lstrip("@").strip("/")
    if usuario and not TELEGRAM_RE.match(usuario):
        raise HTTPException(status_code=400, detail="Usuário do Telegram inválido (5 a 32 caracteres: letras, números e _).")
    habilitado = ativo == "on"
    if habilitado and not usuario:
        raise HTTPException(status_code=400, detail="Informe o usuário para habilitar o botão.")
    tg = db.query(models.TelegramConfig).first() or models.TelegramConfig()
    tg.usuario, tg.ativo = usuario or None, habilitado
    db.add(tg)
    db.commit()
    return _back()


# --- Projetos ---
@router.post("/projetos/add")
def add_projeto(
    titulo: str = Form(..., max_length=60), descricao: str = Form(..., max_length=160),
    categoria: str = Form(..., max_length=50), link_projeto: str = Form(None),
    link_github: str = Form(None), db: Session = Depends(get_db),
):
    db.add(models.Projeto(
        titulo=titulo.strip(), descricao=descricao.strip(), categoria=categoria.strip(),
        link_projeto=normalizar_url(link_projeto), link_github=normalizar_url(link_github),
    ))
    db.commit()
    return _back()


@router.post("/projetos/delete/{projeto_id}")
def delete_projeto(projeto_id: int, db: Session = Depends(get_db)):
    projeto = db.get(models.Projeto, projeto_id)
    if projeto:
        db.delete(projeto)
        db.commit()
    return _back()


@router.get("/projetos/edit/{projeto_id}")
def edit_projeto_page(request: Request, projeto_id: int, db: Session = Depends(get_db)):
    projeto = db.get(models.Projeto, projeto_id)
    if not projeto:
        return _back()
    return templates.TemplateResponse(
        request, "admin_edit_projeto.html", {"projeto": projeto, "version": config.APP_VERSION}
    )


@router.post("/projetos/edit/{projeto_id}")
def edit_projeto_post(
    projeto_id: int, titulo: str = Form(..., max_length=60), descricao: str = Form(..., max_length=160),
    categoria: str = Form(..., max_length=50), link_projeto: str = Form(None),
    link_github: str = Form(None), db: Session = Depends(get_db),
):
    projeto = _get_or_404(db, models.Projeto, projeto_id)
    projeto.titulo, projeto.descricao, projeto.categoria = titulo.strip(), descricao.strip(), categoria.strip()
    projeto.link_projeto = normalizar_url(link_projeto)
    projeto.link_github = normalizar_url(link_github)
    db.commit()
    return _back()


# --- Contatos ---
def _dados_contato(nome, url, icone, cor_icone, cor_hover) -> dict:
    link = normalizar_url(url, ("http", "https", "mailto", "tel"))
    if not link:
        raise HTTPException(status_code=400, detail="URL obrigatória.")
    return {
        "nome": nome.strip(),
        "url": link,
        "icone": validar_opcao(icone, ICONES),
        "cor_icone": validar_opcao(cor_icone, CORES_ICONE, "text-gray-400"),
        "cor_hover": validar_opcao(cor_hover, CORES_HOVER, "hover:border-[#00ffcc] hover:text-[#00ffcc]"),
    }


@router.post("/contatos/add")
def add_contato(
    nome: str = Form(..., max_length=50), url: str = Form(...), icone: str = Form(None),
    cor_icone: str = Form(None), cor_hover: str = Form(None), db: Session = Depends(get_db),
):
    dados = _dados_contato(nome, url, icone, cor_icone, cor_hover)
    if db.query(models.Contato).count() < MAX_CONTATOS:
        db.add(models.Contato(**dados))
        db.commit()
    return _back()


@router.post("/contatos/delete/{contato_id}")
def delete_contato(contato_id: int, db: Session = Depends(get_db)):
    contato = db.get(models.Contato, contato_id)
    if contato:
        db.delete(contato)
        db.commit()
    return _back()


@router.get("/contatos/edit/{contato_id}")
def edit_contato_page(request: Request, contato_id: int, db: Session = Depends(get_db)):
    contato = db.get(models.Contato, contato_id)
    if not contato:
        return _back()
    return templates.TemplateResponse(
        request, "admin_edit_contato.html", {"contato": contato, "version": config.APP_VERSION}
    )


@router.post("/contatos/edit/{contato_id}")
def edit_contato_post(
    contato_id: int, nome: str = Form(..., max_length=50), url: str = Form(...),
    icone: str = Form(None), cor_icone: str = Form(None), cor_hover: str = Form(None),
    db: Session = Depends(get_db),
):
    contato = _get_or_404(db, models.Contato, contato_id)
    for campo, valor in _dados_contato(nome, url, icone, cor_icone, cor_hover).items():
        setattr(contato, campo, valor)
    db.commit()
    return _back()


# --- Usuários (somente admin) ---
@router.post("/usuarios/add", dependencies=admin_only)
def add_usuario(
    username: str = Form(..., max_length=50), password: str = Form(..., max_length=128),
    confirm_password: str = Form(..., max_length=128), db: Session = Depends(get_db),
):
    username = username.strip()
    if password != confirm_password:
        return _back("/admin/dashboard?erro_user=senhas_diferentes")
    if not validar_senha_forte(password):
        return _back("/admin/dashboard?erro_user=senha_fraca")
    if not USERNAME_RE.match(username):
        return _back("/admin/dashboard?erro_user=usuario_invalido")
    if not db.query(models.Usuario).filter(models.Usuario.username == username).first():
        db.add(models.Usuario(username=username, password_hash=get_password_hash(password)))
        db.commit()
    return _back()


@router.post("/usuarios/delete/{usuario_id}")
def delete_usuario(usuario_id: int, admin=Depends(require_admin), db: Session = Depends(get_db)):
    usuario = db.get(models.Usuario, usuario_id)
    if usuario and usuario.username != "admin" and usuario.id != admin.id:
        db.delete(usuario)
        db.commit()
    return _back()


@router.post("/usuarios/toggle_admin/{usuario_id}")
def toggle_admin(usuario_id: int, request: Request, admin=Depends(require_admin), db: Session = Depends(get_db)):
    usuario = db.get(models.Usuario, usuario_id)
    if not usuario:
        raise HTTPException(status_code=404)
    if usuario.username == "admin":
        return _flash(request, False, "O usuário principal 'admin' é sempre administrador.")
    if usuario.id == admin.id:
        return _flash(request, False, "Você não pode alterar o seu próprio perfil.")
    usuario.is_admin = not usuario.is_admin
    db.commit()
    estado = "agora é administrador" if usuario.is_admin else "deixou de ser administrador"
    return _flash(request, True, f"O usuário {usuario.username} {estado}.")


@router.post("/usuarios/disable_2fa/{usuario_id}", dependencies=admin_only)
def disable_2fa(usuario_id: int, db: Session = Depends(get_db)):
    usuario = db.get(models.Usuario, usuario_id)
    if usuario and usuario.username != "admin":
        usuario.is_2fa_enabled = False
        usuario.totp_secret = None
        db.commit()
    return _back()


@router.get("/usuarios/edit/{usuario_id}", dependencies=admin_only)
def edit_usuario_page(request: Request, usuario_id: int, db: Session = Depends(get_db)):
    usuario = db.get(models.Usuario, usuario_id)
    if not usuario or usuario.username == "admin":
        return _back()
    return templates.TemplateResponse(
        request, "admin_edit_usuario.html", {"usuario": usuario, "version": config.APP_VERSION}
    )


@router.post("/usuarios/edit/{usuario_id}", dependencies=admin_only)
def edit_usuario_post(
    usuario_id: int, password: str = Form(..., max_length=128),
    confirm_password: str = Form(..., max_length=128), db: Session = Depends(get_db),
):
    destino = f"/admin/usuarios/edit/{usuario_id}"
    if password != confirm_password:
        return _back(f"{destino}?erro=senhas_diferentes")
    if not validar_senha_forte(password):
        return _back(f"{destino}?erro=senha_fraca")
    usuario = db.get(models.Usuario, usuario_id)
    if usuario and usuario.username != "admin":
        usuario.password_hash = get_password_hash(password)
        db.commit()
    return _back()
