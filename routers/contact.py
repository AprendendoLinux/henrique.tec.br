import logging
import re
import time

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

import ipinfo
import mailer
import notify
from deps import get_site_context, recaptcha_context, templates, verify_recaptcha
from security import EMAIL_RE, cadeia_proxies, client_ip, contact_limiter, csrf_protect

logger = logging.getLogger(__name__)
router = APIRouter()

SERVICOS = ["Servidores Linux", "Firewall / MikroTik", "Suporte Desktop", "Docker e Containers",
            "Virtualização", "Desenvolvimento", "Outro assunto"]
PRAZOS = ["Urgente", "Até 1 mês", "Sem pressa"]
TEL_RE = re.compile(r"^[0-9+()\-.\s]{8,30}$")
TEMPO_MINIMO = 3
LIMITE_IP, LIMITE_GLOBAL, JANELA = 3, 30, 600


def _pagina(request: Request, ctx: dict, form: dict | None = None, erro: str | None = None,
            enviado: bool = False, status_code: int = 200):
    return templates.TemplateResponse(request, "contato.html", {
        **ctx, **recaptcha_context(), "form": form or {}, "erro": erro, "enviado": enviado,
        "servicos": SERVICOS, "prazos": PRAZOS,
        "envio_ok": mailer.smtp_configurado() or notify.telegram_configurado(),
    }, status_code=status_code)


@router.get("/contato")
def contato_page(request: Request, ctx: dict = Depends(get_site_context)):
    request.session["form_ts"] = time.time()
    enviado = bool(request.session.pop("contato_enviado", False))
    return _pagina(request, ctx, enviado=enviado)


@router.post("/contato", dependencies=[Depends(csrf_protect)])
def contato_post(
    request: Request,
    nome: str = Form("", max_length=100),
    email: str = Form("", max_length=254),
    telefone: str = Form("", max_length=30),
    servico: str = Form("", max_length=60),
    prazo: str = Form("", max_length=30),
    mensagem: str = Form("", max_length=3000),
    website: str = Form("", max_length=200),
    recaptcha: str | None = Form(None, alias="g-recaptcha-response"),
    ctx: dict = Depends(get_site_context),
):
    form = {"nome": nome, "email": email, "telefone": telefone,
            "servico": servico, "prazo": prazo, "mensagem": mensagem}
    ip = client_ip(request)

    if website:
        request.session["contato_enviado"] = True
        return RedirectResponse("/contato", status_code=303)

    if (contact_limiter.blocked(f"ip:{ip}", LIMITE_IP, JANELA)
            or contact_limiter.blocked("global", LIMITE_GLOBAL, 3600)):
        return _pagina(request, ctx, form, "Muitos envios em pouco tempo. Tente novamente mais tarde.", status_code=429)

    if time.time() - request.session.get("form_ts", 0) < TEMPO_MINIMO:
        return _pagina(request, ctx, form, "Envio rápido demais. Aguarde alguns segundos e tente de novo.", status_code=400)

    nome, email, telefone, mensagem = nome.strip(), email.strip(), telefone.strip(), mensagem.strip()
    erro = None
    if len(nome) < 2:
        erro = "Informe seu nome."
    elif not EMAIL_RE.match(email):
        erro = "Informe um e-mail válido."
    elif telefone and not TEL_RE.match(telefone):
        erro = "Telefone inválido."
    elif servico not in SERVICOS or (prazo and prazo not in PRAZOS):
        erro = "Selecione opções válidas."
    elif len(mensagem) < 10:
        erro = "Descreva sua necessidade (mínimo 10 caracteres)."
    erro = erro or verify_recaptcha(recaptcha)
    if erro:
        return _pagina(request, ctx, form, erro, status_code=400)

    if not (mailer.smtp_configurado() or notify.telegram_configurado()):
        logger.error("Nenhum canal de envio configurado: pedido descartado.")
        return _pagina(request, ctx, form, "Envio indisponível no momento. Use o WhatsApp.", status_code=503)

    assunto = f"[Orçamento] {servico} - {nome}"
    detalhes = ipinfo.detalhes_ip(ip)
    corpo = (
        f"Serviço: {servico}\nPrazo: {prazo or '-'}\n"
        f"Nome: {nome}\nE-mail: {email}\nTelefone: {telefone or '-'}\n\n"
        f"--- Mensagem ---\n{mensagem}\n\n"
        f"--- Detalhes do IP ---\n{detalhes}\n"
        f"Cabeçalhos de proxy: {cadeia_proxies(request)}\n"
    )
    contact_limiter.hit(f"ip:{ip}", JANELA)
    contact_limiter.hit("global", 3600)

    entregue = False
    if mailer.smtp_configurado():
        try:
            mailer.enviar_email(assunto, corpo, reply_to=email, reply_to_nome=nome)
            entregue = True
        except Exception as exc:
            logger.error("Falha ao enviar e-mail do orçamento: %s", exc)
    if notify.telegram_configurado():
        try:
            notify.enviar_telegram("📩 Novo pedido de orçamento\n\n" + corpo)
            entregue = True
        except Exception as exc:
            logger.error("Falha ao notificar no Telegram: %s", type(exc).__name__)

    if not entregue:
        return _pagina(request, ctx, form, "Não foi possível enviar agora. Tente novamente ou use o WhatsApp.", status_code=502)

    request.session["contato_enviado"] = True
    return RedirectResponse("/contato", status_code=303)
