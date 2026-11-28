import logging
import re
import time
from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

import antispam
import ipinfo
import email_orcamento
import mailer
import models
import monitor
import notify
from appsettings import cfg
from database import SessionLocal
from deps import base_publica, get_site_context, recaptcha_context, templates, verify_recaptcha
from security import EMAIL_RE, cadeia_proxies, client_ip, contact_limiter, csrf_protect

logger = logging.getLogger(__name__)
router = APIRouter()

SERVICOS = ["Servidores Linux", "Firewall / MikroTik", "Suporte Desktop", "Docker e Containers",
            "Virtualização", "Desenvolvimento", "Outro assunto"]
# slug da página de serviço -> opção pré-selecionada no formulário (/contato?servico=<slug>)
SERVICO_POR_SLUG = {"linux": "Servidores Linux", "firewall": "Firewall / MikroTik", "desktop": "Suporte Desktop",
                    "docker": "Docker e Containers", "virtualizacao": "Virtualização",
                    "desenvolvimento": "Desenvolvimento"}
PRAZOS = ["Urgente", "Até 1 mês", "Sem pressa"]
TEL_RE = re.compile(r"^[0-9+()\-.\s]{8,30}$")
TEMPO_MINIMO = 3
LIMITE_IP, LIMITE_GLOBAL, JANELA = 3, 30, 600
LIMITE_FAIXA, JANELA_FAIXA = 5, 3600  # a faixa inteira (/24 ou /48): os robôs trocam de IP dentro da mesma rede


def _pagina(request: Request, ctx: dict, form: dict | None = None, erro: str | None = None,
            enviado: bool = False, status_code: int = 200):
    return templates.TemplateResponse(request, "contato.html", {
        **ctx, **recaptcha_context(), "form": form or {}, "erro": erro, "enviado": enviado,
        "servicos": SERVICOS, "prazos": PRAZOS,
        "envio_ok": mailer.smtp_configurado() or notify.telegram_configurado(),
    }, status_code=status_code)


@router.get("/contato")
def contato_page(request: Request, servico: str = "", ctx: dict = Depends(get_site_context)):
    request.session["form_ts"] = time.time()
    enviado = bool(request.session.pop("contato_enviado", False))
    form = {"servico": SERVICO_POR_SLUG[servico]} if servico in SERVICO_POR_SLUG else None
    return _pagina(request, ctx, form, enviado=enviado)


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

    def fingir_sucesso():  # o robô não percebe que foi barrado e não muda de tática
        request.session["contato_enviado"] = True
        return RedirectResponse("/contato", status_code=303)

    if website:
        monitor.registrar_evento(ip, "spam_formulario", None, "/contato", "Campo-isca preenchido")
        antispam.penalizar(ip)
        return fingir_sucesso()

    with SessionLocal() as db:
        reincidente = antispam.penalizado(ip, db)
    if reincidente:
        monitor.registrar_evento(ip, "formulario_bloqueado", None, "/contato",
                                 f"Reincidente: caiu no campo-isca nas últimas {antispam.PENALIDADE_HORAS} h")
        return fingir_sucesso()

    rede = antispam.faixa(ip)
    if (contact_limiter.blocked(f"ip:{ip}", LIMITE_IP, JANELA)
            or contact_limiter.blocked(f"faixa:{rede}", LIMITE_FAIXA, JANELA_FAIXA)
            or contact_limiter.blocked("global", LIMITE_GLOBAL, 3600)):
        monitor.registrar_evento(ip, "formulario_bloqueado", None, "/contato", f"Limite de envios atingido ({rede})")
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

    contact_limiter.hit(f"ip:{ip}", JANELA)
    contact_limiter.hit(f"faixa:{rede}", JANELA_FAIXA)
    contact_limiter.hit("global", 3600)

    ind = dict(ipinfo.indicadores(ip))
    try:
        with SessionLocal() as db:
            ind["historico_ip"], ind["historico_faixa"] = antispam.historico(ip, db)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Histórico do IP indisponível: %s", exc)
    pontos, motivos = antispam.pontuar(nome, email, mensagem, ind)
    m = models.MensagemContato(
        ts=datetime.utcnow(), status="quarentena" if antispam.suspeito(pontos) else "entregue", nome=nome[:100],
        email=email[:254], telefone=telefone or None, servico=servico, prazo=prazo or None, mensagem=mensagem, ip=ip,
        pais=ind["pais"][:2] or None, cidade=ind["cidade"][:80] or None, org=ind["org"][:120] or None, pontuacao=pontos,
        motivos="; ".join(motivos)[:500] or None, detalhes_ip=ipinfo.detalhes_ip(ip), proxies=cadeia_proxies(request)[:500])

    if m.status == "quarentena":
        _salvar(m)
        monitor.registrar_evento(ip, "formulario_quarentena", None, "/contato", f"pontuação {pontos}: {m.motivos}"[:300])
        logger.info("Pedido de orçamento em quarentena (pontuação %s).", pontos)
        return fingir_sucesso()  # sem notificação; fica no painel para revisão

    entregue = entregar(m, base_publica(request))
    m.status = "entregue" if entregue else "falha"
    _salvar(m)
    if not entregue:
        return _pagina(request, ctx, form, "Não foi possível enviar agora. Tente novamente ou use o WhatsApp.", status_code=502)

    request.session["contato_enviado"] = True
    return RedirectResponse("/contato", status_code=303)


def _salvar(m: models.MensagemContato) -> None:
    try:
        with SessionLocal() as db:
            db.add(m)
            db.commit()
            db.refresh(m)
            db.expunge(m)
    except Exception as exc:  # noqa: BLE001 - o registro nunca impede a entrega
        logger.error("Falha ao registrar a mensagem do formulário: %s", exc)


def _texto_email(m: models.MensagemContato) -> str:
    return (
        f"Serviço: {m.servico}\nPrazo: {m.prazo or '-'}\n"
        f"Nome: {m.nome}\nE-mail: {m.email}\nTelefone: {m.telefone or '-'}\n\n"
        f"--- Mensagem ---\n{m.mensagem}\n\n"
        f"--- Detalhes do IP ---\n{m.detalhes_ip or m.ip}\n"
        f"Cabeçalhos de proxy: {m.proxies or '-'}\n"
    )


def texto_telegram(m: models.MensagemContato) -> str:
    """Notificação enxuta: o essencial do pedido e uma linha de origem (o e-mail traz os detalhes do IP)."""
    titulo = f"📩 Novo orçamento — {m.servico}" + (f" ({m.prazo})" if m.prazo else "")
    contato = [f"👤 {m.nome}", f"✉️ {m.email}"] + ([f"📞 {m.telefone}"] if m.telefone else [])
    local = ", ".join(x for x in (m.cidade, m.pais) if x)
    origem = " · ".join(x for x in (m.ip, local, m.org) if x)
    mensagem = m.mensagem if len(m.mensagem) <= 1500 else m.mensagem[:1500].rstrip() + "…"
    return f"{titulo}\n\n" + "\n".join(contato) + f"\n\n💬 {mensagem}\n\n🌐 {origem}"


def entregar(m: models.MensagemContato, site: str = "") -> bool:
    """Envia o pedido por e-mail (HTML + texto) e Telegram. True se ao menos um canal entregou."""
    assunto = f"[Orçamento] {m.servico} - {m.nome}"
    entregue = False
    if mailer.smtp_configurado():
        try:
            try:
                html = email_orcamento.montar(assunto, m.nome, m.email, m.telefone or "", m.servico, m.prazo or "",
                                              m.mensagem, m.detalhes_ip or m.ip, m.proxies or "-",
                                              cfg.SITE_URL or site or "https://henrique.tec.br/")
            except Exception as exc:  # noqa: BLE001 - sem o HTML, o pedido ainda chega em texto puro
                logger.error("Falha ao montar o e-mail HTML do orçamento: %s", exc)
                html = None
            mailer.enviar_email(assunto, _texto_email(m), reply_to=m.email, reply_to_nome=m.nome, html=html)
            entregue = True
        except Exception as exc:
            logger.error("Falha ao enviar e-mail do orçamento: %s", exc)
    if notify.telegram_configurado():
        try:
            notify.enviar_telegram(texto_telegram(m))
            entregue = True
        except Exception as exc:
            logger.error("Falha ao notificar no Telegram: %s", type(exc).__name__)
    return entregue
