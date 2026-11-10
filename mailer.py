import logging
import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr

from appsettings import cfg

logger = logging.getLogger(__name__)
_CTRL = re.compile(r"[\r\n\x00-\x1f\x7f]+")


def limpar_cabecalho(valor: str, limite: int = 120) -> str:
    return _CTRL.sub(" ", valor).strip()[:limite]


def smtp_security() -> str:
    if cfg.SMTP_SECURITY in ("ssl", "starttls", "none"):
        return cfg.SMTP_SECURITY
    return {465: "ssl", 25: "none"}.get(cfg.SMTP_PORT, "starttls")


def smtp_configurado() -> bool:
    return bool(cfg.SMTP_HOST and cfg.SMTP_FROM and cfg.CONTACT_TO)


def montar_mensagem(assunto: str, corpo: str, reply_to: str | None = None,
                    reply_to_nome: str | None = None) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = formataddr((limpar_cabecalho(cfg.SMTP_FROM_NAME, 60), cfg.SMTP_FROM))
    msg["To"] = cfg.CONTACT_TO
    msg["Subject"] = limpar_cabecalho(assunto, 200)
    if reply_to:
        msg["Reply-To"] = formataddr((limpar_cabecalho(reply_to_nome or "", 80), limpar_cabecalho(reply_to, 254)))
    msg.set_content(corpo)
    return msg


def enviar_email(assunto: str, corpo: str, reply_to: str | None = None,
                 reply_to_nome: str | None = None) -> None:
    msg = montar_mensagem(assunto, corpo, reply_to, reply_to_nome)

    contexto = ssl.create_default_context()
    if not cfg.SMTP_VERIFY_TLS:
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE

    modo = smtp_security()
    if modo == "ssl":
        servidor = smtplib.SMTP_SSL(
            cfg.SMTP_HOST, cfg.SMTP_PORT, timeout=cfg.SMTP_TIMEOUT, context=contexto
        )
    else:
        servidor = smtplib.SMTP(cfg.SMTP_HOST, cfg.SMTP_PORT, timeout=cfg.SMTP_TIMEOUT)

    with servidor:
        servidor.ehlo()
        if modo == "starttls":
            servidor.starttls(context=contexto)
            servidor.ehlo()
        if cfg.SMTP_USER:
            servidor.login(cfg.SMTP_USER, cfg.SMTP_PASSWORD)
        servidor.send_message(msg)
    logger.info("E-mail de contato enviado (%s:%s, modo=%s).", cfg.SMTP_HOST, cfg.SMTP_PORT, modo)
