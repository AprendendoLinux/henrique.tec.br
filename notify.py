import json
import logging
import urllib.request

from appsettings import cfg

logger = logging.getLogger(__name__)


def telegram_configurado() -> bool:
    return bool(cfg.TELEGRAM_BOT_TOKEN and cfg.TELEGRAM_CHAT_ID)


def enviar_telegram(texto: str) -> None:
    corpo = json.dumps({
        "chat_id": cfg.TELEGRAM_CHAT_ID,
        "text": texto[:4000],
        "disable_web_page_preview": True,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{cfg.TELEGRAM_BOT_TOKEN}/sendMessage",
        data=corpo, headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        if not json.loads(resp.read().decode()).get("ok"):
            raise RuntimeError("Telegram recusou a mensagem.")
    logger.info("Notificação enviada ao Telegram.")
