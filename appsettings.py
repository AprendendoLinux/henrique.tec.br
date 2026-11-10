import base64
import hashlib
import ipaddress
import os
import secrets
import threading
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

import models

DEFAULT_PROXIES = "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fc00::/7"
DEFAULT_HEADERS = "cf-connecting-ip,x-real-ip,x-forwarded-for"

DEFAULTS = {
    "secret_key": "",
    "cookie_secure": "false",
    "trusted_proxies": DEFAULT_PROXIES,
    "client_ip_headers": DEFAULT_HEADERS,
    "recaptcha_enabled": "false",
    "recaptcha_site_key": "",
    "recaptcha_secret": "",
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "smtp_host": "",
    "smtp_port": "587",
    "smtp_security": "starttls",
    "smtp_user": "",
    "smtp_password": "",
    "smtp_from": "",
    "smtp_from_name": "Site henrique.tec.br",
    "smtp_verify_tls": "true",
    "contact_to": "",
}
SECRETS = {"secret_key", "smtp_password", "telegram_bot_token", "recaptcha_secret"}

# Importação única de variáveis de ambiente antigas (somente para chaves ainda ausentes no banco).
LEGACY_ENV = {
    "secret_key": "SECRET_KEY", "cookie_secure": "COOKIE_SECURE", "trusted_proxies": "TRUSTED_PROXIES",
    "client_ip_headers": "CLIENT_IP_HEADERS", "recaptcha_enabled": "ENABLE_RECAPTCHA",
    "recaptcha_site_key": "RECAPTCHA_SITE_KEY", "recaptcha_secret": "RECAPTCHA_SECRET_KEY",
    "telegram_bot_token": "TELEGRAM_BOT_TOKEN", "telegram_chat_id": "TELEGRAM_CHAT_ID",
    "smtp_host": "SMTP_HOST", "smtp_port": "SMTP_PORT", "smtp_security": "SMTP_SECURITY",
    "smtp_user": "SMTP_USER", "smtp_password": "SMTP_PASSWORD", "smtp_from": "SMTP_FROM",
    "smtp_from_name": "SMTP_FROM_NAME", "smtp_verify_tls": "SMTP_VERIFY_TLS", "contact_to": "CONTACT_TO",
}


def _fernet() -> Fernet:
    mestre = os.getenv("DB_PASSWORD", "")
    if len(mestre) < 8:
        raise RuntimeError("DB_PASSWORD ausente ou curta: é usada para proteger os segredos salvos no banco.")
    digest = hashlib.sha256(("settings-v1|" + mestre).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _truthy(valor: str) -> bool:
    return str(valor).strip().lower() in ("1", "true", "yes", "on")


class Store:
    def __init__(self) -> None:
        self._v = dict(DEFAULTS)
        self._lock = threading.RLock()

    def load(self, db: Session) -> None:
        valores = dict(DEFAULTS)
        for row in db.query(models.Setting).all():
            valor = row.value or ""
            if row.is_secret and valor:
                try:
                    valor = _fernet().decrypt(valor.encode()).decode()
                except InvalidToken:
                    valor = ""
            valores[row.key] = valor
        with self._lock:
            self._v = valores

    def save(self, db: Session, mapa: dict) -> None:
        for chave, valor in mapa.items():
            if chave not in DEFAULTS:
                raise KeyError(chave)
            valor = "" if valor is None else str(valor)
            segredo = chave in SECRETS
            row = db.get(models.Setting, chave) or models.Setting(key=chave)
            row.is_secret = segredo
            row.value = _fernet().encrypt(valor.encode()).decode() if segredo and valor else valor
            db.add(row)
        db.commit()
        with self._lock:
            self._v.update({k: ("" if v is None else str(v)) for k, v in mapa.items()})

    def seed(self, db: Session) -> None:
        existentes = {r.key for r in db.query(models.Setting.key).all()}
        novos = {}
        for chave, env in LEGACY_ENV.items():
            if chave not in existentes and os.getenv(env) not in (None, ""):
                valor = os.getenv(env)
                novos[chave] = ("true" if _truthy(valor) else "false") if chave in BOOLEANS else valor
        if "secret_key" not in existentes and "secret_key" not in novos:
            novos["secret_key"] = secrets.token_urlsafe(48)
        if novos:
            self.save(db, novos)
        self.load(db)

    def get(self, chave: str) -> str:
        with self._lock:
            return self._v.get(chave, DEFAULTS.get(chave, ""))

    def flag(self, chave: str) -> bool:
        return _truthy(self.get(chave))


BOOLEANS = {"cookie_secure", "recaptcha_enabled", "smtp_verify_tls"}
store = Store()


@lru_cache(maxsize=16)
def _redes(csv: str):
    return tuple(ipaddress.ip_network(p.strip(), strict=False) for p in csv.split(",") if p.strip())


class Cfg:
    """Acesso somente leitura às configurações salvas no banco (com cache em memória)."""

    @property
    def SECRET_KEY(self): return store.get("secret_key")
    @property
    def COOKIE_SECURE(self): return store.flag("cookie_secure")
    @property
    def TRUSTED_PROXIES(self): return _redes(store.get("trusted_proxies") or DEFAULT_PROXIES)
    @property
    def CLIENT_IP_HEADERS(self):
        return [h.strip().lower() for h in (store.get("client_ip_headers") or DEFAULT_HEADERS).split(",") if h.strip()]
    @property
    def ENABLE_RECAPTCHA(self): return store.flag("recaptcha_enabled")
    @property
    def RECAPTCHA_SITE_KEY(self): return store.get("recaptcha_site_key")
    @property
    def RECAPTCHA_SECRET_KEY(self): return store.get("recaptcha_secret")
    @property
    def TELEGRAM_BOT_TOKEN(self): return store.get("telegram_bot_token")
    @property
    def TELEGRAM_CHAT_ID(self): return store.get("telegram_chat_id")
    @property
    def SMTP_HOST(self): return store.get("smtp_host")
    @property
    def SMTP_PORT(self):
        try:
            return int(store.get("smtp_port") or 587)
        except ValueError:
            return 587
    @property
    def SMTP_SECURITY(self): return store.get("smtp_security")
    @property
    def SMTP_USER(self): return store.get("smtp_user")
    @property
    def SMTP_PASSWORD(self): return store.get("smtp_password")
    @property
    def SMTP_FROM(self): return store.get("smtp_from")
    @property
    def SMTP_FROM_NAME(self): return store.get("smtp_from_name")
    @property
    def SMTP_VERIFY_TLS(self): return store.flag("smtp_verify_tls")
    @property
    def SMTP_TIMEOUT(self): return 15
    @property
    def CONTACT_TO(self): return store.get("contact_to") or store.get("smtp_from")


cfg = Cfg()
