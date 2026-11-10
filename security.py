import base64
import hashlib
import hmac
import ipaddress
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, Request
from itsdangerous import BadSignature, URLSafeTimedSerializer
from markupsafe import Markup, escape

import config
from appsettings import cfg

ICONES = {
    "fa-brands fa-facebook", "fa-brands fa-instagram", "fa-brands fa-linkedin",
    "fa-brands fa-telegram", "fa-brands fa-whatsapp", "fa-brands fa-x-twitter",
    "fa-brands fa-youtube", "fa-solid fa-envelope", "fa-solid fa-globe",
}
CORES_ICONE = {
    "text-[#00ffcc]", "text-blue-500", "text-gray-400", "text-green-500",
    "text-red-500", "text-white",
}
CORES_HOVER = {
    "hover:border-[#00ffcc] hover:text-[#00ffcc]", "hover:border-blue-400 hover:text-blue-400",
    "hover:border-blue-600 hover:text-blue-600", "hover:border-green-500 hover:text-green-500",
    "hover:border-pink-500 hover:text-pink-500", "hover:border-red-600 hover:text-red-600",
    "hover:border-white hover:text-white",
}
TELEGRAM_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{4,31}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")
EMAIL_RE = re.compile(r"^[^@\s<>\"',;:]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,}$")
_BASE32_RE = re.compile(r"^[A-Z2-7]{16,64}$")


# --- Senhas ---
def _pw_bytes(plain: str) -> bytes:
    return plain.encode("utf-8")[:72]


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(_pw_bytes(password), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_pw_bytes(plain), hashed.encode("utf-8"))
    except (ValueError, AttributeError):
        return False


_DUMMY_HASH = get_password_hash("dummy-password-for-timing")


def verify_dummy(plain: str) -> None:
    verify_password(plain, _DUMMY_HASH)


def validar_senha_forte(senha: str) -> bool:
    return (
        len(senha) >= 8
        and any(c.isupper() for c in senha)
        and any(c.isdigit() for c in senha)
        and any(not c.isalnum() for c in senha)
    )


def user_fingerprint(user, with_totp: bool = False) -> str:
    base = user.password_hash + (user.totp_secret or "" if with_totp else "")
    return hashlib.sha256(base.encode()).hexdigest()[:20]


# --- Segredo TOTP criptografado ---
def _fernet() -> Fernet:
    digest = hashlib.sha256(("totp-v1|" + cfg.SECRET_KEY).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def is_encrypted(value: str) -> bool:
    return value.startswith("gAAAA")


def decrypt_secret(value: str | None) -> str | None:
    if not value:
        return None
    if not is_encrypted(value):
        return value if _BASE32_RE.match(value) else None
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken:
        return None


# --- Dispositivo confiável (cookie assinado) ---
def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(cfg.SECRET_KEY, salt="trusted-device")


def make_trusted_token(user) -> str:
    return _serializer().dumps({"u": user.id, "f": user_fingerprint(user, True)})


def trusted_token_valid(token: str | None, user) -> bool:
    if not token or not user.is_2fa_enabled:
        return False
    try:
        data = _serializer().loads(token, max_age=config.TRUSTED_DEVICE_DAYS * 86400)
    except BadSignature:
        return False
    return data.get("u") == user.id and hmac.compare_digest(
        str(data.get("f")), user_fingerprint(user, True)
    )


# --- CSRF ---
def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def csrf_input(request: Request) -> Markup:
    return Markup(f'<input type="hidden" name="csrf_token" value="{escape(csrf_token(request))}">')


async def csrf_protect(request: Request) -> None:
    expected = request.session.get("csrf", "")
    form = await request.form()
    sent = form.get("csrf_token") or request.headers.get("x-csrf-token") or ""
    if not expected or not hmac.compare_digest(str(sent), expected):
        raise HTTPException(status_code=403, detail="Token CSRF inválido ou ausente.")


# --- Rate limit em memória ---
class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _purge(self, key: str, window: int, now: float) -> deque:
        dq = self._hits[key]
        while dq and now - dq[0] > window:
            dq.popleft()
        return dq

    def blocked(self, key: str, limit: int, window: int) -> bool:
        with self._lock:
            now = time.monotonic()
            dq = self._purge(key, window, now)
            blocked = len(dq) >= limit
            if not dq:
                self._hits.pop(key, None)
            return blocked

    def hit(self, key: str, window: int) -> None:
        with self._lock:
            now = time.monotonic()
            self._purge(key, window, now).append(now)
            if len(self._hits) > 10000:
                for k in [k for k, v in self._hits.items() if not v or now - v[-1] > window]:
                    self._hits.pop(k, None)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


login_limiter = RateLimiter()
contact_limiter = RateLimiter()


def _parse_ip(valor: str | None):
    valor = (valor or "").strip()
    if valor.startswith("["):
        valor = valor[1:].split("]")[0]
    elif valor.count(":") == 1:
        valor = valor.split(":")[0]
    try:
        ip = ipaddress.ip_address(valor)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def proxy_confiavel(ip) -> bool:
    return any(ip in rede for rede in cfg.TRUSTED_PROXIES)


def client_ip(request: Request) -> str:
    """IP público do visitante (IPv4/IPv6). Cabeçalhos de proxy só valem se o par TCP for confiável."""
    host = request.client.host if request.client else ""
    peer = _parse_ip(host)
    if peer is None:
        return host or "unknown"
    if not proxy_confiavel(peer):
        return str(peer)

    for cabecalho in cfg.CLIENT_IP_HEADERS:
        valor = request.headers.get(cabecalho)
        if not valor:
            continue
        candidatos = reversed(valor.split(",")) if cabecalho == "x-forwarded-for" else [valor]
        for item in candidatos:
            ip = _parse_ip(item)
            if ip is None or proxy_confiavel(ip):
                continue
            if ip.is_global:
                return str(ip)
    return str(peer)


def cadeia_proxies(request: Request) -> str:
    partes = [f"{h}: {request.headers[h]}" for h in ("cf-connecting-ip", "x-real-ip", "x-forwarded-for") if request.headers.get(h)]
    return " | ".join(partes)[:500] or "-"


# --- Validação de entrada ---
def normalizar_url(valor: str | None, esquemas: tuple = ("http", "https")) -> str | None:
    valor = (valor or "").strip()
    if not valor:
        return None
    parsed = urlparse(valor)
    if len(valor) > 255 or parsed.scheme not in esquemas:
        raise HTTPException(status_code=400, detail="URL inválida.")
    if parsed.scheme in ("mailto", "tel"):
        if not parsed.path:
            raise HTTPException(status_code=400, detail="URL inválida.")
        return valor
    if not parsed.netloc:
        raise HTTPException(status_code=400, detail="URL inválida (use http:// ou https://).")
    return valor


def validar_opcao(valor: str | None, permitidos: set[str], padrao: str | None = None) -> str:
    valor = (valor or "").strip()
    if not valor and padrao is not None:
        return padrao
    if valor not in permitidos:
        raise HTTPException(status_code=400, detail="Valor não permitido.")
    return valor
