import json
from base64 import b64decode, b64encode

import itsdangerous
from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection

from appsettings import cfg
from security import proxy_confiavel, _parse_ip


def _https(scope) -> bool:
    if scope.get("scheme") in ("https", "wss"):
        return True
    cliente = scope.get("client")
    peer = _parse_ip(cliente[0]) if cliente else None
    if peer is None or not proxy_confiavel(peer):
        return False
    cab = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
    return cab.get("x-forwarded-proto", "").lower() == "https" or '"https"' in cab.get("cf-visitor", "")


class DynamicSessionMiddleware:
    """Sessão em cookie assinado, com a chave e a flag Secure lidas das configurações em tempo de execução."""

    def __init__(self, app, session_cookie: str = "session", max_age: int = 8 * 3600, same_site: str = "lax"):
        self.app, self.cookie, self.max_age, self.same_site = app, session_cookie, max_age, same_site

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        signer = itsdangerous.TimestampSigner(cfg.SECRET_KEY)
        conn = HTTPConnection(scope)
        vazia = True
        scope["session"] = {}
        if self.cookie in conn.cookies:
            try:
                dados = signer.unsign(conn.cookies[self.cookie].encode("utf-8"), max_age=self.max_age)
                scope["session"] = json.loads(b64decode(dados))
                vazia = False
            except (itsdangerous.BadSignature, ValueError):
                scope["session"] = {}

        flags = f"httponly; samesite={self.same_site}" + ("; secure" if cfg.COOKIE_SECURE or _https(scope) else "")

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                if scope["session"]:
                    dados = signer.sign(b64encode(json.dumps(scope["session"]).encode("utf-8")))
                    headers.append("Set-Cookie", f"{self.cookie}={dados.decode()}; path=/; Max-Age={self.max_age}; {flags}")
                elif not vazia:
                    headers.append("Set-Cookie", f"{self.cookie}=null; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; {flags}")
            await send(message)

        await self.app(scope, receive, send_wrapper)
