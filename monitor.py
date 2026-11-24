"""Monitoramento de acessos e eventos de segurança (painel /admin/seguranca).

- Cada requisição vira uma linha em `acessos` (exceto arquivos estáticos e a busca da Base de Conhecimento).
- Eventos de segurança (login falho, 2FA, CSRF, varreduras...) vão para `eventos_seguranca`.
- A gravação é assíncrona: as requisições só enfileiram; uma thread grava em lote, sem atrasar o site.
- Geolocalização por IP com cache em `ip_geo`: usa os cabeçalhos de localização da Cloudflare quando
  existem (cf-ipcity, cf-iplatitude...) e, na falta deles, consulta ipwho.is uma única vez por IP.
"""
import ipaddress
import logging
import queue
import re
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

import ipinfo
import models
from database import SessionLocal, engine

logger = logging.getLogger(__name__)

RETENCAO_DIAS = 90
GEO_VALIDADE = timedelta(days=30)
GEO_INTERVALO = 1.5  # segundos entre consultas externas de geolocalização (respeita o serviço gratuito)
LOTE_MAX = 500

# Robôs conhecidos: (nome exibido, categoria, regex no User-Agent)
ROBOS = [
    ("Googlebot", "buscador", r"googlebot|google-inspectiontool|googleother|storebot-google|adsbot-google"),
    ("Bingbot", "buscador", r"bingbot|bingpreview|msnbot|adidxbot"),
    ("Applebot", "buscador", r"applebot"),
    ("DuckDuckBot", "buscador", r"duckduckbot|duckassistbot"),
    ("YandexBot", "buscador", r"yandex(bot|images|mobilebot)?"),
    ("Baiduspider", "buscador", r"baiduspider"),
    ("Yahoo Slurp", "buscador", r"slurp"),
    ("Qwant", "buscador", r"qwantify|qwantbot"),
    ("Seznam", "buscador", r"seznambot"),
    ("Facebook", "social", r"facebookexternalhit|facebookcatalog|meta-externalagent"),
    ("WhatsApp", "social", r"whatsapp"),
    ("Telegram", "social", r"telegrambot"),
    ("Twitter/X", "social", r"twitterbot"),
    ("LinkedIn", "social", r"linkedinbot"),
    ("Slack", "social", r"slackbot|slack-imgproxy"),
    ("Discord", "social", r"discordbot"),
    ("Pinterest", "social", r"pinterest"),
    ("GPTBot", "ia", r"gptbot|chatgpt-user|oai-searchbot"),
    ("ClaudeBot", "ia", r"claudebot|claude-user|claude-searchbot|anthropic-ai"),
    ("PerplexityBot", "ia", r"perplexitybot|perplexity-user"),
    ("CCBot", "ia", r"ccbot"),
    ("Bytespider", "ia", r"bytespider"),
    ("Google-Extended", "ia", r"google-extended"),
    ("AhrefsBot", "seo", r"ahrefsbot|ahrefssiteaudit"),
    ("SemrushBot", "seo", r"semrushbot"),
    ("MJ12bot", "seo", r"mj12bot"),
    ("DotBot", "seo", r"dotbot"),
    ("PetalBot", "seo", r"petalbot"),
    ("DataForSeoBot", "seo", r"dataforseobot"),
    ("UptimeRobot", "monitor", r"uptimerobot"),
    ("Scanner", "ferramenta", r"zgrab|masscan|nmap|nikto|sqlmap|nuclei|wpscan|dirbuster|gobuster|ffuf|censys|"
                              r"expanse|internet-measurement|paloalto|shodan|l9explore|leakix"),
    ("Script", "ferramenta", r"^curl/|^wget/|python-requests|python-urllib|aiohttp|go-http-client|okhttp|"
                             r"java/|libwww-perl|^axios/|node-fetch|^$"),
]
_ROBOS_RE = [(nome, cat, re.compile(rx, re.I)) for nome, cat, rx in ROBOS]
CATEGORIA = {nome: cat for nome, cat, _ in ROBOS}

# Domínios oficiais para confirmar (DNS reverso + direto) que o robô é legítimo
DOMINIOS_ROBO = {
    "Googlebot": (".googlebot.com", ".google.com", ".googleusercontent.com"),
    "Bingbot": (".search.msn.com",),
    "Applebot": (".applebot.apple.com",),
    "YandexBot": (".yandex.ru", ".yandex.net", ".yandex.com"),
    "Baiduspider": (".baidu.com", ".baidu.jp"),
    "DuckDuckBot": (".duckduckgo.com",),
}

# Caminhos típicos de varredura de vulnerabilidades (o site não tem nada disso)
VARREDURA_RE = re.compile(
    r"(^/(wp-|wordpress|xmlrpc\.php|wp/)|\.php\d?(\?|$|/)|/\.(env|git|svn|hg|aws|ssh|docker|vscode|idea|DS_Store)"
    r"|phpmyadmin|pma/|myadmin|adminer|/cgi-bin|/boaform|/hnap1|/actuator|/server-status|/manager/html"
    r"|/vendor/|/config\.(json|yml|yaml|js)|/\.well-known/security\.txt\.php|\.(bak|old|sql|swp|tar|tgz|zip|rar|7z|log)$"
    r"|/etc/passwd|\.\./|%2e%2e|/shell|/console|/solr/|/jenkins|/owa/|/autodiscover|/ecp/|/druid|/telescope"
    r"|/geoserver|/remote/login|/global-protect|/sslvpn|/api/v1/pods|/_ignition|/debug/|/backup|/db\.|/dump)",
    re.I,
)

# Rotas que não entram no registro de acessos (ruído)
IGNORAR_RE = re.compile(r"^/(static/|favicon\.ico$|conhecimento/busca$)")


def identificar_robo(user_agent: str | None) -> str | None:
    ua = (user_agent or "").strip()
    for nome, _cat, rx in _ROBOS_RE:
        if rx.search(ua):
            return nome
    return None


def eh_varredura(caminho: str) -> bool:
    return bool(VARREDURA_RE.search(caminho or ""))


def _agora() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _ip_publico(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# ---------------------------------------------------------------- fila e gravação
_fila: "queue.Queue[tuple[str, dict]]" = queue.Queue(maxsize=20000)
_geo_fila: "queue.Queue[tuple[str, bool]]" = queue.Queue(maxsize=5000)  # (ip, só completar org/rdns)
_geo_conhecidos: set[str] = set()   # IPs já com geolocalização (ou já enfileirados) nesta execução
_geo_lock = threading.Lock()
_ativo = False
_ultima_limpeza = 0.0


def _enfileirar(tipo: str, dados: dict) -> None:
    try:
        _fila.put_nowait((tipo, dados))
    except queue.Full:
        logger.warning("Monitor: fila cheia, registro descartado")


def registrar_acesso(ip: str, metodo: str, caminho: str, status: int, ms: int, user_agent: str | None,
                     referer: str | None, cf_geo: dict | None = None) -> None:
    if IGNORAR_RE.search(caminho):
        return
    robo = identificar_robo(user_agent)
    suspeito = eh_varredura(caminho)
    _enfileirar("acesso", {
        "ts": _agora(), "ip": ip[:45], "metodo": metodo[:8], "caminho": caminho[:300], "status": status,
        "ms": ms, "user_agent": (user_agent or "")[:300] or None, "referer": (referer or "")[:300] or None,
        "robo": robo, "suspeito": suspeito,
    })
    if suspeito:
        _enfileirar("evento", {"ts": _agora(), "ip": ip[:45], "tipo": "varredura", "usuario": None,
                               "caminho": caminho[:300], "detalhe": f"{metodo} → {status}"})
    _geo_solicitar(ip, cf_geo)


def registrar_evento(ip: str, tipo: str, usuario: str | None = None, caminho: str | None = None,
                     detalhe: str | None = None) -> None:
    _enfileirar("evento", {"ts": _agora(), "ip": ip[:45], "tipo": tipo[:30], "usuario": (usuario or None) and usuario[:50],
                           "caminho": (caminho or None) and caminho[:300], "detalhe": (detalhe or None) and detalhe[:300]})


def processar_fila() -> int:
    """Grava em lote o que estiver na fila. Chamada pela thread de fundo (e diretamente nos testes)."""
    acessos, eventos, geos = [], [], {}
    while len(acessos) + len(eventos) + len(geos) < LOTE_MAX:
        try:
            tipo, dados = _fila.get_nowait()
        except queue.Empty:
            break
        if tipo == "acesso":
            acessos.append(dados)
        elif tipo == "evento":
            eventos.append(dados)
        elif tipo == "geo":
            geos[dados["ip"]] = dados
    if not (acessos or eventos or geos):
        return 0
    db = SessionLocal()
    try:
        if acessos:
            db.bulk_insert_mappings(models.Acesso, acessos)
        if eventos:
            db.bulk_insert_mappings(models.EventoSeguranca, eventos)
        for ip, dados in geos.items():
            atual = db.get(models.IpGeo, ip)
            if atual is None:
                db.add(models.IpGeo(**dados))
            else:
                for k, v in dados.items():
                    if v is not None:
                        setattr(atual, k, v)
        db.commit()
    except Exception as exc:  # noqa: BLE001 - monitoramento nunca derruba o site
        db.rollback()
        logger.error("Monitor: falha ao gravar lote (%s)", exc)
    finally:
        db.close()
    return len(acessos) + len(eventos) + len(geos)


def limpar_antigos(db=None) -> None:
    proprio = db is None
    db = db or SessionLocal()
    try:
        limite = _agora() - timedelta(days=RETENCAO_DIAS)
        db.execute(delete(models.Acesso).where(models.Acesso.ts < limite))
        db.execute(delete(models.EventoSeguranca).where(models.EventoSeguranca.ts < limite))
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.error("Monitor: falha na limpeza (%s)", exc)
    finally:
        if proprio:
            db.close()


def _laco_gravacao() -> None:
    global _ultima_limpeza
    while True:
        try:
            if not processar_fila():
                time.sleep(2)
            if time.time() - _ultima_limpeza > 86400:
                _ultima_limpeza = time.time()
                limpar_antigos()
        except Exception as exc:  # noqa: BLE001
            logger.error("Monitor: erro na thread de gravação (%s)", exc)
            time.sleep(5)


# ---------------------------------------------------------------- geolocalização
def geo_dos_cabecalhos(headers) -> dict | None:
    """Localização enviada pela Cloudflare (Managed Transform 'Add visitor location headers')."""
    pais = (headers.get("cf-ipcountry") or "").upper()
    if not pais or pais in ("XX", "T1"):
        pais = None
    try:
        lat = float(headers.get("cf-iplatitude")) if headers.get("cf-iplatitude") else None
        lon = float(headers.get("cf-iplongitude")) if headers.get("cf-iplongitude") else None
    except ValueError:
        lat = lon = None
    if not pais and lat is None:
        return None

    def texto(nome):  # a Cloudflare envia UTF-8; o servidor lê cabeçalhos como latin-1
        valor = headers.get(nome) or ""
        try:
            valor = valor.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
        return valor[:80] or None

    return {"pais": pais, "cidade": texto("cf-ipcity"), "regiao": texto("cf-region"), "lat": lat, "lon": lon}


def _geo_solicitar(ip: str, cf_geo: dict | None) -> None:
    if not _ip_publico(ip):
        return
    with _geo_lock:
        if ip in _geo_conhecidos:
            return
        _geo_conhecidos.add(ip)
    da_cloudflare = bool(cf_geo and cf_geo.get("lat") is not None)
    if da_cloudflare:
        _enfileirar("geo", {"ip": ip, **cf_geo, "fonte": "cloudflare", "atualizado": _agora()})
    if _ativo:
        try:
            _geo_fila.put_nowait((ip, da_cloudflare))
        except queue.Full:
            pass


def _consultar_geo(ip: str) -> dict:
    dados = {"ip": ip, "atualizado": _agora(), "fonte": "ipwho.is"}
    try:
        d = ipinfo._ipwho(ip)
        con = d.get("connection") or {}
        dados.update({"pais": (d.get("country_code") or "")[:2] or None, "pais_nome": d.get("country"),
                      "regiao": d.get("region"), "cidade": d.get("city"), "lat": d.get("latitude"),
                      "lon": d.get("longitude"), "org": (con.get("org") or con.get("isp") or "")[:120] or None})
    except Exception as exc:  # noqa: BLE001
        logger.info("Monitor: geolocalização indisponível para %s (%s)", ip, exc)
        dados["fonte"] = "falha"
    try:
        fut = ipinfo._pool.submit(ipinfo._reverso, ip)
        rev = fut.result(timeout=4)
        dados["rdns"] = (rev["ptr"] if rev["confirmado"] else "~" + rev["ptr"])[:255]
    except Exception:  # noqa: BLE001 - sem DNS reverso
        pass
    return dados


def _laco_geo() -> None:
    while True:
        ip, so_completar = _geo_fila.get()
        try:
            db = SessionLocal()
            try:
                atual = db.get(models.IpGeo, ip)
                fresco = (atual is not None and atual.fonte != "falha" and atual.org is not None
                          and atual.atualizado > _agora() - GEO_VALIDADE)
                so_completar = so_completar or (atual is not None and atual.fonte == "cloudflare")
            finally:
                db.close()
            if fresco:
                continue
            dados = _consultar_geo(ip)
            if so_completar:  # a Cloudflare já deu a localização: só completa provedor, nome do país e DNS reverso
                dados = {k: v for k, v in dados.items() if k in ("ip", "org", "rdns", "pais_nome")}
            _enfileirar("geo", dados)
            time.sleep(GEO_INTERVALO)
        except Exception as exc:  # noqa: BLE001
            logger.error("Monitor: erro na geolocalização (%s)", exc)


def robo_confirmado(robo: str | None, rdns: str | None) -> bool | None:
    """True/False quando dá para verificar (DNS reverso confirmado no domínio oficial); None se não se aplica."""
    if robo not in DOMINIOS_ROBO:
        return None
    if not rdns or rdns.startswith("~"):
        return False
    return rdns.lower().rstrip(".").endswith(DOMINIOS_ROBO[robo])


def iniciar() -> None:
    """Sobe as threads de gravação e geolocalização (não usadas com SQLite, que roda os testes)."""
    global _ativo
    if _ativo or engine.dialect.name == "sqlite":
        return
    _ativo = True
    threading.Thread(target=_laco_gravacao, name="monitor-gravacao", daemon=True).start()
    threading.Thread(target=_laco_geo, name="monitor-geo", daemon=True).start()
