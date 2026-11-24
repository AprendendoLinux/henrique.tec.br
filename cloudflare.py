"""Integração (somente leitura) com a API da Cloudflare para o painel de segurança.

- Eventos de firewall bloqueados/desafiados na borda (WAF, bots, verificação de navegador...), que nunca
  chegam ao servidor: buscados a cada 5 minutos e gravados como eventos `cloudflare_bloqueio`.
- Resumo diário da zona (requisições, ameaças, visitantes únicos), com cache de 10 minutos.
O token (permissões Zone:Read e Analytics:Read) fica criptografado nas configurações do painel.
"""
import json
import logging
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from appsettings import cfg, store
from database import SessionLocal

logger = logging.getLogger(__name__)

API = "https://api.cloudflare.com/client/v4"
INTERVALO = 300
ACOES_IGNORADAS = ["allow", "skip", "log", "bypass"]
_resumo_cache: tuple[float, list] | None = None
_lock = threading.Lock()


class CloudflareErro(Exception):
    pass


def configurado() -> bool:
    return bool(cfg.CF_TOKEN)


def _req(caminho: str, dados: dict | None = None) -> dict:
    req = urllib.request.Request(
        API + caminho, data=json.dumps(dados).encode() if dados is not None else None,
        method="POST" if dados is not None else "GET",
        headers={"Authorization": f"Bearer {cfg.CF_TOKEN}", "Content-Type": "application/json",
                 "User-Agent": "henrique.tec.br-painel/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            corpo = json.loads(r.read().decode())
    except urllib.error.HTTPError as exc:
        raise CloudflareErro(f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise CloudflareErro(type(exc).__name__) from exc
    if corpo.get("errors"):
        raise CloudflareErro(str(corpo["errors"][0].get("message", corpo["errors"][0]))[:200])
    return corpo


def _hosts() -> list[str]:
    host = cfg.SITE_URL.split("://", 1)[-1].split("/")[0]
    base = host[4:] if host.startswith("www.") else host
    return [base, "www." + base]


def zona_id() -> str:
    if cfg.CF_ZONE_ID:
        return cfg.CF_ZONE_ID
    zonas = _req(f"/zones?name={_hosts()[0]}").get("result") or []
    if not zonas:
        raise CloudflareErro("zona não encontrada para o token")
    db = SessionLocal()
    try:
        store.save(db, {"cf_zone_id": zonas[0]["id"]})
    finally:
        db.close()
    return zonas[0]["id"]


def _graphql(consulta: str, variaveis: dict) -> dict:
    corpo = _req("/graphql", {"query": consulta, "variables": variaveis})
    return corpo["data"]["viewer"]["zones"][0]


def eventos_desde(desde: datetime) -> list[dict]:
    q = """query($z:String!,$d:Time!,$h:[String!],$a:[String!]){viewer{zones(filter:{zoneTag:$z}){
      firewallEventsAdaptive(filter:{datetime_gt:$d,clientRequestHTTPHost_in:$h,action_notin:$a},
                             limit:1000,orderBy:[datetime_ASC]){
        datetime action source ruleId clientIP clientCountryName clientRequestHTTPMethodName
        clientRequestPath clientRequestQuery userAgent}}}}"""
    return _graphql(q, {"z": zona_id(), "d": desde.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "h": _hosts(), "a": ACOES_IGNORADAS})["firewallEventsAdaptive"]


def resumo_diario(dias: int = 7) -> list[dict]:
    """Totais diários da zona inteira (todos os subdomínios), em cache por 10 minutos."""
    global _resumo_cache
    if _resumo_cache and time.time() - _resumo_cache[0] < 600:
        return _resumo_cache[1]
    q = """query($z:String!,$d:Date!){viewer{zones(filter:{zoneTag:$z}){
      httpRequests1dGroups(filter:{date_geq:$d},limit:31,orderBy:[date_ASC]){
        dimensions{date} sum{requests threats pageViews cachedRequests} uniq{uniques}}}}}"""
    desde = (datetime.now(timezone.utc) - timedelta(days=dias - 1)).strftime("%Y-%m-%d")
    linhas = [{"data": g["dimensions"]["date"], "requisicoes": g["sum"]["requests"], "ameacas": g["sum"]["threats"],
               "paginas": g["sum"]["pageViews"], "cache": g["sum"]["cachedRequests"], "visitantes": g["uniq"]["uniques"]}
              for g in _graphql(q, {"z": zona_id(), "d": desde})["httpRequests1dGroups"]]
    _resumo_cache = (time.time(), linhas)
    return linhas


def sincronizar() -> int:
    """Grava como eventos de segurança os bloqueios da Cloudflare ocorridos desde a última sincronização."""
    import monitor  # import local: monitor não depende deste módulo
    if not configurado():
        return 0
    with _lock:
        try:
            desde = datetime.fromisoformat(store.get("cf_ultimo_evento").replace("Z", "+00:00"))
        except ValueError:
            desde = datetime.now(timezone.utc) - timedelta(hours=24)
        eventos = eventos_desde(desde)
        for e in eventos:
            ts = datetime.fromisoformat(e["datetime"].replace("Z", "+00:00"))
            caminho = (e["clientRequestPath"] or "/") + (e["clientRequestQuery"] or "")
            monitor.registrar_evento(
                e["clientIP"], "cloudflare_bloqueio", None, caminho[:300],
                f'{e["action"]} · {e["source"]}{(" · regra " + e["ruleId"][:12]) if e.get("ruleId") else ""}'
                f' · {e["clientRequestHTTPMethodName"]} · {(e["userAgent"] or "")[:80]}',
                ts=ts.astimezone(timezone.utc).replace(tzinfo=None))
            monitor.solicitar_geo(e["clientIP"])
        if eventos:
            db = SessionLocal()
            try:
                store.save(db, {"cf_ultimo_evento": eventos[-1]["datetime"],
                                "cf_ultima_sync": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                                + f" · {len(eventos)} evento(s)"})
            finally:
                db.close()
        return len(eventos)


def testar() -> str:
    global _resumo_cache
    _resumo_cache = None
    zid = zona_id()
    hoje = resumo_diario(1)
    total = hoje[-1] if hoje else {"requisicoes": 0, "ameacas": 0}
    return (f"Conectado à zona {_hosts()[0]} ({zid[:8]}…). Hoje: {total['requisicoes']} requisições, "
            f"{total['ameacas']} ameaças na zona.")


def iniciar() -> None:
    def laco():
        time.sleep(30)
        while True:
            try:
                if configurado():
                    n = sincronizar()
                    if n:
                        logger.info("Cloudflare: %s bloqueio(s) importado(s)", n)
            except Exception as exc:  # noqa: BLE001 - nunca derruba o site
                logger.warning("Cloudflare: falha ao sincronizar (%s)", exc)
            time.sleep(INTERVALO)
    threading.Thread(target=laco, name="cloudflare-sync", daemon=True).start()
