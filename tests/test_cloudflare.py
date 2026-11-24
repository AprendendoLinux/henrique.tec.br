import database
import models
import monitor
import cloudflare
from appsettings import store
from tests.conftest import login_admin, post

DASH = "/admin/dashboard"
TOKEN = "cfToken_" + "A" * 32

EVENTOS = [
    {"datetime": "2026-11-24T10:00:00Z", "action": "block", "source": "firewallManaged", "ruleId": "abc123def4567890",
     "clientIP": "185.220.101.9", "clientCountryName": "DE", "clientRequestHTTPMethodName": "GET",
     "clientRequestPath": "/wp-admin/setup-config.php", "clientRequestQuery": "?step=1", "userAgent": "Mozilla/5.0"},
    {"datetime": "2026-11-24T10:05:00Z", "action": "managed_challenge", "source": "bic", "ruleId": "",
     "clientIP": "45.9.9.9", "clientCountryName": "NL", "clientRequestHTTPMethodName": "POST",
     "clientRequestPath": "/contato", "clientRequestQuery": "", "userAgent": ""},
]


class FakeAPI:
    def __init__(self):
        self.chamadas = []

    def __call__(self, caminho, dados=None):
        self.chamadas.append((caminho, dados))
        if caminho.startswith("/zones?name="):
            return {"result": [{"id": "z" * 32}]}
        q = dados["query"]
        if "firewallEventsAdaptive" in q:
            desde = dados["variables"]["d"]
            ev = [e for e in EVENTOS if e["datetime"] > desde]
            return {"data": {"viewer": {"zones": [{"firewallEventsAdaptive": ev}]}}}
        if "httpRequests1dGroups" in q:
            return {"data": {"viewer": {"zones": [{"httpRequests1dGroups": [
                {"dimensions": {"date": "2026-11-24"}, "sum": {"requests": 10299, "threats": 50, "pageViews": 1960,
                                                                "cachedRequests": 1030}, "uniq": {"uniques": 916}}]}]}}}
        raise AssertionError(q)


def _configurar(monkeypatch):
    for k, v in {"cf_token": TOKEN, "cf_zone_id": "", "cf_ultimo_evento": "2026-11-24T09:00:00Z",
                 "cf_ultima_sync": "", "site_url": "https://henrique.tec.br"}.items():
        monkeypatch.setitem(store._v, k, v)
    salvos = {}
    monkeypatch.setattr(store, "save", lambda db, mapa: (salvos.update(mapa), store._v.update(mapa)))
    api = FakeAPI()
    monkeypatch.setattr(cloudflare, "_req", api)
    monkeypatch.setattr(cloudflare, "_resumo_cache", None)
    return api, salvos


def test_sincroniza_bloqueios_como_eventos(client, monkeypatch):  # client inicializa o app (tabelas)
    api, salvos = _configurar(monkeypatch)
    assert cloudflare.sincronizar() == 2
    consulta = [d for c, d in api.chamadas if c == "/graphql"][0]
    assert consulta["variables"]["h"] == ["henrique.tec.br", "www.henrique.tec.br"]
    assert "allow" in consulta["variables"]["a"] and "skip" in consulta["variables"]["a"]
    assert salvos["cf_ultimo_evento"] == "2026-11-24T10:05:00Z" and salvos["cf_zone_id"] == "z" * 32
    while monitor.processar_fila():
        pass
    db = database.SessionLocal()
    try:
        ev = db.query(models.EventoSeguranca).filter_by(tipo="cloudflare_bloqueio", ip="185.220.101.9").one()
    finally:
        db.close()
    assert ev.caminho == "/wp-admin/setup-config.php?step=1" and ev.ts.isoformat() == "2026-11-24T10:00:00"
    assert ev.detalhe.startswith("block · firewallManaged · regra abc123def456")
    assert cloudflare.sincronizar() == 0  # incremental: nada novo desde o último evento


def test_resumo_e_teste_de_conexao(monkeypatch):
    _configurar(monkeypatch)
    assert "Hoje: 10299 requisições, 50 ameaças" in cloudflare.testar()
    assert cloudflare.resumo_diario()[0]["visitantes"] == 916


def test_sem_token_nao_faz_nada(monkeypatch):
    monkeypatch.setitem(store._v, "cf_token", "")
    assert cloudflare.sincronizar() == 0


def test_admin_salva_token_criptografado_e_painel_mostra_resumo(client, monkeypatch):
    for k in ("cf_token", "cf_zone_id", "cf_ultimo_evento", "cf_ultima_sync"):
        monkeypatch.setitem(store._v, k, store.get(k))
    monkeypatch.setattr(cloudflare, "_req", FakeAPI())
    monkeypatch.setattr(cloudflare, "_resumo_cache", None)
    login_admin(client)
    r = post(client, "/admin/config/cloudflare", {"cf_token": TOKEN}, page=DASH)
    assert r.status_code == 302
    db = database.SessionLocal()
    try:
        row = db.get(models.Setting, "cf_token")
        assert row.is_secret and TOKEN not in row.value
    finally:
        db.close()
    html = client.get("/admin/seguranca").text
    assert "Cloudflare — últimos 7 dias" in html and "10299" in html
    assert post(client, "/admin/config/cloudflare", {"cf_token": "x y"}, page=DASH).status_code == 400
    post(client, "/admin/config/cloudflare", {"remover": "1"}, page=DASH)
    assert store.get("cf_token") == ""
