from types import SimpleNamespace

import ipinfo
import mailer
from security import client_ip


def req(peer, **headers):
    return SimpleNamespace(client=SimpleNamespace(host=peer), headers={k.replace("_", "-"): v for k, v in headers.items()})


def test_ip_direto_publico_ignora_cabecalhos_forjados():
    assert client_ip(req("200.10.20.30", x_forwarded_for="1.2.3.4", cf_connecting_ip="5.6.7.8")) == "200.10.20.30"


def test_proxy_confiavel_usa_cloudflare_ipv4():
    assert client_ip(req("172.18.0.1", cf_connecting_ip="189.1.2.3")) == "189.1.2.3"


def test_proxy_confiavel_usa_ipv6():
    assert client_ip(req("10.0.0.5", cf_connecting_ip="2804:14d:1234::1")) == "2804:14d:1234::1"


def test_xff_pega_primeiro_publico_da_direita():
    r = req("172.18.0.1", x_forwarded_for="9.9.9.9, 189.1.2.3, 10.0.0.7")
    assert client_ip(r) == "189.1.2.3"


def test_xff_com_ipv4_mapeado_e_porta():
    assert client_ip(req("127.0.0.1", x_forwarded_for="::ffff:189.1.2.3")) == "189.1.2.3"
    assert client_ip(req("127.0.0.1", x_forwarded_for="189.1.2.3:5555")) == "189.1.2.3"


def test_sem_ip_publico_retorna_peer():
    assert client_ip(req("172.18.0.1", x_forwarded_for="192.168.0.9")) == "172.18.0.1"


def test_detalhes_ip_nao_publico_nao_consulta():
    assert "NÃO é público" in ipinfo.detalhes_ip("172.18.0.1")
    assert "NÃO é público" in ipinfo.detalhes_ip("fd00::1")


def test_detalhes_ip_formata_campos(monkeypatch):
    monkeypatch.setattr(ipinfo, "_reverso", lambda ip: {"ptr": "host.exemplo.net", "confirmado": True})
    monkeypatch.setattr(ipinfo, "_ipwho", lambda ip: {
        "success": True, "city": "Rio de Janeiro", "region": "Rio de Janeiro", "region_code": "RJ",
        "country": "Brazil", "country_code": "BR", "continent": "South America", "postal": "20000",
        "latitude": -22.9, "longitude": -43.2, "calling_code": "55",
        "connection": {"asn": 64500, "org": "Org X", "isp": "Provedor X", "domain": "x.net"},
        "timezone": {"id": "America/Sao_Paulo", "abbr": "-03", "utc": "-03:00"}, "flag": {"emoji": "🇧🇷"},
    })
    monkeypatch.setattr(ipinfo, "_ipapi_is", lambda ip: {"is_vpn": False, "is_datacenter": True})
    monkeypatch.setattr(ipinfo, "_rdap", lambda ip: {
        "name": "NET-X", "handle": "NET-X-1", "country": "BR", "startAddress": "200.160.0.0",
        "endAddress": "200.160.0.255", "cidr0_cidrs": [{"v4prefix": "200.160.0.0", "length": 24}],
        "events": [{"eventAction": "registration", "eventDate": "2015-01-02T00:00:00Z"}],
        "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse X"], ["email", {}, "text", "abuse@x.net"]]]}],
    })
    ipinfo._cache.clear()
    txt = ipinfo.detalhes_ip("200.160.2.3")
    for esperado in ("IPv4", "host.exemplo.net", "Provedor X", "AS64500", "Rio de Janeiro", "-22.9, -43.2",
                     "200.160.0.0/24", "abuse@x.net", "datacenter/hospedagem: SIM", "abuseipdb.com/check/200.160.2.3"):
        assert esperado in txt, esperado


def test_reply_to_e_o_email_do_visitante():
    msg = mailer.montar_mensagem("[Orçamento] x", "corpo", reply_to="maria@exemplo.com", reply_to_nome="Maria Silva")
    assert msg["Reply-To"] == "Maria Silva <maria@exemplo.com>"
    assert "maria@exemplo.com" not in msg["From"]


def test_reply_to_nao_aceita_injecao_de_cabecalho():
    msg = mailer.montar_mensagem("a", "b", reply_to="x@y.com\r\nBcc: z@w.com", reply_to_nome="N\r\nBcc: q@q.com")
    assert "Bcc" not in msg
    assert "\n" not in str(msg["Reply-To"])
