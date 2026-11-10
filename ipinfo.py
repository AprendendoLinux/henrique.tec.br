import ipaddress
import json
import logging
import socket
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait

logger = logging.getLogger(__name__)

TIMEOUT_GLOBAL = 7
TIMEOUT_HTTP = 5
TIMEOUT_DNS = 3
CACHE_TTL = 3600
_cache: dict[str, tuple[float, str]] = {}
_pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="ipinfo")


def _get_json(url: str, accept: str = "application/json") -> dict:
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "henrique.tec.br-contato/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT_HTTP) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _reverso(ip: str) -> dict:
    nome = socket.gethostbyaddr(ip)[0]
    confirmado = False
    try:
        confirmado = any(
            ipaddress.ip_address(i[4][0]) == ipaddress.ip_address(ip) for i in socket.getaddrinfo(nome, None)
        )
    except OSError:
        pass
    return {"ptr": nome, "confirmado": confirmado}


def _ipwho(ip: str) -> dict:
    d = _get_json(f"https://ipwho.is/{ip}")
    if not d.get("success"):
        raise RuntimeError(d.get("message", "ipwho.is sem dados"))
    return d


def _ipapi_is(ip: str) -> dict:
    return _get_json(f"https://api.ipapi.is/?q={ip}")


def _rdap(ip: str) -> dict:
    return _get_json(f"https://rdap.org/ip/{ip}", "application/rdap+json, application/json")


def _vcard(entity: dict) -> tuple[str, str]:
    nome = email = ""
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item[0] == "fn" and not nome:
            nome = str(item[3])
        elif item[0] == "email" and not email:
            email = str(item[3])
    return nome, email


def _entidades(rdap: dict, papel: str) -> list[str]:
    achados = []

    def visitar(entidades):
        for e in entidades or []:
            if papel in e.get("roles", []):
                nome, email = _vcard(e)
                texto = " ".join(p for p in (nome or e.get("handle", ""), f"<{email}>" if email else "") if p)
                if texto and texto not in achados:
                    achados.append(texto)
            visitar(e.get("entities"))

    visitar(rdap.get("entities"))
    return achados


def _evento(rdap: dict, acao: str) -> str:
    for ev in rdap.get("events", []):
        if ev.get("eventAction") == acao:
            return str(ev.get("eventDate", ""))[:10]
    return ""


def _linhas(ip: str, familia: str, ptr, who, apis, rdap) -> list[str]:
    L = [f"IP público: {ip} ({familia})"]

    if ptr:
        L.append(f"DNS reverso (PTR): {ptr['ptr']} [{'confirmado pelo DNS direto' if ptr['confirmado'] else 'NÃO confirmado pelo DNS direto'}]")
    else:
        L.append("DNS reverso (PTR): sem registro")

    if who:
        con, tz, flag = who.get("connection") or {}, who.get("timezone") or {}, who.get("flag") or {}
        L += [
            f"Provedor (ISP): {con.get('isp') or '-'}",
            f"Organização: {con.get('org') or '-'}",
            f"ASN: {('AS' + str(con['asn'])) if con.get('asn') else '-'}  |  Domínio: {con.get('domain') or '-'}",
            "",
            "Geolocalização (aproximada):",
            f"  Cidade/Região: {who.get('city') or '-'} / {who.get('region') or '-'} ({who.get('region_code') or '-'})",
            f"  País: {who.get('country') or '-'} ({who.get('country_code') or '-'}) {flag.get('emoji', '')}  |  Continente: {who.get('continent') or '-'}",
            f"  CEP: {who.get('postal') or '-'}  |  Código telefônico: +{who.get('calling_code') or '-'}  |  UE: {'sim' if who.get('is_eu') else 'não'}",
        ]
        if who.get("latitude") is not None:
            lat, lon = who["latitude"], who["longitude"]
            L += [f"  Coordenadas: {lat}, {lon}", f"  Mapa: https://www.google.com/maps?q={lat},{lon}"]
        L.append(f"  Fuso: {tz.get('id') or '-'} ({tz.get('abbr') or '-'}, UTC{tz.get('utc') or ''}{', horário de verão' if tz.get('is_dst') else ''})")
    else:
        L.append("Geolocalização/ISP: consulta indisponível")

    if apis:
        marcas = {
            "is_mobile": "rede móvel", "is_datacenter": "datacenter/hospedagem", "is_vpn": "VPN",
            "is_proxy": "proxy", "is_tor": "Tor", "is_abuser": "histórico de abuso", "is_crawler": "crawler",
            "is_bogon": "bogon",
        }
        presentes = {k: apis[k] for k in marcas if k in apis}
        L += ["", "Reputação/tipo de conexão (ipapi.is):"]
        if presentes:
            L.append("  " + ", ".join(f"{marcas[k]}: {'SIM' if v else 'não'}" for k, v in presentes.items()))
        else:
            L.append("  (sem indicadores no plano gratuito)")
        empresa = apis.get("company")
        if isinstance(empresa, dict):
            L.append(f"  Empresa: {empresa.get('name') or '-'} ({empresa.get('type') or '-'}) rede {empresa.get('network') or '-'}")
        elif empresa:
            L.append(f"  Empresa: {empresa}")
        if isinstance(apis.get("asn"), dict):
            a = apis["asn"]
            L.append(f"  ASN: AS{a.get('asn')} {a.get('descr') or ''} rota {a.get('route') or '-'} tipo {a.get('type') or '-'}")
        elif apis.get("asn"):
            L.append(f"  ASN: {apis['asn']}")

    if rdap:
        cidrs = ", ".join(
            f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in rdap.get("cidr0_cidrs", [])
        )
        L += [
            "",
            "Registro da rede (RDAP/WHOIS):",
            f"  Nome: {rdap.get('name') or '-'}  |  Handle: {rdap.get('handle') or '-'}  |  Tipo: {rdap.get('type') or '-'}",
            f"  Faixa: {rdap.get('startAddress') or '-'} - {rdap.get('endAddress') or '-'}  |  CIDR: {cidrs or '-'}",
            f"  País: {rdap.get('country') or '-'}  |  Status: {', '.join(rdap.get('status', [])) or '-'}",
            f"  Registrada em: {_evento(rdap, 'registration') or '-'}  |  Última alteração: {_evento(rdap, 'last changed') or '-'}",
        ]
        for rotulo, papel in (("Titular", "registrant"), ("Contato de abuso", "abuse"), ("Contato técnico", "technical")):
            ents = _entidades(rdap, papel)
            if ents:
                L.append(f"  {rotulo}: {'; '.join(ents[:3])}")
        for nota in rdap.get("remarks", [])[:2]:
            texto = " ".join(str(x) for x in nota.get("description", []) if not set(str(x)) <= {"-", " "})
            if texto:
                L.append(f"  Obs.: {texto[:200]}")
    else:
        L += ["", "Registro da rede (RDAP): consulta indisponível"]

    L += [
        "",
        "Consultar mais:",
        f"  https://www.abuseipdb.com/check/{ip}",
        f"  https://bgp.he.net/ip/{ip}",
        f"  https://www.shodan.io/host/{ip}",
    ]
    return L


def eh_publico(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def detalhes_ip(ip: str) -> str:
    try:
        endereco = ipaddress.ip_address(ip)
    except ValueError:
        return f"IP: {ip} (formato inválido)"
    familia = "IPv6" if endereco.version == 6 else "IPv4"
    if not endereco.is_global:
        return (f"IP da conexão: {ip} ({familia}) — NÃO é público (rede local/Docker/proxy sem cabeçalho confiável). "
                "Consultas externas não realizadas.")

    agora = time.monotonic()
    em_cache = _cache.get(ip)
    if em_cache and agora - em_cache[0] < CACHE_TTL:
        return em_cache[1]

    tarefas = {
        "ptr": _pool.submit(_reverso, ip), "who": _pool.submit(_ipwho, ip),
        "apis": _pool.submit(_ipapi_is, ip), "rdap": _pool.submit(_rdap, ip),
    }
    wait(tarefas.values(), timeout=TIMEOUT_GLOBAL)
    r = {}
    for nome, fut in tarefas.items():
        try:
            r[nome] = fut.result(timeout=0) if fut.done() else None
        except Exception as exc:
            logger.warning("Consulta de IP '%s' falhou: %s", nome, type(exc).__name__)
            r[nome] = None

    texto = "\n".join(_linhas(ip, familia, r["ptr"], r["who"], r["apis"], r["rdap"]))
    if any(r.values()):
        _cache[ip] = (agora, texto)
        if len(_cache) > 500:
            _cache.pop(next(iter(_cache)))
    return texto
