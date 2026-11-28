"""Proteções do formulário de orçamento contra spam.

1. Pontuação de suspeita: envios com pontuação >= LIMIAR vão para a quarentena (sem notificação) e aparecem
   no painel, onde podem ser liberados. Nenhum pedido é descartado por engano.
2. Reincidência: o IP que preenche o campo-isca fica bloqueado no formulário por PENALIDADE_HORAS
   (os envios seguintes são descartados em silêncio, com cara de sucesso).
3. Faixa de rede: o limite de envios também conta a faixa inteira (/24 no IPv4, /48 no IPv6), porque os
   robôs trocam de IP dentro da mesma rede.
"""
import ipaddress
import re
import threading
import time
import unicodedata
from datetime import datetime, timedelta

LIMIAR = 4
PENALIDADE_HORAS = 24

# --------------------------------------------------------------------------------------------- faixa de rede


def faixa(ip: str) -> str:
    """Rede /24 (IPv4) ou /48 (IPv6) do IP, usada no limite de envios por faixa."""
    try:
        endereco = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if endereco.version == 6 and endereco.ipv4_mapped:
        endereco = endereco.ipv4_mapped
    prefixo = 24 if endereco.version == 4 else 48
    return str(ipaddress.ip_network(f"{endereco}/{prefixo}", strict=False))


# ------------------------------------------------------------------------------------------- reincidentes

_penalizados: dict[str, float] = {}  # ip -> expira em (time.time())
_lock = threading.Lock()


def penalizar(ip: str) -> None:
    with _lock:
        _penalizados[ip] = time.time() + PENALIDADE_HORAS * 3600
        if len(_penalizados) > 5000:
            agora = time.time()
            for k in [k for k, v in _penalizados.items() if v < agora]:
                _penalizados.pop(k, None)


def penalizado(ip: str, db=None) -> bool:
    """IP caiu no campo-isca nas últimas PENALIDADE_HORAS? Consulta a memória e, se informado, o banco
    (eventos 'spam_formulario', para o castigo sobreviver a reinícios do site)."""
    with _lock:
        expira = _penalizados.get(ip)
    if expira and expira > time.time():
        return True
    if db is None:
        return False
    import models
    limite = datetime.utcnow() - timedelta(hours=PENALIDADE_HORAS)
    achou = db.query(models.EventoSeguranca.id).filter(
        models.EventoSeguranca.ip == ip, models.EventoSeguranca.tipo == "spam_formulario",
        models.EventoSeguranca.ts >= limite).first()
    if achou:
        penalizar(ip)
    return bool(achou)


HISTORICO_DIAS = 30
TIPOS_ATAQUE = ("spam_formulario", "formulario_bloqueado", "formulario_quarentena", "varredura", "cloudflare_bloqueio")


def historico(ip: str, db) -> tuple[int, int]:
    """Eventos de ataque nos últimos HISTORICO_DIAS: (do próprio IP, de outros IPs da mesma faixa)."""
    import models
    E = models.EventoSeguranca
    base = db.query(E.id).filter(E.tipo.in_(TIPOS_ATAQUE), E.ts >= datetime.utcnow() - timedelta(days=HISTORICO_DIAS))
    do_ip = base.filter(E.ip == ip).limit(50).count()
    rede = faixa(ip)
    prefixo = None
    if rede.endswith("/24"):
        prefixo = rede.rsplit(".", 1)[0] + "."
    elif rede.endswith("/48"):
        prefixo = rede.split("::")[0] + ":"
    da_faixa = base.filter(E.ip.like(prefixo + "%"), E.ip != ip).limit(50).count() if prefixo else 0
    return do_ip, da_faixa


def limpar() -> None:
    with _lock:
        _penalizados.clear()


# ----------------------------------------------------------------------------------------------- pontuação

_URL = re.compile(r"(https?://|www\.|\b[a-z0-9-]+\.(com|net|org|io|ru|xyz|top|info|biz|online|site|shop)\b)", re.I)
_EMAIL = re.compile(r"\S+@\S+")
DESCARTAVEIS = {
    "mailinator.com", "guerrillamail.com", "guerrillamail.net", "10minutemail.com", "temp-mail.org", "tempmail.com",
    "yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com", "dispostable.com", "maildrop.cc",
    "throwawaymail.com", "fakeinbox.com", "mohmal.com", "emailondeck.com", "tempmail.plus", "mail.tm", "mailnesia.com",
    "spamgourmet.com", "moakt.com", "tempr.email", "burnermail.io", "minuteinbox.com", "inboxkitten.com",
}
TERMOS_SPAM = (
    "seo", "backlink", "rank your", "ranking on google", "first page of google", "google first page", "guest post",
    "link building", "domain authority", "traffic to your", "increase your traffic", "web design services",
    "website redesign", "app development company", "outsourc", "lead generation", "leads for your", "crypto",
    "bitcoin", "forex", "casino", "betting", "loan", "viagra", "cialis", "porn", "dating", "investment opportunity",
    "make money", "earn money", "whatsapp me", "telegram me", "unsubscribe", "opt-out", "dear sir", "dear business owner",
    "hello sir", "i noticed your website", "i came across your website", "your website is not", "free quote",
)
_INGLES = {"the", "and", "your", "you", "we", "our", "website", "business", "with", "for", "this", "can", "are", "hello",
           "hi", "please", "services", "offer"}
_PORTUGUES = {"de", "que", "não", "nao", "para", "com", "um", "uma", "meu", "minha", "preciso", "olá", "ola", "bom",
              "dia", "tarde", "noite", "obrigado", "obrigada", "servidor", "empresa", "gostaria", "orçamento", "você"}


def _escrita_estrangeira(texto: str) -> bool:
    """Cirílico, chinês/japonês/coreano, árabe etc. (a parte não latina do texto)."""
    for ch in texto:
        if ch.isalpha() and ord(ch) > 0x24F:
            nome = unicodedata.name(ch, "")
            if not nome.startswith(("LATIN", "GREEK")):  # acentos e símbolos latinos são normais em português
                return True
    return False


def pontuar(nome: str, email: str, mensagem: str, ind: dict) -> tuple[int, list[str]]:
    """Pontuação de suspeita e os motivos (legíveis no painel). ind = ipinfo.indicadores(ip)."""
    pontos, motivos = 0, []

    def soma(p: int, motivo: str):
        nonlocal pontos
        pontos += p
        motivos.append(f"{motivo} (+{p})")

    if ind.get("tor"):
        soma(3, "rede Tor")
    elif ind.get("vpn") or ind.get("proxy"):
        soma(2, "VPN/proxy")
    if ind.get("datacenter"):
        soma(3, "IP de datacenter/hospedagem")
    if ind.get("abuso"):
        soma(2, "IP com histórico de abuso")
    if ind.get("historico_ip"):
        soma(3, f"IP com histórico de ataques ao site ({ind['historico_ip']} evento(s))")
    elif ind.get("historico_faixa"):
        soma(2, f"rede com histórico de ataques ao site ({ind['historico_faixa']} evento(s))")
    if ind.get("pais") and ind["pais"] != "BR":
        soma(1, f"fora do Brasil ({ind['pais']})")

    links = len(_URL.findall(_EMAIL.sub(" ", mensagem)))  # e-mail citado na mensagem não conta como link
    if links:
        soma(min(4, 2 * links), f"{links} link(s) na mensagem")
    if _escrita_estrangeira(nome + " " + mensagem):
        soma(4, "escrita em alfabeto estrangeiro")
    dominio = email.rsplit("@", 1)[-1].lower()
    if dominio in DESCARTAVEIS:
        soma(3, "e-mail descartável")
    texto = mensagem.lower()
    termos = [t for t in TERMOS_SPAM if re.search(r"\b" + re.escape(t), texto)]
    if termos:
        soma(min(4, 2 * len(termos)), "termos de spam: " + ", ".join(termos[:4]))
    palavras = re.findall(r"[a-zà-ú]+", texto)
    if sum(p in _INGLES for p in palavras) >= 4 and sum(p in _PORTUGUES for p in palavras) < 2:
        soma(2, "mensagem em inglês")
    return pontos, motivos


def suspeito(pontos: int) -> bool:
    return pontos >= LIMIAR
