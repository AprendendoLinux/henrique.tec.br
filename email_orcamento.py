"""E-mail (HTML no tema do site + texto puro) do formulário de orçamento."""
import re
from datetime import datetime, timedelta, timezone

from markupsafe import Markup, escape

from deps import templates

BRT = timezone(timedelta(hours=-3))
_URL = re.compile(r"https?://[^\s<>\"']+")


def _linkar(valor: str, cor: str = "#00ffcc") -> Markup:
    """Escapa o texto e transforma URLs em links."""
    partes, ultimo = [], 0
    texto = str(valor)
    for m in _URL.finditer(texto):
        partes.append(escape(texto[ultimo:m.start()]))
        url = escape(m.group(0))
        partes.append(Markup(f'<a href="{url}" style="color:{cor};text-decoration:none;">{url}</a>'))
        ultimo = m.end()
    partes.append(escape(texto[ultimo:]))
    return Markup("").join(partes)


templates.env.filters["linkar"] = _linkar


def secoes_ip(detalhes: str) -> list[dict]:
    """Converte o relatório de texto do ipinfo em seções [{titulo, linhas: [(chave, valor)]}]."""
    secoes = [{"titulo": "", "linhas": []}]
    for bruta in detalhes.splitlines():
        linha = bruta.strip()
        if not linha:
            continue
        if not bruta.startswith(" ") and linha.endswith(":"):
            secoes.append({"titulo": linha[:-1], "linhas": []})
            continue
        partes = []
        for parte in linha.split("  |  "):
            # "rede móvel: não, VPN: SIM" -> um indicador por linha
            partes += parte.split(", ") if parte.count(": ") > 1 and "://" not in parte else [parte]
        for parte in partes:
            chave, sep, valor = parte.partition(": ")
            if sep and "," not in chave and len(chave) <= 30 and not chave.startswith("http"):
                secoes[-1]["linhas"].append((chave.strip(), valor.strip()))
            else:
                secoes[-1]["linhas"].append(("", parte.strip()))
    return [s for s in secoes if s["linhas"]]


def _whatsapp(telefone: str) -> str | None:
    digitos = re.sub(r"\D", "", telefone or "")
    if len(digitos) in (10, 11) and not telefone.strip().startswith("+"):
        digitos = "55" + digitos  # número brasileiro sem código do país
    return f"https://wa.me/{digitos}" if len(digitos) >= 12 else None


def montar(assunto: str, nome: str, email: str, telefone: str, servico: str, prazo: str, mensagem: str,
           detalhes_ip: str, proxies: str, site: str) -> str:
    site = site.rstrip("/") + "/"
    return templates.get_template("email/orcamento.html").render(
        assunto=assunto, nome=nome, email=email, telefone=telefone, servico=servico, prazo=prazo,
        mensagem=mensagem, proxies=proxies, ip_secoes=secoes_ip(detalhes_ip),
        tel_digitos=re.sub(r"[^\d+]", "", telefone or ""), whatsapp=_whatsapp(telefone),
        quando=datetime.now(BRT).strftime("%d/%m/%Y %H:%M"), site=site,
        site_nome=site.split("://", 1)[-1].rstrip("/"))
