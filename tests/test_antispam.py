import antispam
import database
import ipinfo
import models
import monitor
from routers import contact
from tests.conftest import csrf_from, login_admin, post
from tests.test_contato import VALIDO, liberar_tempo

LIMPO = {"pais": "BR", "cidade": "Niterói", "org": "Provedor X", "datacenter": False, "vpn": False, "proxy": False,
         "tor": False, "abuso": False, "consultado": True}
VPS_RU = {**LIMPO, "pais": "RU", "cidade": "Moscow", "org": "VDSINA VDS Hosting", "datacenter": True}


def _enviar(client, monkeypatch, dados=None):
    page = client.get("/contato")
    if 'name="csrf_token"' not in page.text:  # tela de "enviado" após um envio: recarrega o formulário
        page = client.get("/contato")
    liberar_tempo(client, monkeypatch)
    return client.post("/contato", data={**(dados or VALIDO), "csrf_token": csrf_from(page.text)})


def _ultima():
    with database.SessionLocal() as db:
        return db.query(models.MensagemContato).order_by(models.MensagemContato.id.desc()).first()


def test_pontuacao():
    assert antispam.pontuar("Maria", "maria@empresa.com.br", "Olá, preciso de um orçamento para migrar meu servidor.", LIMPO)[0] == 0
    # e-mail citado na mensagem não conta como link
    assert antispam.pontuar("Maria", "m@x.com", "Olá, meu outro e-mail é maria@empresa.com, preciso de ajuda.", LIMPO)[0] == 0
    p, motivos = antispam.pontuar("John", "john@x.com", "Olá, preciso de um orçamento.", VPS_RU)
    assert antispam.suspeito(p) and any("datacenter" in m for m in motivos) and any("RU" in m for m in motivos)
    p, motivos = antispam.pontuar("John", "john@gmail.com", "Hello, we can rank your website on the first page of Google "
                                  "with our SEO and backlink services for your business. Visit https://x.top", LIMPO)
    assert antispam.suspeito(p) and any("termos de spam" in m for m in motivos) and any("link" in m for m in motivos)
    assert antispam.suspeito(antispam.pontuar("Иван", "ivan@mail.ru", "Привет, мы предлагаем услуги для вашего сайта", LIMPO)[0])
    assert "e-mail descartável" in antispam.pontuar("X", "x@yopmail.com", "Olá, preciso de ajuda.", LIMPO)[1][0]
    assert antispam.pontuar("José Conceição", "j@x.com.br", "Olá! Ação rápida: manutenção e configuração.", LIMPO)[0] == 0


def test_faixa_de_rede():
    assert antispam.faixa("178.20.45.159") == antispam.faixa("178.20.45.128") == "178.20.45.0/24"
    assert antispam.faixa("::ffff:178.20.45.1") == "178.20.45.0/24"
    assert antispam.faixa("2804:1740:11:1700::8") == "2804:1740:11::/48"


def test_pedido_legitimo_e_entregue_com_telegram_enxuto(client, enviados, monkeypatch):
    tg = []
    monkeypatch.setattr(contact.notify, "telegram_configurado", lambda: True)
    monkeypatch.setattr(contact.notify, "enviar_telegram", tg.append)
    monkeypatch.setattr(ipinfo, "indicadores", lambda ip: LIMPO)
    assert _enviar(client, monkeypatch).status_code == 303
    assert len(enviados) == 1 and "Detalhes do IP" in enviados[0][1]  # e-mail continua completo
    msg = tg[0]
    assert msg.startswith("📩 Novo orçamento — Servidores Linux (Urgente)")
    for trecho in ("👤 Maria Silva", "✉️ maria@exemplo.com", "📞 +55 21 99999-0000", "💬 Preciso migrar", "🌐 testclient · Niterói, BR · Provedor X"):
        assert trecho in msg, trecho
    assert "abuseipdb" not in msg and "RDAP" not in msg and "Cabeçalhos" not in msg
    assert _ultima().status == "entregue"


def test_suspeito_vai_para_quarentena_e_admin_libera(client, enviados, monkeypatch):
    monkeypatch.setattr(ipinfo, "indicadores", lambda ip: VPS_RU)
    r = _enviar(client, monkeypatch)
    assert r.status_code == 303 and not enviados  # parece sucesso para o robô, mas não notifica
    m = _ultima()
    assert m.status == "quarentena" and m.pontuacao >= 4 and "datacenter" in m.motivos and m.org == "VDSINA VDS Hosting"
    login_admin(client)
    html = client.get("/admin/dashboard").text
    assert 'id="tab-mensagens"' in html and "VDSINA VDS Hosting" in html and "Liberar" in html
    assert post(client, f"/admin/mensagens/{m.id}/liberar", {}, page="/admin/dashboard").status_code == 302
    assert len(enviados) == 1 and _ultima().status == "liberada"
    post(client, f"/admin/mensagens/{m.id}/excluir", {}, page="/admin/dashboard")
    with database.SessionLocal() as db:
        assert db.get(models.MensagemContato, m.id) is None


def test_reincidente_do_campo_isca_e_ignorado_em_silencio(client, enviados, monkeypatch):
    monkeypatch.setattr(ipinfo, "indicadores", lambda ip: LIMPO)
    assert _enviar(client, monkeypatch, {**VALIDO, "website": "http://spam"}).status_code == 303
    assert _enviar(client, monkeypatch).status_code == 303 and not enviados
    while monitor.processar_fila():
        pass
    with database.SessionLocal() as db:
        ev = db.query(models.EventoSeguranca).filter_by(tipo="formulario_bloqueado").order_by(models.EventoSeguranca.id.desc()).first()
    assert "Reincidente" in ev.detalhe
    antispam.limpar()  # reinício do site: o castigo continua valendo pelo banco
    assert antispam.penalizado("testclient", database.SessionLocal())


def test_limite_por_faixa_de_rede(client, enviados, monkeypatch):
    monkeypatch.setattr(ipinfo, "indicadores", lambda ip: LIMPO)
    ips = iter(f"178.20.45.{i}" for i in range(1, 20))
    monkeypatch.setattr(contact, "client_ip", lambda request: next(ips))
    codigos = [_enviar(client, monkeypatch).status_code for _ in range(contact.LIMITE_FAIXA + 1)]
    assert codigos[:-1] == [303] * contact.LIMITE_FAIXA and codigos[-1] == 429
    assert len(enviados) == contact.LIMITE_FAIXA


def test_nao_admin_nao_ve_mensagens(client):
    from fastapi.testclient import TestClient
    from app import app
    from tests.conftest import login_user
    login_admin(client)
    post(client, "/admin/usuarios/add", {"username": "leitor", "password": "Leitor@Senha123", "confirm_password": "Leitor@Senha123"}, page="/admin/dashboard")
    with TestClient(app, follow_redirects=False) as outro:
        login_user(outro, "leitor", "Leitor@Senha123")
        assert 'id="tab-mensagens"' not in outro.get("/admin/dashboard").text
        assert post(outro, "/admin/mensagens/limpar-quarentena", {}, page="/admin/dashboard").status_code == 403
    with database.SessionLocal() as db:
        uid = db.query(models.Usuario).filter_by(username="leitor").first().id
    post(client, f"/admin/usuarios/delete/{uid}", {}, page="/admin/dashboard")


def test_provedor_de_hospedagem_pelo_nome_e_dns_reverso():
    for org in ("VDSINA VDS Hosting", "Hosting technology LTD", "SERVERS TECH FZCO", "Alibaba Cloud - HK", "Xorek.Cloud Helsinki",
                "Amazon Technologies Inc.", "Hospedagem Segura", "DigitalOcean, LLC", "Hetzner Online GmbH", "OVH SAS", "Server Mania Inc."):
        assert ipinfo.eh_hospedagem(org), org
    assert ipinfo.eh_hospedagem("Empresa X", ptr="host-178-20-45-159.hosted-by-vdsina.ru")
    for org in ("TELEFÔNICA BRASIL S.A", "FIRENET SERVIÇOS DE TELECOMUNICAÇÕES", "Claro NXT Telecomunicacoes Ltda",
                "TIM S/A", "Lanet Network LTD", "Núcleo de Inf. e Coord. do Ponto BR - NIC.BR"):
        assert not ipinfo.eh_hospedagem(org), org
    assert not ipinfo.eh_hospedagem("Vivo", ptr="179-100-20-30.user.vivozap.com.br")


def test_historico_de_ataques_do_ip_e_da_faixa(client):
    from datetime import datetime
    with database.SessionLocal() as db:
        db.add(models.EventoSeguranca(ts=datetime.utcnow(), ip="185.231.154.128", tipo="varredura", caminho="/.env"))
        db.commit()
        assert antispam.historico("185.231.154.128", db) == (1, 0)
        assert antispam.historico("185.231.154.9", db) == (0, 1)
        assert antispam.historico("185.231.155.9", db) == (0, 0)
    assert antispam.suspeito(antispam.pontuar("X", "x@x.com", "Olá, preciso de um orçamento.",
                                              {**LIMPO, "pais": "NL", "historico_ip": 1})[0])
