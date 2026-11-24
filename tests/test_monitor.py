from datetime import datetime, timedelta

from fastapi.testclient import TestClient

import database
import models
import monitor
from app import app
from tests.conftest import csrf_from, login_admin, login_user, post

DASH = "/admin/dashboard"
SENHA = "Monitor@Senha123"


def _gravar():
    while monitor.processar_fila():
        pass


def _db():
    return database.SessionLocal()


def _eventos(tipo):
    _gravar()
    db = _db()
    try:
        return db.query(models.EventoSeguranca).filter_by(tipo=tipo).all()
    finally:
        db.close()


def test_identifica_robos_e_varreduras():
    assert monitor.identificar_robo("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)") == "Googlebot"
    assert monitor.identificar_robo("Mozilla/5.0 (compatible; bingbot/2.0)") == "Bingbot"
    assert monitor.identificar_robo("WhatsApp/2.23.20.0") == "WhatsApp"
    assert monitor.identificar_robo("curl/8.5.0") == "Script"
    assert monitor.identificar_robo("") == "Script"
    assert monitor.identificar_robo("Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0") is None
    for caminho in ("/wp-login.php", "/.env", "/.git/config", "/phpmyadmin/", "/cgi-bin/luci", "/xmlrpc.php",
                    "/backup.sql", "/vendor/phpunit/x", "/../../etc/passwd"):
        assert monitor.eh_varredura(caminho), caminho
    for caminho in ("/", "/conhecimento", "/conhecimento/fazer-chroot", "/servicos/linux", "/contato", "/admin"):
        assert not monitor.eh_varredura(caminho), caminho


def test_robo_confirmado_por_dns_reverso():
    assert monitor.robo_confirmado("Googlebot", "crawl-66-249-66-1.googlebot.com") is True
    assert monitor.robo_confirmado("Googlebot", "~fake.googlebot.com") is False  # DNS direto não confirma
    assert monitor.robo_confirmado("Googlebot", "host.evil.example") is False
    assert monitor.robo_confirmado("WhatsApp", None) is None


def test_registra_acessos_e_ignora_estaticos(client):
    _gravar()
    client.get("/", headers={"user-agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"})
    client.get("/static/social-card.jpg")
    client.get("/pagina-que-nao-existe")
    _gravar()
    db = _db()
    try:
        ultimos = db.query(models.Acesso).order_by(models.Acesso.id.desc()).limit(2).all()
    finally:
        db.close()
    assert [(a.caminho, a.status) for a in ultimos] == [("/pagina-que-nao-existe", 404), ("/", 200)]
    assert ultimos[1].robo == "Googlebot" and ultimos[1].ms >= 0


def test_varredura_gera_evento_e_marca_suspeito(client):
    client.get("/wp-login.php")
    ev = [e for e in _eventos("varredura") if e.caminho == "/wp-login.php"]
    assert ev and ev[-1].detalhe == "GET → 404"
    db = _db()
    try:
        assert db.query(models.Acesso).filter_by(caminho="/wp-login.php", suspeito=True).count() >= 1
    finally:
        db.close()


def test_login_invalido_bloqueio_e_login_ok_geram_eventos(client):
    post(client, "/admin/login", {"username": "admin", "password": "errada"})
    post(client, "/admin/login", {"username": "fantasma", "password": "x"})
    falhas = _eventos("login_falha")
    assert {(e.usuario, e.detalhe) for e in falhas} >= {("admin", "senha incorreta"), ("fantasma", "usuário inexistente")}
    login_admin(client)
    assert any(e.usuario == "admin" for e in _eventos("login_ok"))


def test_csrf_invalido_gera_evento(client):
    client.post("/contato", data={"nome": "x"})
    assert any(e.caminho == "/contato" for e in _eventos("csrf_invalido"))


def test_geolocalizacao_pelos_cabecalhos_da_cloudflare():
    with TestClient(app, client=("172.18.0.5", 5000)) as via_proxy:  # proxy de confiança (rede docker)
        via_proxy.get("/", headers={"cf-connecting-ip": "200.160.2.3", "cf-ipcountry": "BR", "cf-ipcity": "Niterói".encode(),
                                    "cf-region": "Rio de Janeiro", "cf-iplatitude": "-22.88", "cf-iplongitude": "-43.10"})
    _gravar()
    db = _db()
    try:
        geo = db.get(models.IpGeo, "200.160.2.3")
        assert db.query(models.Acesso).filter_by(ip="200.160.2.3").count() == 1
    finally:
        db.close()
    assert geo and geo.fonte == "cloudflare" and geo.cidade == "Niterói" and geo.pais == "BR" and geo.lat == -22.88


def test_painel_so_para_admin_e_mostra_dados(client):
    login_admin(client)
    db = _db()
    try:
        agora = datetime.utcnow()
        db.add(models.IpGeo(ip="45.10.20.30", pais="NL", pais_nome="Netherlands", cidade="Amsterdam", lat=52.37,
                            lon=4.89, org="Hostile Hosting", rdns="~scan.example", fonte="ipwho.is", atualizado=agora))
        db.add(models.Acesso(ts=agora, ip="45.10.20.30", metodo="GET", caminho="/.env", status=404, ms=1,
                             user_agent="zgrab/0.x", robo="Scanner", suspeito=True))
        db.add(models.EventoSeguranca(ts=agora, ip="45.10.20.30", tipo="varredura", caminho="/.env", detalhe="GET → 404"))
        db.commit()
    finally:
        db.close()
    r = client.get("/admin/seguranca?periodo=7d")
    assert r.status_code == 200 and "Acessos &amp; Segurança_" in r.text
    assert "45.10.20.30" in r.text and "Hostile Hosting" in r.text
    pontos = client.get("/admin/seguranca/mapa.json?periodo=7d").json()["pontos"]
    p = next(x for x in pontos if x["ip"] == "45.10.20.30")
    assert p["tipo"] == "ataque" and p["local"] == "Amsterdam, Netherlands"
    d = client.get("/admin/seguranca/ip/45.10.20.30")
    assert d.status_code == 200 and "/.env" in d.text and "não confirmado" in d.text
    assert client.get("/admin/seguranca/ip/nao-e-ip").status_code == 404
    assert 'href="/admin/seguranca"' in client.get(DASH).text


def test_nao_admin_nao_ve_o_painel(client):
    login_admin(client)
    post(client, "/admin/usuarios/add", {"username": "espiao", "password": SENHA, "confirm_password": SENHA}, page=DASH)
    with TestClient(app, follow_redirects=False) as outro:
        login_user(outro, "espiao", SENHA)
        assert outro.get("/admin/seguranca").status_code == 403
        assert outro.get("/admin/seguranca/mapa.json").status_code == 403
        assert 'href="/admin/seguranca"' not in outro.get(DASH).text
    assert any(e.usuario == "espiao" and e.caminho == "/admin/seguranca" for e in _eventos("acesso_negado"))
    db = _db()
    try:
        uid = db.query(models.Usuario).filter_by(username="espiao").first().id
    finally:
        db.close()
    post(client, f"/admin/usuarios/delete/{uid}", {}, page=DASH)


def test_anonimo_e_redirecionado_e_admin_tem_noindex(client):
    r = client.get("/admin/seguranca")
    assert r.status_code == 302 and r.headers["location"] == "/admin"
    assert client.get("/admin").headers.get("x-robots-tag") == "noindex, nofollow"


def test_limpeza_remove_registros_antigos():
    db = _db()
    try:
        velho = datetime.utcnow() - timedelta(days=monitor.RETENCAO_DIAS + 1)
        db.add(models.Acesso(ts=velho, ip="10.0.0.1", metodo="GET", caminho="/velho", status=200, ms=1))
        db.add(models.EventoSeguranca(ts=velho, ip="10.0.0.1", tipo="login_falha"))
        db.commit()
        monitor.limpar_antigos(db)
        assert db.query(models.Acesso).filter_by(caminho="/velho").count() == 0
        assert db.query(models.EventoSeguranca).filter_by(ip="10.0.0.1").count() == 0
    finally:
        db.close()
