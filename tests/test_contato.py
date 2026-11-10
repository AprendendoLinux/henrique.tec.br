import time

from tests.conftest import csrf_from

VALIDO = {
    "nome": "Maria Silva", "email": "maria@exemplo.com", "telefone": "+55 21 99999-0000",
    "servico": "Servidores Linux", "prazo": "Urgente",
    "mensagem": "Preciso migrar meu servidor de e-mail.",
}


def enviar(client, dados, esperar=True):
    page = client.get("/contato")
    if esperar:
        client.cookies  # noqa
    token = csrf_from(page.text)
    return client.post("/contato", data={**dados, "csrf_token": token})


def liberar_tempo(client, monkeypatch):
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 10)


def test_pagina_carrega(client):
    r = client.get("/contato")
    assert r.status_code == 200 and "Solicitar Orçamento" in r.text


def test_envio_valido(client, enviados, monkeypatch):
    page = client.get("/contato")
    liberar_tempo(client, monkeypatch)
    r = client.post("/contato", data={**VALIDO, "csrf_token": csrf_from(page.text)})
    assert r.status_code == 303
    assert len(enviados) == 1
    assunto, corpo, reply_to = enviados[0]
    assert assunto.startswith("[Orçamento]") and reply_to == "maria@exemplo.com"
    assert "migrar meu servidor" in corpo


def test_envio_rapido_demais_rejeitado(client, enviados):
    r = enviar(client, VALIDO)
    assert r.status_code == 400 and not enviados


def test_honeypot_nao_envia(client, enviados, monkeypatch):
    page = client.get("/contato")
    liberar_tempo(client, monkeypatch)
    r = client.post("/contato", data={**VALIDO, "website": "http://spam", "csrf_token": csrf_from(page.text)})
    assert r.status_code == 303 and not enviados


def test_sem_csrf_rejeitado(client, enviados):
    client.get("/contato")
    assert client.post("/contato", data=VALIDO).status_code == 403 and not enviados


def test_validacoes(client, enviados, monkeypatch):
    page = client.get("/contato")
    liberar_tempo(client, monkeypatch)
    token = csrf_from(page.text)
    for ruim in ({"email": "invalido"}, {"nome": ""}, {"mensagem": "curta"}, {"servico": "Hackear"},
                 {"email": "a@b.com\r\nBcc: x@y.com"}):
        r = client.post("/contato", data={**VALIDO, **ruim, "csrf_token": token})
        assert r.status_code in (400, 422), ruim
    assert not enviados


def test_rate_limit_por_ip(client, enviados, monkeypatch):
    real, avanco = time.time, [0]
    monkeypatch.setattr(time, "time", lambda: real() + avanco[0])
    codigos = []
    for _ in range(4):
        page = client.get("/contato")
        if "csrf_token" not in page.text:
            page = client.get("/contato")
        avanco[0] += 10
        r = client.post("/contato", data={**VALIDO, "csrf_token": csrf_from(page.text)})
        codigos.append(r.status_code)
    assert codigos == [303, 303, 303, 429]


def test_cabecalho_sem_injecao():
    from mailer import limpar_cabecalho
    assert "\n" not in limpar_cabecalho("Assunto\r\nBcc: x@y.com")


def _enviar(client, monkeypatch):
    page = client.get("/contato")
    liberar_tempo(client, monkeypatch)
    return client.post("/contato", data={**VALIDO, "csrf_token": csrf_from(page.text)})


def test_telegram_recebe_pedido(client, enviados, monkeypatch):
    import notify
    tg = []
    monkeypatch.setattr(notify, "telegram_configurado", lambda: True)
    monkeypatch.setattr(notify, "enviar_telegram", lambda t: tg.append(t))
    assert _enviar(client, monkeypatch).status_code == 303
    assert len(enviados) == 1 and len(tg) == 1 and "migrar meu servidor" in tg[0]


def test_email_falha_mas_telegram_entrega(client, monkeypatch):
    import mailer, notify
    def quebra(*a, **k):
        raise OSError("smtp fora")
    monkeypatch.setattr(mailer, "enviar_email", quebra)
    monkeypatch.setattr(notify, "telegram_configurado", lambda: True)
    monkeypatch.setattr(notify, "enviar_telegram", lambda t: None)
    assert _enviar(client, monkeypatch).status_code == 303


def test_todos_canais_falham(client, monkeypatch):
    import mailer
    def quebra(*a, **k):
        raise OSError("smtp fora")
    monkeypatch.setattr(mailer, "enviar_email", quebra)
    assert _enviar(client, monkeypatch).status_code == 502
