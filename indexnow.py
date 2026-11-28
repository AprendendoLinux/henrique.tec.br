"""IndexNow: avisa os buscadores (Bing, Yandex, Seznam, Naver...) sempre que um artigo é publicado,
atualizado ou removido na Base de Conhecimento.

- A chave é gerada uma vez e publicada em /<chave>.txt (exigência do protocolo).
- O estado enviado ({slug: data de atualização}) fica salvo nas configurações; a cada atualização do
  índice da busca, só as diferenças são enviadas. Na primeira vez, envia todas as URLs.
- Desligado fora da produção (variável SITE_AMBIENTE=dev no compose da dev) e pelo painel.
"""
import json
import logging
import os
import secrets
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone

from appsettings import cfg, store
from database import SessionLocal

logger = logging.getLogger(__name__)

ENDPOINT = "https://api.indexnow.org/IndexNow"
_lock = threading.Lock()


def em_producao() -> bool:
    return os.getenv("SITE_AMBIENTE", "producao").lower() not in ("dev", "desenvolvimento", "teste")


def garantir_chave() -> str:
    chave = cfg.INDEXNOW_KEY
    if not chave:
        chave = secrets.token_hex(16)
        db = SessionLocal()
        try:
            store.save(db, {"indexnow_key": chave})
        finally:
            db.close()
    return chave


def _estado() -> dict:
    try:
        return json.loads(store.get("indexnow_estado") or "{}")
    except ValueError:
        return {}


def _salvar(mapa: dict) -> None:
    db = SessionLocal()
    try:
        store.save(db, mapa)
    finally:
        db.close()


def enviar(urls: list[str]) -> tuple[bool, str]:
    """Envia a lista de URLs ao IndexNow (até 10.000 por chamada)."""
    if not urls:
        return True, "nada a enviar"
    if not em_producao():  # trava final: dev e testes nunca falam com o IndexNow
        return False, "fora da produção: nada enviado"
    base = cfg.SITE_URL
    corpo = json.dumps({"host": base.split("://", 1)[-1].split("/")[0], "key": garantir_chave(),
                        "keyLocation": f"{base}/{garantir_chave()}.txt", "urlList": urls[:10000]}).encode()
    req = urllib.request.Request(ENDPOINT, data=corpo, method="POST",
                                 headers={"Content-Type": "application/json; charset=utf-8",
                                          "User-Agent": "henrique.tec.br-indexnow/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return True, f"HTTP {r.status}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return False, type(exc).__name__


def sincronizar(paginas: list[dict], forcar: bool = False) -> str | None:
    """Compara os artigos atuais com o último estado enviado e notifica as diferenças."""
    if not (cfg.INDEXNOW_ATIVO and em_producao()):
        return None
    with _lock:
        anterior = {} if forcar else _estado()
        atual = {p["slug"]: (p["atualizado"] or p["publicado"]).isoformat() if (p["atualizado"] or p["publicado"]) else ""
                 for p in paginas}
        base = cfg.SITE_URL
        mudados = [s for s, data in atual.items() if anterior.get(s) != data]
        removidos = [s for s in anterior if s not in atual]
        if not (mudados or removidos):
            return None
        urls = [f"{base}/conhecimento/{s}" for s in mudados + removidos] + [f"{base}/conhecimento", f"{base}/sitemap.xml"]
        if not anterior:  # primeira vez: o site inteiro
            urls += [base + "/", f"{base}/contato"] + [f"{base}/servicos/{s}" for s in
                                                       ("linux", "firewall", "docker", "virtualizacao", "desenvolvimento", "desktop")]
        ok, msg = enviar(urls)
        quando = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        resumo = f"{quando} · {len(urls)} URL(s) · {'ok' if ok else 'falha'} ({msg})"
        dados = {"indexnow_ultimo": resumo}
        if ok:
            dados["indexnow_estado"] = json.dumps(atual)
        _salvar(dados)
        (logger.info if ok else logger.warning)("IndexNow: %s", resumo)
        return resumo
