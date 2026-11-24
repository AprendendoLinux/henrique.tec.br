"""Painel de acessos e segurança (somente administradores): /admin/seguranca."""
import ipaddress
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import case, distinct, func
from sqlalchemy.orm import Session

import models
import monitor
from database import get_db
from deps import admin_guard, require_admin, templates

router = APIRouter(prefix="/admin", dependencies=[Depends(admin_guard), Depends(require_admin)])

PERIODOS = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30, "90d": 24 * 90}
EVENTOS = {
    "varredura": ("Varredura de vulnerabilidades", "ataque"),
    "login_falha": ("Login com credenciais inválidas", "ataque"),
    "login_bloqueado": ("Login bloqueado por excesso de tentativas", "ataque"),
    "2fa_falha": ("Código 2FA inválido", "ataque"),
    "2fa_bloqueado": ("2FA bloqueado por excesso de tentativas", "ataque"),
    "csrf_invalido": ("Requisição sem token CSRF válido", "ataque"),
    "acesso_negado": ("Acesso negado (exige administrador)", "alerta"),
    "spam_formulario": ("Spam no formulário (campo-isca)", "alerta"),
    "formulario_bloqueado": ("Formulário bloqueado por excesso de envios", "alerta"),
    "login_ok": ("Login realizado", "info"),
    "logout": ("Logout", "info"),
}
ATAQUES = [k for k, (_, nivel) in EVENTOS.items() if nivel == "ataque"]


def _desde(periodo: str) -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=PERIODOS[periodo])


def _balde(db: Session, periodo: str):
    """Expressão que agrupa o horário em hora (24h) ou dia (demais períodos), em UTC."""
    por_hora = periodo == "24h"
    if db.bind.dialect.name == "sqlite":
        return func.strftime("%Y-%m-%d %H:00" if por_hora else "%Y-%m-%d", models.Acesso.ts)
    return func.date_format(models.Acesso.ts, "%Y-%m-%d %H:00" if por_hora else "%Y-%m-%d")


def _serie(db: Session, periodo: str, desde: datetime) -> dict:
    b = _balde(db, periodo).label("b")
    linhas = (db.query(b, func.count().label("total"),
                       func.sum(case((models.Acesso.robo.is_(None), 1), else_=0)).label("humanos"),
                       func.sum(case((models.Acesso.suspeito.is_(True), 1), else_=0)).label("suspeitos"))
              .filter(models.Acesso.ts >= desde).group_by(b).order_by(b).all())
    por = {r.b: r for r in linhas}
    rotulos, passo = [], timedelta(hours=1) if periodo == "24h" else timedelta(days=1)
    fmt = "%Y-%m-%d %H:00" if periodo == "24h" else "%Y-%m-%d"
    t, fim = desde.replace(minute=0, second=0, microsecond=0), datetime.now(timezone.utc).replace(tzinfo=None)
    if periodo != "24h":
        t = t.replace(hour=0)
    while t <= fim:
        rotulos.append(t.strftime(fmt))
        t += passo
    return {
        "rotulos": rotulos,
        "humanos": [int(por[r].humanos or 0) if r in por else 0 for r in rotulos],
        "robos": [int((por[r].total or 0) - (por[r].humanos or 0)) if r in por else 0 for r in rotulos],
        "suspeitos": [int(por[r].suspeitos or 0) if r in por else 0 for r in rotulos],
    }


def _geo_map(db: Session, ips) -> dict:
    ips = list({i for i in ips if i})
    if not ips:
        return {}
    return {g.ip: g for g in db.query(models.IpGeo).filter(models.IpGeo.ip.in_(ips)).all()}


def painel(db: Session, periodo: str) -> dict:
    desde = _desde(periodo)
    A, E = models.Acesso, models.EventoSeguranca
    no_periodo = A.ts >= desde

    tot = db.query(func.count(), func.count(distinct(A.ip)),
                   func.sum(case((A.robo.is_(None), 1), else_=0)),
                   func.sum(case((A.suspeito.is_(True), 1), else_=0)),
                   func.count(distinct(case((A.robo.is_(None), A.ip)))),
                   func.sum(case((A.status == 404, 1), else_=0))).filter(no_periodo).one()
    buscadores = [n for n, c in monitor.CATEGORIA.items() if c == "buscador"]
    hits_buscadores = db.query(func.count()).filter(no_periodo, A.robo.in_(buscadores)).scalar() or 0
    eventos_por_tipo = dict(db.query(E.tipo, func.count()).filter(E.ts >= desde).group_by(E.tipo).all())
    ips_atacantes = db.query(func.count(distinct(E.ip))).filter(E.ts >= desde, E.tipo.in_(ATAQUES)).scalar() or 0

    # IPs: acessos + eventos de ataque
    ev_por_ip = dict(db.query(E.ip, func.count()).filter(E.ts >= desde, E.tipo.in_(ATAQUES)).group_by(E.ip).all())
    top = (db.query(A.ip, func.count().label("hits"), func.max(A.ts).label("ultimo"),
                    func.sum(case((A.suspeito.is_(True), 1), else_=0)).label("suspeitos"),
                    func.max(A.robo).label("robo"), func.count(distinct(A.caminho)).label("paginas"))
           .filter(no_periodo).group_by(A.ip).order_by(func.count().desc()).limit(40).all())
    # IPs mais suspeitos: por eventos de ataque (mesmo sem muitos acessos)
    ips_suspeitos = sorted(ev_por_ip.items(), key=lambda x: -x[1])[:25]
    geos = _geo_map(db, [t.ip for t in top] + [i for i, _ in ips_suspeitos])

    eventos = db.query(E).filter(E.ts >= desde).order_by(E.ts.desc()).limit(120).all()
    geos.update(_geo_map(db, [e.ip for e in eventos if e.ip not in geos]))

    paginas = (db.query(A.caminho, func.count().label("hits"), func.count(distinct(A.ip)).label("ips"))
               .filter(no_periodo, A.robo.is_(None), A.status < 400, A.metodo == "GET")
               .group_by(A.caminho).order_by(func.count().desc()).limit(20).all())
    nao_encontradas = (db.query(A.caminho, func.count().label("hits"), func.count(distinct(A.ip)).label("ips"))
                       .filter(no_periodo, A.status == 404).group_by(A.caminho)
                       .order_by(func.count().desc()).limit(15).all())

    robos_brutos = (db.query(A.robo, A.ip, func.count().label("hits"), func.max(A.ts).label("ultimo"))
                    .filter(no_periodo, A.robo.isnot(None)).group_by(A.robo, A.ip).all())
    geos.update(_geo_map(db, [r.ip for r in robos_brutos if r.ip not in geos]))
    robos: dict[str, dict] = {}
    for r in robos_brutos:
        item = robos.setdefault(r.robo, {"robo": r.robo, "categoria": monitor.CATEGORIA.get(r.robo, "-"),
                                         "hits": 0, "ips": 0, "ultimo": r.ultimo, "verificados": 0, "falsos": 0})
        item["hits"] += r.hits
        item["ips"] += 1
        item["ultimo"] = max(item["ultimo"], r.ultimo)
        ok = monitor.robo_confirmado(r.robo, getattr(geos.get(r.ip), "rdns", None))
        if ok is True:
            item["verificados"] += 1
        elif ok is False and getattr(geos.get(r.ip), "rdns", None) is not None:
            item["falsos"] += 1
    robos_lista = sorted(robos.values(), key=lambda x: -x["hits"])

    paises = (db.query(models.IpGeo.pais, func.max(models.IpGeo.pais_nome), func.count(distinct(A.ip)), func.count())
              .join(models.IpGeo, models.IpGeo.ip == A.ip).filter(no_periodo)
              .group_by(models.IpGeo.pais).order_by(func.count().desc()).limit(15).all())
    referers = (db.query(A.referer, func.count().label("hits"))
                .filter(no_periodo, A.referer.isnot(None), A.robo.is_(None),
                        ~A.referer.like("%henrique.tec.br%"), ~A.referer.like("%187.110.161.52%"))
                .group_by(A.referer).order_by(func.count().desc()).limit(12).all())
    sem_geo = db.query(func.count(distinct(A.ip))).outerjoin(models.IpGeo, models.IpGeo.ip == A.ip) \
        .filter(no_periodo, models.IpGeo.ip.is_(None)).scalar() or 0

    return {
        "periodo": periodo, "desde": desde,
        "resumo": {"acessos": tot[0] or 0, "ips": tot[1] or 0, "humanos": int(tot[2] or 0),
                   "visitantes": tot[4] or 0, "suspeitos": int(tot[3] or 0), "nao_encontrado": int(tot[5] or 0),
                   "buscadores": hits_buscadores, "ataques": sum(eventos_por_tipo.get(t, 0) for t in ATAQUES),
                   "ips_atacantes": ips_atacantes, "logins_falhos": eventos_por_tipo.get("login_falha", 0)
                   + eventos_por_tipo.get("2fa_falha", 0), "sem_geo": sem_geo},
        "eventos_por_tipo": eventos_por_tipo,
        "serie": _serie(db, periodo, desde),
        "top": top, "ips_suspeitos": ips_suspeitos, "ev_por_ip": ev_por_ip, "geos": geos,
        "eventos": eventos, "paginas": paginas, "nao_encontradas": nao_encontradas,
        "robos": robos_lista, "paises": paises, "referers": referers,
    }


def pontos_mapa(db: Session, periodo: str) -> list[dict]:
    desde = _desde(periodo)
    A, G, E = models.Acesso, models.IpGeo, models.EventoSeguranca
    ataques = dict(db.query(E.ip, func.count()).filter(E.ts >= desde, E.tipo.in_(ATAQUES)).group_by(E.ip).all())
    linhas = (db.query(A.ip, G.lat, G.lon, G.cidade, G.regiao, G.pais, G.pais_nome, G.org,
                       func.count().label("hits"), func.max(A.robo).label("robo"),
                       func.sum(case((A.suspeito.is_(True), 1), else_=0)).label("suspeitos"))
              .join(G, G.ip == A.ip).filter(A.ts >= desde, G.lat.isnot(None), G.lon.isnot(None))
              .group_by(A.ip, G.lat, G.lon, G.cidade, G.regiao, G.pais, G.pais_nome, G.org)
              .order_by(func.count().desc()).limit(3000).all())
    pontos = []
    for r in linhas:
        n_ataques = ataques.get(r.ip, 0) + int(r.suspeitos or 0)
        tipo = "ataque" if n_ataques else ("robo" if r.robo else "visitante")
        pontos.append({"ip": r.ip, "lat": r.lat, "lon": r.lon, "hits": int(r.hits), "tipo": tipo,
                       "ataques": n_ataques, "robo": r.robo,
                       "local": ", ".join(x for x in (r.cidade, r.regiao, r.pais_nome or r.pais) if x),
                       "org": r.org})
    return pontos


@router.get("/seguranca")
def pagina(request: Request, periodo: str = Query("24h"), user=Depends(admin_guard), db: Session = Depends(get_db)):
    if periodo not in PERIODOS:
        periodo = "24h"
    dados = painel(db, periodo)
    return templates.TemplateResponse(request, "admin_seguranca.html", {
        **dados, "eventos_info": EVENTOS, "periodos": list(PERIODOS), "current_user": user.username,
        "robo_confirmado": monitor.robo_confirmado, "categoria": monitor.CATEGORIA,
    })


@router.get("/seguranca/mapa.json")
def mapa(periodo: str = Query("24h"), db: Session = Depends(get_db)):
    if periodo not in PERIODOS:
        periodo = "24h"
    return {"pontos": pontos_mapa(db, periodo)}


@router.get("/seguranca/ip/{ip}")
def detalhe_ip(request: Request, ip: str, db: Session = Depends(get_db)):
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(status_code=404)
    A, E = models.Acesso, models.EventoSeguranca
    resumo = db.query(func.count(), func.min(A.ts), func.max(A.ts),
                      func.sum(case((A.suspeito.is_(True), 1), else_=0)),
                      func.count(distinct(A.caminho))).filter(A.ip == ip).one()
    acessos = db.query(A).filter(A.ip == ip).order_by(A.ts.desc()).limit(300).all()
    eventos = db.query(E).filter(E.ip == ip).order_by(E.ts.desc()).limit(200).all()
    agentes = db.query(A.user_agent, func.count()).filter(A.ip == ip).group_by(A.user_agent) \
        .order_by(func.count().desc()).limit(10).all()
    geo = db.get(models.IpGeo, ip)
    robo = next((a.robo for a in acessos if a.robo), None)
    return templates.TemplateResponse(request, "admin_seguranca_ip.html", {
        "ip": ip, "geo": geo, "acessos": acessos, "eventos": eventos, "agentes": agentes, "robo": robo,
        "confirmado": monitor.robo_confirmado(robo, geo.rdns if geo else None),
        "resumo": {"hits": resumo[0] or 0, "primeiro": resumo[1], "ultimo": resumo[2],
                   "suspeitos": int(resumo[3] or 0), "paginas": resumo[4] or 0},
        "eventos_info": EVENTOS,
    })
