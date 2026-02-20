from fastapi import FastAPI, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import models
from database import engine, get_db

# Garante que as novas tabelas existam no banco
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Henrique.tec.br", description="Infraestrutura e Sistemas")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/")
async def read_root(request: Request, db: Session = Depends(get_db)):
    projetos = db.query(models.Projeto).all()
    contatos = db.query(models.Contato).limit(10).all() # Limite de 10 botões
    return templates.TemplateResponse(
        "index.html", 
        {"request": request, "projetos": projetos, "contatos": contatos}
    )

@app.get("/servicos/linux")
async def servicos_linux(request: Request, db: Session = Depends(get_db)):
    contatos = db.query(models.Contato).limit(10).all()
    return templates.TemplateResponse("linux.html", {"request": request, "contatos": contatos})

@app.get("/servicos/mikrotik")
async def servicos_mikrotik(request: Request, db: Session = Depends(get_db)):
    contatos = db.query(models.Contato).limit(10).all()
    return templates.TemplateResponse("mikrotik.html", {"request": request, "contatos": contatos})

@app.get("/servicos/manutencao")
async def servicos_manutencao(request: Request, db: Session = Depends(get_db)):
    contatos = db.query(models.Contato).limit(10).all()
    return templates.TemplateResponse("manutencao.html", {"request": request, "contatos": contatos})

@app.get("/admin")
async def admin_dashboard(request: Request):
    # Em breve: Verificação de login e renderização do painel
    return templates.TemplateResponse("admin_login.html", {"request": request})