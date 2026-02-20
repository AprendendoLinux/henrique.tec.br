import os
from fastapi import FastAPI, Request, Depends, Form, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
import bcrypt
import models
from database import engine, get_db

# --- FUNÇÕES DE CRIPTOGRAFIA E VALIDAÇÃO ---
def get_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode('utf-8'), 
        hashed_password.encode('utf-8')
    )

def validar_senha_forte(senha: str) -> bool:
    if len(senha) < 8: return False
    if not any(c.isupper() for c in senha): return False
    if not any(c.isdigit() for c in senha): return False
    if not any(not c.isalnum() for c in senha): return False
    return True

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Henrique.tec.br", description="Infraestrutura e Sistemas")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# --- STARTUP: BLINDAGEM DO ADMIN VIA DOCKER ---
@app.on_event("startup")
def startup_event():
    db = next(get_db())
    admin_pwd = os.environ.get("ADMIN_PASSWORD", "admin") 
    
    admin_user = db.query(models.Usuario).filter(models.Usuario.username == "admin").first()
    if not admin_user:
        admin_user = models.Usuario(username="admin", password_hash=get_password_hash(admin_pwd))
        db.add(admin_user)
    else:
        admin_user.password_hash = get_password_hash(admin_pwd)
    db.commit()

# --- ROTAS PÚBLICAS ---
@app.get("/")
async def read_root(request: Request, db: Session = Depends(get_db)):
    projetos = db.query(models.Projeto).all()
    contatos = db.query(models.Contato).limit(10).all()
    return templates.TemplateResponse("index.html", {"request": request, "projetos": projetos, "contatos": contatos})

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

# --- ROTAS ADMIN (AUTENTICAÇÃO) ---
@app.get("/admin")
async def admin_login_page(request: Request):
    if request.cookies.get("session_token"):
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("admin_login.html", {"request": request})

@app.post("/admin/login")
async def admin_login_post(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(models.Usuario).filter(models.Usuario.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("admin_login.html", {"request": request, "erro": True})
    
    response = RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="session_token", value=user.username, httponly=True)
    return response

@app.get("/admin/logout")
async def admin_logout():
    response = RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("session_token")
    return response

# --- ROTAS ADMIN (PAINEL E PROJETOS/CONTATOS INALTERADOS) ---
@app.get("/admin/dashboard")
async def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    current_user = request.cookies.get("session_token")
    if not current_user:
        return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    projetos = db.query(models.Projeto).all()
    contatos = db.query(models.Contato).limit(10).all()
    usuarios = db.query(models.Usuario).all()
    
    return templates.TemplateResponse("admin_dashboard.html", {
        "request": request, "projetos": projetos, "contatos": contatos, "usuarios": usuarios, "current_user": current_user
    })

@app.post("/admin/projetos/add")
async def add_projeto(request: Request, titulo: str = Form(...), descricao: str = Form(...), categoria: str = Form(...), link_projeto: str = Form(None), link_github: str = Form(None), db: Session = Depends(get_db)):
    if not request.cookies.get("session_token"): return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    novo_projeto = models.Projeto(titulo=titulo, descricao=descricao, categoria=categoria, link_projeto=link_projeto, link_github=link_github)
    db.add(novo_projeto)
    db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

@app.get("/admin/projetos/delete/{projeto_id}")
async def delete_projeto(request: Request, projeto_id: int, db: Session = Depends(get_db)):
    if not request.cookies.get("session_token"): return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    projeto = db.query(models.Projeto).filter(models.Projeto.id == projeto_id).first()
    if projeto: db.delete(projeto); db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

@app.get("/admin/projetos/edit/{projeto_id}")
async def edit_projeto_page(request: Request, projeto_id: int, db: Session = Depends(get_db)):
    if not request.cookies.get("session_token"): return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    projeto = db.query(models.Projeto).filter(models.Projeto.id == projeto_id).first()
    if not projeto: return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("admin_edit_projeto.html", {"request": request, "projeto": projeto})

@app.post("/admin/projetos/edit/{projeto_id}")
async def edit_projeto_post(request: Request, projeto_id: int, titulo: str=Form(...), descricao: str=Form(...), categoria: str=Form(...), link_projeto: str=Form(None), link_github: str=Form(None), db: Session=Depends(get_db)):
    if not request.cookies.get("session_token"): return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    projeto = db.query(models.Projeto).filter(models.Projeto.id == projeto_id).first()
    if projeto:
        projeto.titulo = titulo; projeto.descricao = descricao; projeto.categoria = categoria; projeto.link_projeto = link_projeto; projeto.link_github = link_github
        db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

@app.post("/admin/contatos/add")
async def add_contato(request: Request, nome: str = Form(...), url: str = Form(...), icone: str = Form(None), cor_hover: str = Form(None), db: Session = Depends(get_db)):
    if not request.cookies.get("session_token"): return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    if db.query(models.Contato).count() < 10:
        novo_contato = models.Contato(nome=nome, url=url, icone=icone, cor_hover=cor_hover or "hover:bg-neon")
        db.add(novo_contato)
        db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

@app.get("/admin/contatos/delete/{contato_id}")
async def delete_contato(request: Request, contato_id: int, db: Session = Depends(get_db)):
    if not request.cookies.get("session_token"): return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    contato = db.query(models.Contato).filter(models.Contato.id == contato_id).first()
    if contato: db.delete(contato); db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

@app.get("/admin/contatos/edit/{contato_id}")
async def edit_contato_page(request: Request, contato_id: int, db: Session = Depends(get_db)):
    if not request.cookies.get("session_token"): return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    contato = db.query(models.Contato).filter(models.Contato.id == contato_id).first()
    if not contato: return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("admin_edit_contato.html", {"request": request, "contato": contato})

@app.post("/admin/contatos/edit/{contato_id}")
async def edit_contato_post(request: Request, contato_id: int, nome: str=Form(...), url: str=Form(...), icone: str=Form(None), cor_hover: str=Form(None), db: Session=Depends(get_db)):
    if not request.cookies.get("session_token"): return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    contato = db.query(models.Contato).filter(models.Contato.id == contato_id).first()
    if contato:
        contato.nome = nome; contato.url = url; contato.icone = icone; contato.cor_hover = cor_hover or "hover:bg-neon"
        db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

# --- ROTAS ADMIN (AÇÕES: UTILIZADORES COM NOVAS REGRAS) ---
@app.post("/admin/usuarios/add")
async def add_usuario(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    if not request.cookies.get("session_token"): return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    if password != confirm_password:
        return RedirectResponse(url="/admin/dashboard?erro_user=senhas_diferentes", status_code=status.HTTP_302_FOUND)
        
    if not validar_senha_forte(password):
        return RedirectResponse(url="/admin/dashboard?erro_user=senha_fraca", status_code=status.HTTP_302_FOUND)

    existe = db.query(models.Usuario).filter(models.Usuario.username == username).first()
    if not existe:
        novo_usuario = models.Usuario(username=username, password_hash=get_password_hash(password))
        db.add(novo_usuario)
        db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

@app.get("/admin/usuarios/delete/{usuario_id}")
async def delete_usuario(request: Request, usuario_id: int, db: Session = Depends(get_db)):
    current_user = request.cookies.get("session_token")
    if not current_user: return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    usuario = db.query(models.Usuario).filter(models.Usuario.id == usuario_id).first()
    
    if usuario and usuario.username != 'admin' and usuario.username != current_user:
        db.delete(usuario)
        db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

@app.get("/admin/usuarios/edit/{usuario_id}")
async def edit_usuario_page(request: Request, usuario_id: int, db: Session = Depends(get_db)):
    if not request.cookies.get("session_token"): return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    usuario = db.query(models.Usuario).filter(models.Usuario.id == usuario_id).first()
    if not usuario or usuario.username == 'admin':
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)
        
    return templates.TemplateResponse("admin_edit_usuario.html", {"request": request, "usuario": usuario})

@app.post("/admin/usuarios/edit/{usuario_id}")
async def edit_usuario_post(
    request: Request,
    usuario_id: int,
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    if not request.cookies.get("session_token"): return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    if password != confirm_password:
        return RedirectResponse(url=f"/admin/usuarios/edit/{usuario_id}?erro=senhas_diferentes", status_code=status.HTTP_302_FOUND)
        
    if not validar_senha_forte(password):
        return RedirectResponse(url=f"/admin/usuarios/edit/{usuario_id}?erro=senha_fraca", status_code=status.HTTP_302_FOUND)

    usuario = db.query(models.Usuario).filter(models.Usuario.id == usuario_id).first()
    if usuario and usuario.username != 'admin':
        usuario.password_hash = get_password_hash(password)
        db.commit()
        
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)