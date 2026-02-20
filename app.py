from fastapi import FastAPI, Request, Depends, Form, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
import bcrypt
import models
from database import engine, get_db

# --- FUNÇÕES DE CRIPTOGRAFIA ---
def get_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode('utf-8'), 
        hashed_password.encode('utf-8')
    )

# Garante que as tabelas existam na base de dados
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Henrique.tec.br", description="Infraestrutura e Sistemas")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# --- POPULAR BASE DE DADOS INICIAL ---
@app.on_event("startup")
def startup_event():
    db = next(get_db())
    # Cria o utilizador admin se a tabela estiver vazia
    if not db.query(models.Usuario).first():
        admin_user = models.Usuario(
            username="admin", 
            password_hash=get_password_hash("admin")
        )
        db.add(admin_user)
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
async def admin_login_post(
    request: Request, 
    username: str = Form(...), 
    password: str = Form(...), 
    db: Session = Depends(get_db)
):
    user = db.query(models.Usuario).filter(models.Usuario.username == username).first()
    
    # Valida utilizador e palavra-passe
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("admin_login.html", {"request": request, "erro": True})
    
    # Login com sucesso
    response = RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="session_token", value=user.username, httponly=True)
    return response

@app.get("/admin/logout")
async def admin_logout():
    response = RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("session_token")
    return response

# --- ROTAS ADMIN (PAINEL) ---
@app.get("/admin/dashboard")
async def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    if not request.cookies.get("session_token"):
        return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    # Puxa os dados para preencher as tabelas no painel
    projetos = db.query(models.Projeto).all()
    contatos = db.query(models.Contato).limit(10).all()
    usuarios = db.query(models.Usuario).all()
    
    return templates.TemplateResponse(
        "admin_dashboard.html", 
        {"request": request, "projetos": projetos, "contatos": contatos, "usuarios": usuarios}
    )

# --- ROTAS ADMIN (AÇÕES: PROJETOS) ---
@app.post("/admin/projetos/add")
async def add_projeto(
    request: Request,
    titulo: str = Form(...),
    descricao: str = Form(...),
    categoria: str = Form(...),
    link_projeto: str = Form(None),
    link_github: str = Form(None),
    db: Session = Depends(get_db)
):
    if not request.cookies.get("session_token"):
        return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    novo_projeto = models.Projeto(
        titulo=titulo,
        descricao=descricao,
        categoria=categoria,
        link_projeto=link_projeto if link_projeto else None,
        link_github=link_github if link_github else None
    )
    db.add(novo_projeto)
    db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

@app.get("/admin/projetos/delete/{projeto_id}")
async def delete_projeto(request: Request, projeto_id: int, db: Session = Depends(get_db)):
    if not request.cookies.get("session_token"):
        return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    projeto = db.query(models.Projeto).filter(models.Projeto.id == projeto_id).first()
    if projeto:
        db.delete(projeto)
        db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

# --- ROTAS ADMIN (AÇÕES: EDITAR PROJETOS) ---
@app.get("/admin/projetos/edit/{projeto_id}")
async def edit_projeto_page(request: Request, projeto_id: int, db: Session = Depends(get_db)):
    if not request.cookies.get("session_token"):
        return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    projeto = db.query(models.Projeto).filter(models.Projeto.id == projeto_id).first()
    if not projeto:
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)
        
    return templates.TemplateResponse("admin_edit_projeto.html", {"request": request, "projeto": projeto})

@app.post("/admin/projetos/edit/{projeto_id}")
async def edit_projeto_post(
    request: Request,
    projeto_id: int,
    titulo: str = Form(...),
    descricao: str = Form(...),
    categoria: str = Form(...),
    link_projeto: str = Form(None),
    link_github: str = Form(None),
    db: Session = Depends(get_db)
):
    if not request.cookies.get("session_token"):
        return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    projeto = db.query(models.Projeto).filter(models.Projeto.id == projeto_id).first()
    if projeto:
        projeto.titulo = titulo
        projeto.descricao = descricao
        projeto.categoria = categoria
        projeto.link_projeto = link_projeto if link_projeto else None
        projeto.link_github = link_github if link_github else None
        db.commit()
        
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

# --- ROTAS ADMIN (AÇÕES: CONTACTOS) ---
@app.post("/admin/contatos/add")
async def add_contato(
    request: Request,
    nome: str = Form(...),
    url: str = Form(...),
    icone: str = Form(None),
    cor_hover: str = Form(None),
    db: Session = Depends(get_db)
):
    if not request.cookies.get("session_token"):
        return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    # Limita o número de contactos a 10
    if db.query(models.Contato).count() >= 10:
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)
        
    novo_contato = models.Contato(
        nome=nome,
        url=url,
        icone=icone if icone else None,
        cor_hover=cor_hover if cor_hover else "hover:bg-neon"
    )
    db.add(novo_contato)
    db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

@app.get("/admin/contatos/delete/{contato_id}")
async def delete_contato(request: Request, contato_id: int, db: Session = Depends(get_db)):
    if not request.cookies.get("session_token"):
        return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    contato = db.query(models.Contato).filter(models.Contato.id == contato_id).first()
    if contato:
        db.delete(contato)
        db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

# --- ROTAS ADMIN (AÇÕES: EDITAR CONTACTOS) ---
@app.get("/admin/contatos/edit/{contato_id}")
async def edit_contato_page(request: Request, contato_id: int, db: Session = Depends(get_db)):
    if not request.cookies.get("session_token"):
        return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    contato = db.query(models.Contato).filter(models.Contato.id == contato_id).first()
    if not contato:
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)
        
    return templates.TemplateResponse("admin_edit_contato.html", {"request": request, "contato": contato})

@app.post("/admin/contatos/edit/{contato_id}")
async def edit_contato_post(
    request: Request,
    contato_id: int,
    nome: str = Form(...),
    url: str = Form(...),
    icone: str = Form(None),
    cor_hover: str = Form(None),
    db: Session = Depends(get_db)
):
    if not request.cookies.get("session_token"):
        return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    contato = db.query(models.Contato).filter(models.Contato.id == contato_id).first()
    if contato:
        contato.nome = nome
        contato.url = url
        contato.icone = icone if icone else None
        contato.cor_hover = cor_hover if cor_hover else "hover:bg-neon"
        db.commit()
        
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

# --- ROTAS ADMIN (AÇÕES: UTILIZADORES) ---
@app.post("/admin/usuarios/add")
async def add_usuario(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    if not request.cookies.get("session_token"):
        return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    # Valida se o utilizador já existe
    existe = db.query(models.Usuario).filter(models.Usuario.username == username).first()
    if not existe:
        novo_usuario = models.Usuario(
            username=username,
            password_hash=get_password_hash(password)
        )
        db.add(novo_usuario)
        db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

@app.get("/admin/usuarios/delete/{usuario_id}")
async def delete_usuario(request: Request, usuario_id: int, db: Session = Depends(get_db)):
    if not request.cookies.get("session_token"):
        return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    usuario = db.query(models.Usuario).filter(models.Usuario.id == usuario_id).first()
    
    # Impede a exclusão do utilizador mestre "admin"
    if usuario and usuario.username != 'admin':
        db.delete(usuario)
        db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)