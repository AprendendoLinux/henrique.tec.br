import os
import time
import logging
import urllib.parse
from fastapi import FastAPI, Request, Depends, Form, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy.exc import OperationalError
import bcrypt
import models
from database import engine, get_db

# --- CONFIGURAÇÃO DE LOG ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

# --- UTILITÁRIO DO WHATSAPP ---
def get_whatsapp_url(db: Session):
    wp = db.query(models.WhatsappConfig).first()
    if wp and wp.numero:
        numero_limpo = ''.join(filter(str.isdigit, wp.numero))
        msg = urllib.parse.quote(wp.mensagem or "")
        return f"https://api.whatsapp.com/send?phone={numero_limpo}&text={msg}"
    return None

# --- PRELOAD: VERIFICAÇÃO DE DISPONIBILIDADE DO BANCO DE DADOS ---
def wait_for_db():
    retries = 30
    while retries > 0:
        try:
            # Tenta estabelecer uma conexão real com o banco
            with engine.connect() as conn:
                logger.info("[OK] Conexão com o banco de dados estabelecida com sucesso!")
                return
        except OperationalError:
            retries -= 1
            logger.warning(f"[AGUARDANDO] Banco de dados indisponível. Retentando em 2 segundos... ({retries} tentativas restantes)")
            time.sleep(2)
    logger.error("[ERRO FATAL] Não foi possível conectar ao banco de dados após múltiplas tentativas.")
    exit(1)

# Executa a verificação ANTES de tentar criar as tabelas
wait_for_db()
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Henrique.tec.br", description="Infraestrutura e Sistemas")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

APP_VERSION = os.environ.get("APP_VERSION", "dev-local")

# --- STARTUP ---
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
        
    if not db.query(models.WhatsappConfig).first():
        wp_config = models.WhatsappConfig(numero="5500000000000", mensagem="Olá! Gostaria de falar sobre Infraestrutura e Sistemas.")
        db.add(wp_config)
        
    db.commit()

# --- ROTAS PÚBLICAS ---
@app.get("/")
async def read_root(request: Request, db: Session = Depends(get_db)):
    projetos = db.query(models.Projeto).all()
    contatos = db.query(models.Contato).limit(10).all()
    wp_url = get_whatsapp_url(db)
    return templates.TemplateResponse("index.html", {"request": request, "projetos": projetos, "contatos": contatos, "version": APP_VERSION, "whatsapp_url": wp_url})

@app.get("/servicos/linux")
async def servicos_linux(request: Request, db: Session = Depends(get_db)):
    contatos = db.query(models.Contato).limit(10).all()
    wp_url = get_whatsapp_url(db)
    return templates.TemplateResponse("linux.html", {"request": request, "contatos": contatos, "version": APP_VERSION, "whatsapp_url": wp_url})

@app.get("/servicos/mikrotik")
async def servicos_mikrotik(request: Request, db: Session = Depends(get_db)):
    contatos = db.query(models.Contato).limit(10).all()
    wp_url = get_whatsapp_url(db)
    return templates.TemplateResponse("mikrotik.html", {"request": request, "contatos": contatos, "version": APP_VERSION, "whatsapp_url": wp_url})

@app.get("/servicos/manutencao")
async def servicos_manutencao(request: Request, db: Session = Depends(get_db)):
    contatos = db.query(models.Contato).limit(10).all()
    wp_url = get_whatsapp_url(db)
    return templates.TemplateResponse("manutencao.html", {"request": request, "contatos": contatos, "version": APP_VERSION, "whatsapp_url": wp_url})

# --- ROTAS ADMIN (AUTENTICAÇÃO) ---
@app.get("/admin")
async def admin_login_page(request: Request, db: Session = Depends(get_db)):
    if request.cookies.get("session_token"):
        return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)
    
    # Busca os contatos e WhatsApp para o rodapé/botão flutuante
    contatos = db.query(models.Contato).limit(10).all()
    wp_url = get_whatsapp_url(db)
    
    return templates.TemplateResponse("admin_login.html", {
        "request": request, 
        "contatos": contatos, 
        "version": APP_VERSION, 
        "whatsapp_url": wp_url
    })

@app.post("/admin/login")
async def admin_login_post(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(models.Usuario).filter(models.Usuario.username == username).first()
    
    # Se der erro, precisa carregar os contatos novamente para a página não quebrar
    if not user or not verify_password(password, user.password_hash):
        contatos = db.query(models.Contato).limit(10).all()
        wp_url = get_whatsapp_url(db)
        return templates.TemplateResponse("admin_login.html", {
            "request": request, 
            "erro": True, 
            "contatos": contatos, 
            "version": APP_VERSION, 
            "whatsapp_url": wp_url
        })
    
    response = RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="session_token", value=user.username, httponly=True)
    return response

@app.get("/admin/logout")
async def admin_logout():
    response = RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("session_token")
    return response

# --- ROTAS ADMIN (PAINEL GERAL) ---
@app.get("/admin/dashboard")
async def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    current_user = request.cookies.get("session_token")
    if not current_user:
        return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    projetos = db.query(models.Projeto).all()
    contatos = db.query(models.Contato).limit(10).all()
    usuarios = db.query(models.Usuario).all()
    wp_config = db.query(models.WhatsappConfig).first()
    
    return templates.TemplateResponse("admin_dashboard.html", {
        "request": request, "projetos": projetos, "contatos": contatos, "usuarios": usuarios, 
        "wp_config": wp_config, "current_user": current_user, "version": APP_VERSION
    })

# --- ROTAS ADMIN (WHATSAPP) ---
@app.post("/admin/whatsapp/edit")
async def edit_whatsapp(request: Request, numero: str = Form(...), mensagem: str = Form(...), db: Session = Depends(get_db)):
    if not request.cookies.get("session_token"): return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    
    wp = db.query(models.WhatsappConfig).first()
    if wp:
        wp.numero = numero
        wp.mensagem = mensagem
    else:
        wp = models.WhatsappConfig(numero=numero, mensagem=mensagem)
        db.add(wp)
    db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

# --- ROTAS ADMIN (AÇÕES: PROJETOS, CONTATOS E USUÁRIOS) ---
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
    return templates.TemplateResponse("admin_edit_projeto.html", {"request": request, "projeto": projeto, "version": APP_VERSION})

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
    return templates.TemplateResponse("admin_edit_contato.html", {"request": request, "contato": contato, "version": APP_VERSION})

@app.post("/admin/contatos/edit/{contato_id}")
async def edit_contato_post(request: Request, contato_id: int, nome: str=Form(...), url: str=Form(...), icone: str=Form(None), cor_hover: str=Form(None), db: Session=Depends(get_db)):
    if not request.cookies.get("session_token"): return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    contato = db.query(models.Contato).filter(models.Contato.id == contato_id).first()
    if contato:
        contato.nome = nome; contato.url = url; contato.icone = icone; contato.cor_hover = cor_hover or "hover:bg-neon"
        db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

@app.post("/admin/usuarios/add")
async def add_usuario(request: Request, username: str = Form(...), password: str = Form(...), confirm_password: str = Form(...), db: Session = Depends(get_db)):
    if not request.cookies.get("session_token"): return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    if password != confirm_password: return RedirectResponse(url="/admin/dashboard?erro_user=senhas_diferentes", status_code=status.HTTP_302_FOUND)
    if not validar_senha_forte(password): return RedirectResponse(url="/admin/dashboard?erro_user=senha_fraca", status_code=status.HTTP_302_FOUND)
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
        db.delete(usuario); db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

@app.get("/admin/usuarios/edit/{usuario_id}")
async def edit_usuario_page(request: Request, usuario_id: int, db: Session = Depends(get_db)):
    if not request.cookies.get("session_token"): return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    usuario = db.query(models.Usuario).filter(models.Usuario.id == usuario_id).first()
    if not usuario or usuario.username == 'admin': return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("admin_edit_usuario.html", {"request": request, "usuario": usuario, "version": APP_VERSION})

@app.post("/admin/usuarios/edit/{usuario_id}")
async def edit_usuario_post(request: Request, usuario_id: int, password: str = Form(...), confirm_password: str = Form(...), db: Session = Depends(get_db)):
    if not request.cookies.get("session_token"): return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)
    if password != confirm_password: return RedirectResponse(url=f"/admin/usuarios/edit/{usuario_id}?erro=senhas_diferentes", status_code=status.HTTP_302_FOUND)
    if not validar_senha_forte(password): return RedirectResponse(url=f"/admin/usuarios/edit/{usuario_id}?erro=senha_fraca", status_code=status.HTTP_302_FOUND)
    usuario = db.query(models.Usuario).filter(models.Usuario.id == usuario_id).first()
    if usuario and usuario.username != 'admin':
        usuario.password_hash = get_password_hash(password)
        db.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_302_FOUND)

# --- ROTAS SEO ---
@app.get("/robots.txt")
async def robots(request: Request):
    return templates.TemplateResponse("robots.txt", {"request": request}, media_type="text/plain")

@app.get("/sitemap.xml")
async def sitemap(request: Request):
    return templates.TemplateResponse("sitemap.xml", {"request": request}, media_type="application/xml")