from sqlalchemy import Column, Integer, String, Boolean
from database import Base

class Projeto(Base):
    __tablename__ = "projetos"
    id = Column(Integer, primary_key=True, index=True)
    titulo = Column(String(60), index=True) 
    descricao = Column(String(160)) 
    categoria = Column(String(50))
    link_projeto = Column(String(255), nullable=True)
    link_github = Column(String(255), nullable=True)

class Contato(Base):
    __tablename__ = "contatos"
    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String(50))
    url = Column(String(255))
    icone = Column(String(50))
    cor_hover = Column(String(50))

class Usuario(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    password_hash = Column(String(255))
    totp_secret = Column(String(32), nullable=True)     # Guarda a semente do Google Authenticator
    is_2fa_enabled = Column(Boolean, default=False)     # Marca se ele já confirmou o código

class WhatsappConfig(Base):
    __tablename__ = "whatsapp_config"
    id = Column(Integer, primary_key=True, index=True)
    numero = Column(String(50))
    mensagem = Column(String(255))