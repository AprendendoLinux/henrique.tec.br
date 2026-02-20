from sqlalchemy import Column, Integer, String
from database import Base

class Projeto(Base):
    __tablename__ = "projetos"

    id = Column(Integer, primary_key=True, index=True)
    # Limites definidos para manter os cards simétricos
    titulo = Column(String(60), index=True) 
    descricao = Column(String(160)) 
    categoria = Column(String(50))
    # Links opcionais para os botões
    link_projeto = Column(String(255), nullable=True)
    link_github = Column(String(255), nullable=True)

class Contato(Base):
    __tablename__ = "contatos"

    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String(50))       # Ex: WhatsApp
    url = Column(String(255))       # Ex: https://wa.me/...
    icone = Column(String(50))      # Ex: 📱 ou tag <i>
    cor_hover = Column(String(50))  # Ex: hover:bg-green-500