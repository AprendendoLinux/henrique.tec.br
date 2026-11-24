from sqlalchemy import BigInteger, Boolean, Column, DateTime, Float, Integer, SmallInteger, String, Text
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
    cor_icone = Column(String(50), default="text-gray-400") # Nova linha aqui
    cor_hover = Column(String(50))

class Usuario(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    password_hash = Column(String(255))
    totp_secret = Column(String(255), nullable=True)    # Semente TOTP criptografada (Fernet)
    is_2fa_enabled = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False, nullable=False)     # Marca se ele já confirmou o código

class TelegramConfig(Base):
    __tablename__ = "telegram_config"
    id = Column(Integer, primary_key=True, index=True)
    usuario = Column(String(64), nullable=True)
    ativo = Column(Boolean, default=False, nullable=False)

class WhatsappConfig(Base):
    __tablename__ = "whatsapp_config"
    id = Column(Integer, primary_key=True, index=True)
    numero = Column(String(50))
    mensagem = Column(String(255))
    ativo = Column(Boolean, default=True, nullable=False)

class Setting(Base):
    __tablename__ = "app_settings"
    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=True)
    is_secret = Column(Boolean, default=False, nullable=False)


# --- Monitoramento de acessos e segurança (painel /admin/seguranca) ---
class Acesso(Base):
    __tablename__ = "acessos"
    id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    ts = Column(DateTime, nullable=False, index=True)
    ip = Column(String(45), nullable=False, index=True)
    metodo = Column(String(8), nullable=False)
    caminho = Column(String(300), nullable=False)
    status = Column(SmallInteger, nullable=False)
    ms = Column(Integer, nullable=False, default=0)
    user_agent = Column(String(300), nullable=True)
    referer = Column(String(300), nullable=True)
    robo = Column(String(40), nullable=True, index=True)
    suspeito = Column(Boolean, nullable=False, default=False, index=True)


class EventoSeguranca(Base):
    __tablename__ = "eventos_seguranca"
    id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    ts = Column(DateTime, nullable=False, index=True)
    ip = Column(String(45), nullable=False, index=True)
    tipo = Column(String(30), nullable=False, index=True)
    usuario = Column(String(50), nullable=True)
    caminho = Column(String(300), nullable=True)
    detalhe = Column(String(300), nullable=True)


class IpGeo(Base):
    __tablename__ = "ip_geo"
    ip = Column(String(45), primary_key=True)
    pais = Column(String(2), nullable=True)
    pais_nome = Column(String(80), nullable=True)
    regiao = Column(String(80), nullable=True)
    cidade = Column(String(80), nullable=True)
    lat = Column(Float, nullable=True)
    lon = Column(Float, nullable=True)
    org = Column(String(120), nullable=True)
    rdns = Column(String(255), nullable=True)
    fonte = Column(String(20), nullable=True)
    atualizado = Column(DateTime, nullable=False)
