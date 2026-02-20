import os
import re
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import models

# 1. Configuração da Conexão (Lendo as variáveis do Docker)
DB_USER = os.getenv("DB_USER", "henrique")
DB_PASSWORD = os.getenv("DB_PASSWORD", "senha_segura")
DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_NAME = os.getenv("DB_NAME", "henriquetec")

SQLALCHEMY_DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# >>> ADICIONE ESTA LINHA <<<
# Ela instrui o MySQL a criar a tabela com base no models.py, caso ela não exista
models.Base.metadata.create_all(bind=engine)

def limpar_texto_wp(texto_bruto):
    if not texto_bruto:
        return ""
    # Remove blocos de comentário do editor Gutenberg do WP (ex: )
    texto = re.sub(r'', '', texto_bruto)
    # Remove shortcodes antigos
    texto = re.sub(r'\[.*?\]', '', texto)
    # Remove tags HTML padrão
    texto = re.sub(r'<.*?>', ' ', texto)
    # Remove excesso de espaços em branco e quebras de linha
    texto = re.sub(r'\s+', ' ', texto)
    return texto.strip()

def migrar_dados():
    db = SessionLocal()
    try:
        # 2. Busca posts e páginas publicados da tabela antiga do WP
        query = text("""
            SELECT post_title, post_content, post_type 
            FROM wp_posts 
            WHERE post_status = 'publish' 
            AND post_type IN ('post', 'page')
        """)
        
        resultados = db.execute(query)
        
        contador = 0
        for linha in resultados:
            titulo = linha[0]
            conteudo_completo = linha[1]
            tipo = linha[2]
            
            # Limpa e sanitiza o texto do banco de dados antigo
            descricao_limpa = limpar_texto_wp(conteudo_completo)
            
            # Ignora registos vazios
            if not titulo or not descricao_limpa:
                continue
                
            # Classifica com base no tipo de postagem do WordPress
            categoria = "Artigo" if tipo == 'post' else "Serviço"
            
            # 3. Formata a string para não quebrar o design (ex: pega os primeiros 200 caracteres)
            descricao_resumida = descricao_limpa if len(descricao_limpa) < 200 else descricao_limpa[:200] + "..."
            
            # 4. Insere no novo modelo SQLAlchemy
            novo_registro = models.Projeto(
                titulo=titulo,
                descricao=descricao_resumida,
                categoria=categoria,
                link="#"
            )
            
            db.add(novo_registro)
            contador += 1
            
        db.commit()
        print(f"\\n>_ [SUCESSO] {contador} registos foram migrados do WordPress para o novo formato!")
        
    except Exception as e:
        print(f"\\n>_ [ERRO] Ocorreu uma falha na migração: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    print(">_ Iniciando protocolo de migração de dados...")
    migrar_dados()