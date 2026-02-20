FROM python:3.11-slim

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Evita a criação de arquivos .pyc e força o log no terminal (sem buffer)
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Instala as dependências
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o restante do código para dentro do container
COPY . .

# Expõe a porta que a aplicação vai rodar
EXPOSE 8000

# O comando padrão será sobrescrito no docker-compose para o ambiente de dev
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]