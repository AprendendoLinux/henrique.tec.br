FROM python:3.11-slim

WORKDIR /app

ARG APP_VERSION=dev-local
ENV APP_VERSION=${APP_VERSION} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && rm requirements.txt

COPY . .

RUN useradd --system --no-create-home app && chown -R app /app
USER app

EXPOSE 8000

# Escuta em IPv6 e IPv4 na mesma porta (a rede echelon resolve os contêineres primeiro em IPv6)
CMD ["python", "servidor.py"]
