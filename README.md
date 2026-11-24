# 🌐 Henrique.tec.br - Infraestrutura e Sistemas

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-2CA5E0?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)

Portfólio dinâmico e painel administrativo para exibição de serviços de Engenharia de Infraestrutura, administração de Servidores Linux, Redes MikroTik e Suporte Técnico Especializado.

Identidade visual "Terminal/Hacker" com Glassmorphism, backend FastAPI, configuração 100% pelo painel admin e provisionamento via Docker.

---

## 🚀 Principais Funcionalidades

### 🖥️ Front-end (Público)
* **Design Glassmorphism** responsivo (Tailwind CSS), com `backdrop-filter` otimizado para iOS/Safari.
* **Páginas de Serviços:** Linux, Firewall/MikroTik, Desktop, Docker, Virtualização e Desenvolvimento.
* **Projetos Dinâmicos:** grade alimentada pelo banco de dados.
* **Formulário de Orçamento (`/contato`):** nome, e-mail, telefone, serviço, prazo e mensagem, com proteção contra spam (reCAPTCHA opcional, campo-isca, tempo mínimo de preenchimento e limite de envios por IP).
* **Chamadas para contato levam ao formulário:** os botões das páginas de serviço abrem `/contato?servico=<slug>` com o serviço já selecionado; o WhatsApp fica apenas no botão flutuante.
* **Botões flutuantes de WhatsApp e Telegram:** cada um aparece apenas se habilitado no painel. Com apenas um ativo, ele ocupa a posição original; com os dois, o Telegram fica acima do WhatsApp.
* **Base de Conhecimento (`/conhecimento`):** lista e exibe, dentro do site, as páginas do livro público da wiki BookStack, ordenadas por data de publicação (mais recentes primeiro), com botões para ordenar por mais antigos, atualizados ou A-Z e paginação de 12 em 12. A busca procura no título **e no conteúdo** dos artigos (sem diferenciar acentos/maiúsculas, exigindo todas as palavras) e mostra o trecho encontrado com destaque; o texto fica indexado em memória e só é baixado de novo quando o artigo é atualizado na wiki, lidas pela API pela rede interna (`http://bookstack` na rede echelon, configurável) com cache de 30 s; se a wiki cair, serve o último conteúdo obtido). O HTML é sanitizado, links entre páginas do livro viram links do site e os artigos entram no `sitemap.xml`. Configurada no painel (URL, slug do livro e token da API); o link `./conhecimento` só aparece no menu quando está configurada.
* **Logo em estilo terminal** `~/henrique.tec.br_` com cursor piscando, igual ao da wiki.
* **Rodapé dinâmico** com redes sociais configuráveis e botão "Solicitar orçamento".
* **SEO & Open Graph:** `sitemap.xml` e `robots.txt` dinâmicos e card `social-card.jpg`.

### 📩 Recebimento de Orçamentos
* **E-mail (SMTP):** o pedido chega com `Reply-To` apontando para o e-mail informado pelo visitante.
* **Telegram:** o mesmo pedido é enviado pelo bot. O pedido é aceito se ao menos um canal entregar.
* **Detalhes do IP do visitante** (IPv4 e IPv6) no corpo da mensagem: DNS reverso (com confirmação), provedor, ASN, geolocalização aproximada, fuso, registro RDAP/WHOIS (rede, CIDR, titular e contatos de abuso) e indicadores de reputação. O IP público é obtido de `CF-Connecting-IP`, `X-Real-IP` ou `X-Forwarded-For`, **somente** quando a conexão vem de um proxy de confiança.
* SMTP com as opções: `587 STARTTLS + login`, `465 SSL/TLS + login` ou `25 relay sem autenticação`.

### 🔒 Back-end e Painel Admin (`/admin`)
* **Autenticação:** sessão em cookie assinado (HttpOnly, SameSite, Secure automático em HTTPS), senhas com `bcrypt` e **2FA (TOTP) obrigatório para todos os usuários**, inclusive o admin. Segredos TOTP armazenados criptografados.
* **Proteções:** token CSRF em todo `POST`, ações destrutivas apenas via `POST`, limite de tentativas no login e no 2FA, validação de URLs, ícones e cores, e cabeçalhos de segurança.
* **Perfis:** o usuário principal `admin` é sempre administrador e protegido. Qualquer admin pode **tornar outro usuário admin** (ou remover a permissão), gerenciar usuários e alterar configurações. Usuários comuns gerenciam apenas conteúdo (projetos, contatos, WhatsApp, Telegram) e a própria senha.
* **Configurações pelo painel (salvas no banco):** SMTP, bot do Telegram, reCAPTCHA, Base de Conhecimento (BookStack), proxies de confiança, cabeçalhos de IP e cookies seguros, com botões de teste de e-mail e Telegram. Senhas e tokens ficam **criptografados** no banco.
* **Minha Conta:** troca de senha pelo próprio usuário.
* **Gerenciamento de conteúdo:** CRUD de Projetos e Contatos do rodapé, WhatsApp (número, mensagem e exibição) e Telegram (usuário e exibição).

### ⚙️ DevOps & Infraestrutura
* **Docker Compose** com MySQL 8 (healthcheck), sem exposição da porta do banco, e aplicação rodando sem root.
* **Migrations (Alembic)** executadas automaticamente no startup; bancos já existentes são preservados.
* **CI/CD:** GitHub Actions executa os testes e publica a imagem no GHCR (`dev-latest` na branch `dev`; `latest` e `vX.Y.Z` somente em tags `v*.*.*`). O deploy de produção é feito pelo Portainer após a release.
* **Versionamento dinâmico:** `APP_VERSION` injetada no build e exibida no rodapé.

---

## 🛠️ Stack Tecnológica

* **Back-end:** Python 3.11, FastAPI, SQLAlchemy, Alembic, Bcrypt, PyOTP.
* **Front-end:** HTML5, Jinja2, Tailwind CSS (CDN), FontAwesome 6, JavaScript.
* **Banco de Dados:** MySQL 8 / MariaDB (produção) e SQLite (testes).
* **Infra:** Docker, Docker Compose, GitHub Actions, GHCR, Portainer.

---

## 🚀 Como Rodar

1. Ajuste as credenciais do banco no `docker-compose.yml` (`DB_PASSWORD`, `MYSQL_PASSWORD`, `MYSQL_ROOT_PASSWORD`).
2. Suba o ambiente:

```bash
docker compose up -d --build
```

3. **Primeiro acesso:** a senha inicial do usuário `admin` é gerada aleatoriamente e exibida **uma única vez** nos logs:

```bash
docker compose logs app | grep "senha inicial"
```

Acesse `/admin`, configure o 2FA e troque a senha em **Minha Conta**. Depois configure SMTP, Telegram e reCAPTCHA na aba **Configurações**.

### Variáveis de ambiente

No `docker-compose.yml` ficam **apenas** as do banco. Todo o restante é configurado no painel.

| Variável | Descrição |
|---|---|
| `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_NAME` | Conexão com o banco |
| `DB_PASSWORD` | Senha do banco. **Também protege os segredos salvos no banco**: trocá-la exige reconfigurá-los |

> Atualizando uma instalação antiga: variáveis legadas (`SMTP_*`, `TELEGRAM_*`, `RECAPTCHA_*`, `SECRET_KEY`, `COOKIE_SECURE`, `TRUSTED_PROXIES`, `CLIENT_IP_HEADERS`) são importadas para o banco **uma única vez**, apenas para chaves ainda não configuradas. Depois, podem ser removidas do compose.

### Proxy reverso e IP do visitante

O IP real só é aceito de proxies listados em **Configurações → Rede** (padrão: redes privadas e loopback). Se o app receber tráfego direto do Cloudflare, inclua as faixas dele. Acessos locais mostram o IP do Docker, que não é público.

### Recuperação de acesso

```bash
docker compose exec app python manage.py reset-admin-password   # nova senha do admin
docker compose exec app python manage.py reset-admin-2fa        # zera o 2FA do admin
docker compose exec app python manage.py disable-recaptcha      # desliga o reCAPTCHA
```

### Testes

```bash
pip install -r requirements-dev.txt
pytest -q
```

---

## 📂 Estrutura de Diretórios

```text
├── app.py                  # Aplicação (lifespan, middlewares, handlers, seed)
├── config.py               # Constantes estáticas (versão, tempos)
├── appsettings.py          # Configurações salvas no banco (cache + criptografia)
├── session.py              # Sessão assinada com chave e flag Secure dinâmicas
├── security.py             # Senhas, CSRF, rate limit, IP do cliente, validações
├── deps.py                 # Dependências, contexto dos templates, reCAPTCHA
├── mailer.py               # Envio de e-mail (SMTP 587/465/25)
├── notify.py               # Notificação via Telegram
├── ipinfo.py               # Detalhes do IP (rDNS, geolocalização, ASN, RDAP)
├── manage.py               # Comandos de recuperação
├── database.py / models.py # Engine e modelos SQLAlchemy
├── routers/                # public, auth, admin e contact
├── migrations/             # Alembic (versions/0001 ... 0006)
├── tests/                  # Testes automatizados (pytest)
├── docker-compose.yml      # Orquestração (somente configurações do banco)
├── Dockerfile              # Imagem da aplicação
├── static/                 # Assets (social-card.jpg, ícones)
└── templates/              # base, index, serviços, contato, admin_*, SEO
```

## 🔄 Deploy

* **Desenvolvimento:** roda localmente no host com `docker compose`, na rede `echelon`, usando o banco `henrique_dev` do `db-server` (réplica dos dados de produção).
* **Produção** (fluxo de publicação):
  1. Pull Request `dev` → `main` e merge.
  2. Tag `vX.Y.Z` na `main`: o GitHub Actions roda os testes e publica a imagem no GHCR (`latest` + `vX.Y.Z`).
  3. Release no GitHub com as notas da versão.
  4. Deploy pelo Portainer na stack `henrique-tec-br`, baixando a imagem nova (sem webhooks).
