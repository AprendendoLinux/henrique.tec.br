# 🌐 Henrique.tec.br - Infraestrutura e Sistemas

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-2CA5E0?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)

Portfólio dinâmico e painel administrativo desenvolvido para exibição de serviços de Engenharia de Infraestrutura, administração de Servidores Linux, Redes MikroTik e Suporte Técnico Especializado. 

O sistema possui uma identidade visual única no estilo "Terminal/Hacker" utilizando Glassmorphism, além de um backend blindado com FastAPI e provisionamento 100% via Docker.

---

## 🚀 Principais Funcionalidades

### 🖥️ Front-end (Público)
* **Design Glassmorphism:** Interface fluida e responsiva baseada em Tailwind CSS com efeito de vidro (`backdrop-filter`) otimizado para iOS/Safari.
* **Páginas de Serviços:** Detalhamento técnico para Servidores Linux, Redes MikroTik e Manutenção de Hardware.
* **Projetos Dinâmicos:** Grade de projetos ativos alimentada diretamente pelo banco de dados.
* **Rodapé Dinâmico:** Botões de contato e redes sociais com renderização condicional de ícones (FontAwesome) e cores (Hover).
* **WhatsApp Flutuante:** Botão de contato rápido integrado a todas as páginas com animação CSS personalizada.
* **SEO & Open Graph Automáticos:** Rotas dinâmicas geram o `sitemap.xml` e `robots.txt` com URLs absolutas nativas baseadas no domínio atual (`request.base_url`), além de um card `card.jpg` renderizado para compartilhamento em redes sociais.

### 🔒 Back-end e Painel Admin (`/admin`)
* **Autenticação Segura:** Login via cookies de sessão (HTTPOnly) e senhas criptografadas com `bcrypt`.
* **Gerenciamento de Entidades:** CRUD completo para Projetos, Contatos do Rodapé e Configurações do WhatsApp (Número e Mensagem padrão).
* **Gestão de Administradores:**
  * Criação de novos usuários com validação estrita de senha forte (mínimo 8 caracteres, letras maiúsculas, números e símbolos) validada no Front e no Back-end.
  * Ocultar/Mostrar senha dinâmico (olhinho).
  * O usuário Mestre (`admin`) é inalterável e imune a deleção pelo painel.
* **Stateful UI:** Utilização de `localStorage` para manter a aba atual do painel de controle ativa mesmo após os recarregamentos (POST/Redirect) do servidor.

### ⚙️ DevOps & Infraestrutura
* **Containerização Nativa:** Configurado para rodar perfeitamente através de `docker-compose`.
* **Blindagem de Credenciais:** A senha do usuário mestre (`admin`) é forçada a sincronizar no *startup* do servidor com a variável de ambiente `ADMIN_PASSWORD` do Docker.
* **Database Preload (Wait-for-DB):** Laço de repetição (`wait_for_db()`) no boot da aplicação que garante que o FastAPI aguarde o MySQL/MariaDB estar 100% pronto antes de executar o `metadata.create_all`, evitando crashes em deploys automáticos.
* **Versionamento Dinâmico:** Variável `APP_VERSION` injetada através do Dockerfile (suporte a GitHub Actions) que exibe a versão atual (ex: `v1.0.0`) no rodapé do sistema.

---

## 🛠️ Stack Tecnológica

* **Back-end:** Python 3.11, FastAPI, SQLAlchemy, Bcrypt.
* **Front-end:** HTML5, Jinja2 (Templates), Tailwind CSS (CDN), FontAwesome 6, Vanilla JavaScript.
* **Banco de Dados:** SQLite (Dev) / MySQL ou MariaDB (Prod).
* **Infra:** Docker, Docker Compose.

---

## 📂 Estrutura de Diretórios

```text
├── app.py                  # Aplicação principal (Rotas, Lógica, Startup)
├── database.py             # Configuração da engine do SQLAlchemy
├── models.py               # Modelos das tabelas (Usuário, Projeto, Contato, WhatsApp)
├── docker-compose.yml      # Orquestração dos serviços Docker
├── Dockerfile              # Imagem do servidor Python
├── static/
│   ├── card.jpg            # Imagem Open Graph para redes sociais
│   └── ...                 # Outros assets
└── templates/
    ├── base.html           # Layout mestre (Header, Footer, Tailwind config)
    ├── index.html          # Página Inicial
    ├── linux.html          # Serviço: Linux
    ├── mikrotik.html       # Serviço: MikroTik
    ├── manutencao.html     # Serviço: Manutenção
    ├── admin_login.html    # Tela de Login do Painel
    ├── admin_dashboard.html# Painel de Controle (Abas interativas)
    ├── admin_edit_*.html   # Telas de edição específicas
    ├── robots.txt          # Template SEO
    └── sitemap.xml         # Template SEO Dinâmico