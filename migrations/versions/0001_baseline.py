"""Baseline: cria tabelas ausentes (bancos já existentes são preservados).

Revision ID: 0001
Revises:
"""
import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def _create(name: str, *columns) -> None:
    if name not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table(name, *columns)


def upgrade() -> None:
    _create(
        "projetos",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("titulo", sa.String(60), index=True),
        sa.Column("descricao", sa.String(160)),
        sa.Column("categoria", sa.String(50)),
        sa.Column("link_projeto", sa.String(255), nullable=True),
        sa.Column("link_github", sa.String(255), nullable=True),
    )
    _create(
        "contatos",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("nome", sa.String(50)),
        sa.Column("url", sa.String(255)),
        sa.Column("icone", sa.String(50)),
        sa.Column("cor_icone", sa.String(50), server_default="text-gray-400"),
        sa.Column("cor_hover", sa.String(50)),
    )
    _create(
        "usuarios",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("username", sa.String(50), unique=True, index=True),
        sa.Column("password_hash", sa.String(255)),
        sa.Column("totp_secret", sa.String(32), nullable=True),
        sa.Column("is_2fa_enabled", sa.Boolean, server_default=sa.false()),
    )
    _create(
        "whatsapp_config",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("numero", sa.String(50)),
        sa.Column("mensagem", sa.String(255)),
    )


def downgrade() -> None:
    pass
