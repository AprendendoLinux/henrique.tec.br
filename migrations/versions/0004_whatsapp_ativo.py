"""Adiciona whatsapp_config.ativo (exibir ou ocultar o botão).

Revision ID: 0004
Revises: 0003
"""
import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    colunas = [c["name"] for c in sa.inspect(op.get_bind()).get_columns("whatsapp_config")]
    if "ativo" not in colunas:
        op.add_column("whatsapp_config", sa.Column("ativo", sa.Boolean, nullable=False, server_default=sa.true()))


def downgrade() -> None:
    op.drop_column("whatsapp_config", "ativo")
