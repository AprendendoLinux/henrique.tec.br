"""Cria telegram_config (botão de contato por Telegram).

Revision ID: 0003
Revises: 0002
"""
import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "telegram_config" not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table(
            "telegram_config",
            sa.Column("id", sa.Integer, primary_key=True, index=True),
            sa.Column("usuario", sa.String(64), nullable=True),
            sa.Column("ativo", sa.Boolean, nullable=False, server_default=sa.false()),
        )


def downgrade() -> None:
    op.drop_table("telegram_config")
