"""Cria app_settings (configurações do sistema salvas no banco).

Revision ID: 0005
Revises: 0004
"""
import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "app_settings" not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table(
            "app_settings",
            sa.Column("key", sa.String(64), primary_key=True),
            sa.Column("value", sa.Text, nullable=True),
            sa.Column("is_secret", sa.Boolean, nullable=False, server_default=sa.false()),
        )


def downgrade() -> None:
    op.drop_table("app_settings")
