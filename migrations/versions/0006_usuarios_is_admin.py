"""Adiciona usuarios.is_admin (perfil de administrador).

Revision ID: 0006
Revises: 0005
"""
import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    colunas = [c["name"] for c in sa.inspect(op.get_bind()).get_columns("usuarios")]
    if "is_admin" not in colunas:
        op.add_column("usuarios", sa.Column("is_admin", sa.Boolean, nullable=False, server_default=sa.false()))
    op.execute("UPDATE usuarios SET is_admin = TRUE WHERE username = 'admin'")


def downgrade() -> None:
    op.drop_column("usuarios", "is_admin")
