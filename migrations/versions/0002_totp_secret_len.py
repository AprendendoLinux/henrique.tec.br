"""Amplia totp_secret para comportar o segredo criptografado.

Revision ID: 0002
Revises: 0001
"""
import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "usuarios", "totp_secret",
        existing_type=sa.String(32), type_=sa.String(255), existing_nullable=True,
    )


def downgrade() -> None:
    pass
