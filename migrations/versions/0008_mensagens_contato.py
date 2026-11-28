"""Mensagens do formulário de orçamento (histórico e quarentena de spam).

Revision ID: 0008
Revises: 0007
"""
import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "mensagens_contato" in set(sa.inspect(op.get_bind()).get_table_names()):
        return
    op.create_table(
        "mensagens_contato",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("ts", sa.DateTime, nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("nome", sa.String(100), nullable=False),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("telefone", sa.String(30)),
        sa.Column("servico", sa.String(60), nullable=False),
        sa.Column("prazo", sa.String(30)),
        sa.Column("mensagem", sa.Text, nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("pais", sa.String(2)),
        sa.Column("cidade", sa.String(80)),
        sa.Column("org", sa.String(120)),
        sa.Column("pontuacao", sa.Integer, nullable=False, server_default="0"),
        sa.Column("motivos", sa.String(500)),
        sa.Column("detalhes_ip", sa.Text),
        sa.Column("proxies", sa.String(500)),
    )
    op.create_index("ix_mensagens_contato_ts", "mensagens_contato", ["ts"])
    op.create_index("ix_mensagens_contato_status", "mensagens_contato", ["status"])
    op.create_index("ix_mensagens_contato_ip", "mensagens_contato", ["ip"])


def downgrade() -> None:
    op.drop_table("mensagens_contato")
