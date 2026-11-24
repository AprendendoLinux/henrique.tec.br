"""Tabelas do monitoramento de acessos e segurança (acessos, eventos_seguranca, ip_geo).

Revision ID: 0007
Revises: 0006
"""
import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

ID = sa.BigInteger().with_variant(sa.Integer, "sqlite")


def upgrade() -> None:
    existentes = set(sa.inspect(op.get_bind()).get_table_names())
    if "acessos" not in existentes:
        op.create_table(
            "acessos",
            sa.Column("id", ID, primary_key=True, autoincrement=True),
            sa.Column("ts", sa.DateTime, nullable=False),
            sa.Column("ip", sa.String(45), nullable=False),
            sa.Column("metodo", sa.String(8), nullable=False),
            sa.Column("caminho", sa.String(300), nullable=False),
            sa.Column("status", sa.SmallInteger, nullable=False),
            sa.Column("ms", sa.Integer, nullable=False, server_default="0"),
            sa.Column("user_agent", sa.String(300)),
            sa.Column("referer", sa.String(300)),
            sa.Column("robo", sa.String(40)),
            sa.Column("suspeito", sa.Boolean, nullable=False, server_default=sa.false()),
        )
        op.create_index("ix_acessos_ts", "acessos", ["ts"])
        op.create_index("ix_acessos_ip", "acessos", ["ip"])
        op.create_index("ix_acessos_robo", "acessos", ["robo"])
        op.create_index("ix_acessos_suspeito", "acessos", ["suspeito"])
    if "eventos_seguranca" not in existentes:
        op.create_table(
            "eventos_seguranca",
            sa.Column("id", ID, primary_key=True, autoincrement=True),
            sa.Column("ts", sa.DateTime, nullable=False),
            sa.Column("ip", sa.String(45), nullable=False),
            sa.Column("tipo", sa.String(30), nullable=False),
            sa.Column("usuario", sa.String(50)),
            sa.Column("caminho", sa.String(300)),
            sa.Column("detalhe", sa.String(300)),
        )
        op.create_index("ix_eventos_seguranca_ts", "eventos_seguranca", ["ts"])
        op.create_index("ix_eventos_seguranca_ip", "eventos_seguranca", ["ip"])
        op.create_index("ix_eventos_seguranca_tipo", "eventos_seguranca", ["tipo"])
    if "ip_geo" not in existentes:
        op.create_table(
            "ip_geo",
            sa.Column("ip", sa.String(45), primary_key=True),
            sa.Column("pais", sa.String(2)),
            sa.Column("pais_nome", sa.String(80)),
            sa.Column("regiao", sa.String(80)),
            sa.Column("cidade", sa.String(80)),
            sa.Column("lat", sa.Float),
            sa.Column("lon", sa.Float),
            sa.Column("org", sa.String(120)),
            sa.Column("rdns", sa.String(255)),
            sa.Column("fonte", sa.String(20)),
            sa.Column("atualizado", sa.DateTime, nullable=False),
        )


def downgrade() -> None:
    op.drop_table("ip_geo")
    op.drop_table("eventos_seguranca")
    op.drop_table("acessos")
