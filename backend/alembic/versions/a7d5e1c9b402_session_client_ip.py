"""session client IP

Records the client address at sign-in on each session so the admin section
can show it alongside the user agent.  Nullable: sessions created before
this migration keep NULL.

Revision ID: a7d5e1c9b402
Revises: f8c3a21d7e45
Create Date: 2026-10-20
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a7d5e1c9b402'
down_revision: Union[str, None] = 'f8c3a21d7e45'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 45 chars: longest possible IPv6 literal (IPv4-mapped form included).
    op.add_column('user_sessions',
                  sa.Column('client_ip', sa.String(length=45), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('user_sessions') as batch_op:
        batch_op.drop_column('client_ip')
