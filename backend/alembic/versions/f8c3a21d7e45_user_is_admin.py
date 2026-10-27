"""user is_admin flag

Adds users.is_admin — gates the admin section (registered-user directory and
session revocation).  The earliest registered account is granted admin when
no account holds it yet, matching the bootstrap in app.db / create_user.

Revision ID: f8c3a21d7e45
Revises: d4a1e8b6c93f
Create Date: 2026-10-20
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f8c3a21d7e45'
down_revision: Union[str, None] = 'd4a1e8b6c93f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users',
                  sa.Column('is_admin', sa.Boolean(), nullable=False,
                            server_default=sa.false()))
    # Backfill: earliest account administers an existing instance.
    op.execute(
        "UPDATE users SET is_admin = TRUE "
        "WHERE id = (SELECT id FROM users ORDER BY created_at ASC LIMIT 1) "
        "AND NOT EXISTS (SELECT 1 FROM users WHERE is_admin = TRUE)"
    )


def downgrade() -> None:
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_column('is_admin')
