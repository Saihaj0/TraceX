"""auth owner + perf indexes

Adds:
  * investigations.owner (auth: owning actor; NULL = shared/unowned)
  * ix_events_investigation_type_ts (timeline facet filtering)
  * ix_audit_investigation_created (per-investigation audit reads)

Revision ID: b7d21f4a9c32
Revises: 0989628cf3b0
Create Date: 2026-10-19
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b7d21f4a9c32'
down_revision: Union[str, None] = '0989628cf3b0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('investigations',
                  sa.Column('owner', sa.String(length=128), nullable=True))
    op.create_index(op.f('ix_investigations_owner'), 'investigations', ['owner'], unique=False)
    op.create_index('ix_events_investigation_type_ts', 'events',
                    ['investigation_id', 'event_type', 'timestamp'], unique=False)
    op.create_index('ix_audit_investigation_created', 'audit_logs',
                    ['investigation_id', 'created_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_audit_investigation_created', table_name='audit_logs')
    op.drop_index('ix_events_investigation_type_ts', table_name='events')
    op.drop_index(op.f('ix_investigations_owner'), table_name='investigations')
    op.drop_column('investigations', 'owner')
