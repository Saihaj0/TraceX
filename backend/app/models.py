"""SQLAlchemy ORM models for TRACE-X.

Design rules enforced here:
  * Evidence sources are immutable after ingestion (no update paths exist for
    their content, size or hash fields).
  * Raw source data is kept in `EvidenceSource` / `Event.raw_record`, separate
    from the normalized fields used for analysis.
  * Every investigation owns its evidence, events, findings, chains, graph and
    analysis runs — there are no cross-investigation foreign keys.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    PrimaryKeyConstraint,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def new_id() -> str:
    return uuid.uuid4().hex


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    case_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)
    origin: Mapped[str] = mapped_column(String(32), default="user", nullable=False)  # user | demo
    # Owning actor (auth).  NULL means unowned/shared — visible to everyone, which
    # is the only mode that exists while TRACEX_AUTH_ENABLED=false.
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    analysis_config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    evidence_sources = relationship(
        "EvidenceSource", back_populates="investigation", cascade="all, delete-orphan"
    )
    events = relationship("Event", back_populates="investigation", cascade="all, delete-orphan")


class EvidenceSource(Base):
    __tablename__ = "evidence_sources"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    file_type: Mapped[str] = mapped_column(String(32), nullable=False)  # evtx | fsat | browser | json | csv
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    stored_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    origin: Mapped[str] = mapped_column(String(16), default="imported", nullable=False)  # imported | demo
    parser_name: Mapped[str] = mapped_column(String(64), default="unknown")
    parser_version: Mapped[str] = mapped_column(String(32), default="0")
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    record_count: Mapped[int] = mapped_column(Integer, default=0)
    accepted_count: Mapped[int] = mapped_column(Integer, default=0)
    rejected_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="processed")  # processed | partial | failed
    timezone_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    # Never-mutated row errors from parsing/validation, kept so invalid records
    # are inspectable rather than silently discarded.
    record_errors: Mapped[list] = mapped_column(JSON, default=list)

    investigation = relationship("Investigation", back_populates="evidence_sources")
    events = relationship("Event", back_populates="evidence_source")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    evidence_source_id: Mapped[str | None] = mapped_column(
        ForeignKey("evidence_sources.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # Normalized values (nullable when the source does not provide them)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    timestamp_raw: Mapped[str | None] = mapped_column(String(128), nullable=True)
    timestamp_precision: Mapped[str] = mapped_column(String(24), default="unknown")  # second|minute|day|unknown
    timestamp_confidence: Mapped[str] = mapped_column(String(24), default="none")  # high|medium|low|none
    timezone_note: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    source_type: Mapped[str] = mapped_column(String(64), default="unknown")
    source_file: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_record_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    user: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    process_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True, index=True)
    device_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_record_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_record: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    parser_name: Mapped[str] = mapped_column(String(64), default="unknown")
    parser_version: Mapped[str] = mapped_column(String(32), default="0")
    integrity_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ingestion_status: Mapped[str] = mapped_column(String(24), default="accepted")
    origin: Mapped[str] = mapped_column(String(16), default="imported")  # imported | demo
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    seq: Mapped[int] = mapped_column(Integer, default=0)

    investigation = relationship("Investigation", back_populates="events")
    evidence_source = relationship("EvidenceSource", back_populates="events")


Index("ix_events_investigation_ts", Event.investigation_id, Event.timestamp)
# Timeline facets filter by investigation + type + time.
Index("ix_events_investigation_type_ts", Event.investigation_id, Event.event_type, Event.timestamp)


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    engine_version: Mapped[str] = mapped_column(String(32))
    rules_version: Mapped[str] = mapped_column(String(32))
    trigger: Mapped[str] = mapped_column(String(32), default="manual")
    config_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    # Which rule versions took part — re-analysis stays traceable.
    rules_run: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(24), default="completed")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    analysis_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True
    )
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_name: Mapped[str] = mapped_column(String(255))
    rule_version: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(24), index=True)  # critical|high|medium|low|info
    support: Mapped[str] = mapped_column(String(32), default="insufficient")
    heuristic_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    score_components: Mapped[list] = mapped_column(JSON, default=list)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    explanation: Mapped[dict] = mapped_column(JSON, default=dict)
    chain_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dedupe_key: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    investigation = relationship("Investigation")


class SuspicionChain(Base):
    __tablename__ = "suspicion_chains"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    pattern_id: Mapped[str] = mapped_column(String(16), index=True)
    pattern_name: Mapped[str] = mapped_column(String(255))
    title: Mapped[str] = mapped_column(String(512))
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    steps: Mapped[list] = mapped_column(JSON, default=list)
    relationship_types: Mapped[list] = mapped_column(JSON, default=list)
    severity: Mapped[str] = mapped_column(String(24))
    support: Mapped[str] = mapped_column(String(32), default="low")
    completeness: Mapped[str] = mapped_column(String(24), default="incomplete")
    missing_steps: Mapped[list] = mapped_column(JSON, default=list)
    alternative_explanations: Mapped[list] = mapped_column(JSON, default=list)
    triggered_rules: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="open")
    dedupe_key: Mapped[str] = mapped_column(String(128), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GraphNode(Base):
    __tablename__ = "graph_nodes"
    # Composite key: node ids like `file:<hash>` are deterministic and therefore
    # repeat across investigations — the investigation must be part of the key.
    __table_args__ = (PrimaryKeyConstraint("id", "investigation_id"),)

    id: Mapped[str] = mapped_column(String(64))
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    node_type: Mapped[str] = mapped_column(String(32))  # event|file|user|process|device|source|finding|hypothesis
    label: Mapped[str] = mapped_column(String(512))
    properties: Mapped[dict] = mapped_column(JSON, default=dict)
    event_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class GraphEdge(Base):
    __tablename__ = "graph_edges"
    __table_args__ = (PrimaryKeyConstraint("id", "investigation_id"),)

    id: Mapped[str] = mapped_column(String(64))
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    source_key: Mapped[str] = mapped_column(String(64), index=True)
    target_key: Mapped[str] = mapped_column(String(64), index=True)
    relation: Mapped[str] = mapped_column(String(40))  # OBSERVED_IN, PRECEDES, POSSIBLY_CAUSAL ...
    explanation: Mapped[str] = mapped_column(Text)
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)
    rule_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    inferred: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence: Mapped[str] = mapped_column(String(24), default="observed")  # observed|low|moderate|strong
    weight: Mapped[float] = mapped_column(Float, default=1.0)


class User(Base):
    """A registered investigator account (signup/sign-in).

    Passwords are stored as PBKDF2-HMAC-SHA256 hashes in the format
    ``pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>``; the plaintext is
    never persisted, logged or returned by the API.
    """
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Administrators see the admin section: the registered-user list and
    # session revocation.  The first account created and TRACEX_ADMIN_USERS
    # entries are admins (see services/accounts.is_admin_user).
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    sessions = relationship("UserSession", back_populates="user",
                            cascade="all, delete-orphan")


class UserSession(Base):
    """A sign-in session.

    Only the SHA-256 hash of the bearer token is stored — a database copy can
    never be replayed as a live credential. Sessions expire and can be revoked.
    """
    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Client address at sign-in, shown in the admin session list so an
    # investigator can tell devices apart.  NULL for sessions created before
    # the column existed.  45 chars = longest possible IPv6 literal.
    client_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)

    user = relationship("User", back_populates="sessions")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    investigation_id: Mapped[str | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(64), index=True)
    entity_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor: Mapped[str] = mapped_column(String(128), default="investigator")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


# Audit history is read per-investigation, newest first.
Index("ix_audit_investigation_created", AuditLog.investigation_id, AuditLog.created_at)