"""
Database configuration for SIA Sentinel.

Provides PostgreSQL connection via SQLAlchemy with connection pooling.
"""

from __future__ import annotations

import os
from typing import Any

from sqlalchemy import create_engine, Column, String, Text, DateTime, Integer, Boolean, Index
from sqlalchemy import JSON
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import QueuePool, StaticPool
from datetime import datetime, timezone
from contextlib import contextmanager


# Database URL from environment
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./sentinel.db"  # Fallback to SQLite for dev
)

# SQLite connections are bound to the creating thread by default; audit
# job workers write from background threads, so relax that for sqlite.
_connect_args = (
    {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)

# In-memory SQLite gives each connection its own database; StaticPool
# forces a single shared connection (standard pattern for tests).
_is_sqlite_memory = DATABASE_URL == "sqlite:///:memory:"
_poolclass = StaticPool if _is_sqlite_memory else QueuePool

_pool_kwargs: dict[str, Any] = {}
if not _is_sqlite_memory:
    _pool_kwargs = {
        "pool_size": 10,           # Keep 10 connections open
        "max_overflow": 20,        # Allow 20 extra connections under load
        "pool_pre_ping": True,     # Verify connections before using
        "pool_recycle": 3600,      # Recycle connections after 1 hour
    }

# Create engine with connection pooling
engine = create_engine(
    DATABASE_URL,
    poolclass=_poolclass,
    echo=False,             # Set to True for SQL logging
    connect_args=_connect_args,
    **_pool_kwargs,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


# === ORM Models ===

class EvidenceRecord(Base):
    """ORM model for evidence records."""

    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    evidence_id = Column(String(64), unique=True, nullable=False, index=True)
    agent_id = Column(String(256), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True, default=lambda: datetime.now(timezone.utc))
    description = Column(Text, nullable=True)
    target_path = Column(String(1024), nullable=True)
    target_symbol = Column(String(256), nullable=True)
    current_code_hash = Column(String(128), nullable=True)
    proposed_code_hash = Column(String(128), nullable=True)
    safety_approved = Column(Boolean, nullable=False, default=True)
    trust_level = Column(String(32), nullable=True)
    metadata_json = Column(JSON, nullable=True)
    signature = Column(Text, nullable=False)

    __table_args__ = (
        Index("idx_evidence_agent_timestamp", "agent_id", "timestamp"),
        Index("idx_evidence_trust_level", "trust_level"),
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict."""
        return {
            "id": self.id,
            "evidence_id": self.evidence_id,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "description": self.description,
            "target_path": self.target_path,
            "target_symbol": self.target_symbol,
            "current_code_hash": self.current_code_hash,
            "proposed_code_hash": self.proposed_code_hash,
            "safety_approved": self.safety_approved,
            "trust_level": self.trust_level,
            "metadata": self.metadata_json,
            "signature": self.signature,
        }


class APIKeyRecord(Base):
    """ORM model for API keys."""

    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key_id = Column(String(64), unique=True, nullable=False, index=True)
    hashed_key = Column(String(128), nullable=False, index=True)
    name = Column(String(256), nullable=False)
    role = Column(String(32), nullable=False, default="user")
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    last_used = Column(DateTime(timezone=True), nullable=True)


class TrustLevelRecord(Base):
    """ORM model for agent trust levels."""

    __tablename__ = "trust_levels"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_id = Column(String(256), unique=True, nullable=False, index=True)
    trust_level = Column(String(32), nullable=False)
    success_count = Column(Integer, nullable=False, default=0)
    failure_count = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class AuditJobRecord(Base):
    """ORM model for async audit jobs (persistent queue).

    Stores the flow declaration so pending/running jobs can be resumed
    after a process restart (crash recovery).
    """

    __tablename__ = "audit_jobs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    audit_id = Column(String(64), unique=True, nullable=False, index=True)
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    flow_name = Column(String(256), nullable=True)
    status = Column(String(16), nullable=False, default="pending", index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    error = Column(Text, nullable=True)
    result_json = Column(JSON, nullable=True)
    flow_json = Column(JSON, nullable=True)

    __table_args__ = (
        Index("idx_audit_jobs_tenant_status", "tenant_id", "status"),
    )


def init_db() -> None:
    """Create all tables."""
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_db():
    """Context manager yielding an open database session.

    The session is committed on success, rolled back on error, and always
    closed. (Previously returned an already-closed session — the ``finally``
    ran before the caller could use it.)
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@contextmanager
def get_db_session():
    """Context manager for database sessions."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
