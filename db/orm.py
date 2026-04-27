# db/orm.py
"""
AsyncSQLAlchemy ORM models for PostgreSQL persistence layer.

Tables mapped:
- Claim: Extracted claims from LLM output
- ValidationResult: Single rule validation outcome
- Decision: Final validation decision
- AuditLogEntry: Hash-chained audit record
- AnalystOverride: SOC_ADMIN decision override
- PolicyProfile: Decision policy configuration
- User: RBAC user accounts

All models use async connections with asyncpg driver.

TODO: Wire Tanushree's, Tapan's, and Dhruv's modules to use these models
"""

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    JSONB,
    UUID,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()


class Claim(Base):
    """Extracted claim from LLM output."""

    __tablename__ = "claims"

    id = Column(Integer, primary_key=True)
    claim_id = Column(
        PG_UUID(as_uuid=True), unique=True, default=uuid.uuid4, nullable=False
    )
    text = Column(String, nullable=False)
    claim_type = Column(String(50), index=True)
    confidence = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class ValidationResult(Base):
    """Single validation rule outcome."""

    __tablename__ = "validation_results"

    id = Column(Integer, primary_key=True)
    validation_result_id = Column(
        PG_UUID(as_uuid=True), unique=True, default=uuid.uuid4
    )
    decision_id = Column(PG_UUID(as_uuid=True), index=True, nullable=False)
    rule_id = Column(String(100), index=True)
    rule_name = Column(String(255))
    passed = Column(Boolean)
    evidence = Column(String)
    confidence = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)


class Decision(Base):
    """Final validation decision."""

    __tablename__ = "decisions"

    id = Column(Integer, primary_key=True)
    decision_id = Column(
        PG_UUID(as_uuid=True), unique=True, default=uuid.uuid4, nullable=False
    )
    alert_id = Column(String(255), index=True)
    llm_output = Column(String)
    outcome = Column(String(20), index=True)  # ALLOW | FLAG | BLOCK | CORRECT
    risk_score = Column(Float, nullable=False)
    component_scores = Column(JSONB)
    correction_candidate = Column(String)
    analyst_rationale = Column(String)
    policy_profile_name = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(PG_UUID(as_uuid=True))


class AuditLogEntry(Base):
    """Hash-chained audit log entry."""

    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True)
    decision_id = Column(PG_UUID(as_uuid=True), index=True, nullable=False)
    record_data = Column(JSONB)
    prev_hash = Column(String(64), nullable=False)
    curr_hash = Column(String(64), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class AnalystOverride(Base):
    """SOC_ADMIN decision override."""

    __tablename__ = "analyst_overrides"

    id = Column(Integer, primary_key=True)
    override_id = Column(PG_UUID(as_uuid=True), unique=True, default=uuid.uuid4)
    decision_id = Column(PG_UUID(as_uuid=True), index=True, nullable=False)
    original_outcome = Column(String(20))
    new_outcome = Column(String(20))
    rationale = Column(String)
    correction_suggestion = Column(String)
    overridden_by = Column(PG_UUID(as_uuid=True), index=True, nullable=False)
    override_timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    audit_hash = Column(String(64))


class PolicyProfile(Base):
    """Decision policy configuration."""

    __tablename__ = "policy_profiles"

    id = Column(Integer, primary_key=True)
    profile_id = Column(PG_UUID(as_uuid=True), unique=True, default=uuid.uuid4)
    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(String)
    thresholds = Column(JSONB)
    rule_weights = Column(JSONB)
    active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class User(Base):
    """RBAC user account."""

    __tablename__ = "users"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    role = Column(String(50), index=True)  # SOC_ANALYST | SOC_ADMIN | SYSTEM
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)


# Database connection factory
class DatabaseManager:
    """Manages async database connections."""

    def __init__(self, database_url: str):
        """
        Initialize database manager.

        Args:
            database_url: PostgreSQL connection string (asyncpg driver)
                         e.g., postgresql+asyncpg://user:pass@host/db
        """
        self.database_url = database_url
        self.engine = None
        self.async_session_maker = None

    async def initialize(self):
        """Initialize async engine and session factory."""
        self.engine = create_async_engine(
            self.database_url,
            echo=False,
            pool_size=20,
            max_overflow=10,
            pool_pre_ping=True,
        )

        self.async_session_maker = sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False
        )

        # Create all tables
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def close(self):
        """Close all connections."""
        if self.engine:
            await self.engine.dispose()

    async def get_session(self) -> AsyncSession:
        """Get new async database session."""
        if not self.async_session_maker:
            raise RuntimeError("Database not initialized. Call initialize() first.")

        return self.async_session_maker()


# Singleton instance
_db_manager: Optional[DatabaseManager] = None


def get_db_manager(database_url: str = None) -> DatabaseManager:
    """Get or create database manager singleton."""
    import os

    global _db_manager

    if _db_manager is None:
        url = database_url or os.getenv(
            "DATABASE_URL",
            "postgresql+asyncpg://llm_user:password@localhost/llm_firewall",
        )
        _db_manager = DatabaseManager(url)

    return _db_manager
