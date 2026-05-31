import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class EnvSnapshot(Base):
    __tablename__ = "env_snapshots"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    fingerprint: Mapped[dict] = mapped_column(JSON, nullable=False)
    schema_hash: Mapped[str | None] = mapped_column(String)


class CoverageHistory(Base):
    __tablename__ = "coverage_history"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    measured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    scan_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    industry_profile: Mapped[str] = mapped_column(String, nullable=False)
    coverage_pct: Mapped[float] = mapped_column(Float, nullable=False)
    techniques_covered: Mapped[int | None] = mapped_column(Integer)
    techniques_total: Mapped[int | None] = mapped_column(Integer)
    rules_healthy: Mapped[int | None] = mapped_column(Integer)
    rules_broken: Mapped[int | None] = mapped_column(Integer)
    financial_exposure_usd: Mapped[float | None] = mapped_column(Float)


class Gap(Base):
    __tablename__ = "gaps"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    technique_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    technique_name: Mapped[str] = mapped_column(String, nullable=False)
    tactic: Mapped[str] = mapped_column(String, nullable=False)
    industry: Mapped[str] = mapped_column(String, nullable=False)
    priority_score: Mapped[float] = mapped_column(Float, nullable=False)
    financial_exposure_usd: Mapped[float | None] = mapped_column(Float)
    # CLOSABLE | DATA_PARTIAL | DATA_GAP | CLOSED
    status: Mapped[str] = mapped_column(String, nullable=False, default="CLOSABLE")
    data_gap_detail: Mapped[str | None] = mapped_column(Text)
    first_identified: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    rules: Mapped[list["Rule"]] = relationship("Rule", back_populates="gap", foreign_keys="Rule.gap_id")


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    gap_id: Mapped[str | None] = mapped_column(String, ForeignKey("gaps.id"))
    technique_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    technique_name: Mapped[str] = mapped_column(String, nullable=False)
    tactic: Mapped[str] = mapped_column(String, nullable=False)
    spl: Mapped[str] = mapped_column(Text, nullable=False)
    spl_explanation: Mapped[str | None] = mapped_column(Text)
    splunk_search_name: Mapped[str | None] = mapped_column(String)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    generation_attempts: Mapped[int] = mapped_column(Integer, default=1)
    tuning_rounds: Mapped[int] = mapped_column(Integer, default=0)
    hits_per_day: Mapped[float | None] = mapped_column(Float)
    # LOW | MEDIUM | HIGH
    false_pos_estimate: Mapped[str | None] = mapped_column(String)
    # PENDING_REVIEW | DEPLOYED | BROKEN | RETIRED | ARCHIVED
    status: Mapped[str] = mapped_column(String, nullable=False, default="PENDING_REVIEW")
    industry: Mapped[str] = mapped_column(String, nullable=False)
    required_fields: Mapped[list | None] = mapped_column(JSON)
    index_name: Mapped[str | None] = mapped_column(String)
    sourcetype: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reviewed_by: Mapped[str | None] = mapped_column(String)
    deployed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    parent_rule_id: Mapped[str | None] = mapped_column(String, ForeignKey("rules.id"))

    gap: Mapped["Gap | None"] = relationship("Gap", back_populates="rules", foreign_keys=[gap_id])
    tuning_history: Mapped[list["TuningHistory"]] = relationship("TuningHistory", back_populates="rule")
    drift_events: Mapped[list["DriftEvent"]] = relationship("DriftEvent", back_populates="rule")
    review_entry: Mapped["ReviewQueue | None"] = relationship("ReviewQueue", back_populates="rule", uselist=False)


class TuningHistory(Base):
    __tablename__ = "tuning_history"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    rule_id: Mapped[str] = mapped_column(String, ForeignKey("rules.id"), nullable=False)
    iteration: Mapped[int] = mapped_column(Integer, nullable=False)
    spl_before: Mapped[str] = mapped_column(Text, nullable=False)
    spl_after: Mapped[str] = mapped_column(Text, nullable=False)
    hits_before: Mapped[float | None] = mapped_column(Float)
    hits_after: Mapped[float | None] = mapped_column(Float)
    reason: Mapped[str | None] = mapped_column(Text)
    tuned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    rule: Mapped["Rule"] = relationship("Rule", back_populates="tuning_history")


class DriftEvent(Base):
    __tablename__ = "drift_events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    rule_id: Mapped[str] = mapped_column(String, ForeignKey("rules.id"), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    # SILENT | DATA_STALE | SCHEMA_DRIFT
    drift_type: Mapped[str] = mapped_column(String, nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # REGENERATED | MANUALLY_FIXED | RETIRED
    resolution: Mapped[str | None] = mapped_column(String)

    rule: Mapped["Rule"] = relationship("Rule", back_populates="drift_events")


class ReviewQueue(Base):
    __tablename__ = "review_queue"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    rule_id: Mapped[str] = mapped_column(String, ForeignKey("rules.id"), nullable=False, unique=True)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    mandatory: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # APPROVED | EDITED | REJECTED | PENDING
    decision: Mapped[str | None] = mapped_column(String, default="PENDING")
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decided_by: Mapped[str | None] = mapped_column(String)
    edit_notes: Mapped[str | None] = mapped_column(Text)

    rule: Mapped["Rule"] = relationship("Rule", back_populates="review_entry")


class RuleClassification(Base):
    """Stores Foundation-sec classifications of existing Splunk saved searches."""
    __tablename__ = "rule_classifications"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    search_name: Mapped[str] = mapped_column(String, nullable=False)
    spl: Mapped[str] = mapped_column(Text, nullable=False)
    technique_id: Mapped[str | None] = mapped_column(String, index=True)
    technique_name: Mapped[str | None] = mapped_column(String)
    tactic: Mapped[str | None] = mapped_column(String)
    confidence: Mapped[float | None] = mapped_column(Float)
    reasoning: Mapped[str | None] = mapped_column(Text)
    coverage_quality: Mapped[str | None] = mapped_column(String)
    coverage_gaps: Mapped[str | None] = mapped_column(Text)
    classified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
