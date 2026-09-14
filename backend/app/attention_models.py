from datetime import datetime, timezone

from sqlmodel import Field, SQLModel


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EvidenceAttention(SQLModel, table=True):
    id: int | None = Field(
        default=None,
        primary_key=True,
    )

    case_id: int = Field(
        index=True,
    )

    evidence_id: int = Field(
        index=True,
        unique=True,
    )

    view_count: int = Field(
        default=0,
    )

    revisit_count: int = Field(
        default=0,
    )

    total_view_seconds: float = Field(
        default=0.0,
    )

    focused_seconds: float = Field(
        default=0.0,
    )

    longest_view_seconds: float = Field(
        default=0.0,
    )

    first_viewed_at: datetime | None = Field(
        default=None,
    )

    last_viewed_at: datetime | None = Field(
        default=None,
    )

    updated_at: datetime = Field(
        default_factory=utc_now,
    )


class AttentionUpdate(SQLModel):
    dwell_seconds: float = Field(
        default=0.0,
        ge=0.0,
        le=3600.0,
    )

    focused_seconds: float = Field(
        default=0.0,
        ge=0.0,
        le=3600.0,
    )

    new_view: bool = Field(
        default=True,
    )


class EvidenceAttentionPublic(SQLModel):
    id: int

    case_id: int

    evidence_id: int

    view_count: int

    revisit_count: int

    total_view_seconds: float

    focused_seconds: float

    longest_view_seconds: float

    first_viewed_at: datetime | None

    last_viewed_at: datetime | None

    updated_at: datetime


class AttentionCaseSummary(SQLModel):
    case_id: int

    total_evidence: int

    reviewed_evidence: int

    unreviewed_evidence: int

    total_view_seconds: float

    average_view_seconds: float

    total_views: int

    total_revisits: int

    coverage_percent: float