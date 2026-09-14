from datetime import datetime, timezone

from sqlmodel import Field, SQLModel


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# =========================================================
# CASE
# =========================================================


class CaseBase(SQLModel):
    name: str = Field(
        min_length=2,
        max_length=120,
    )

    case_type: str = Field(
        default="Endpoint Investigation",
        max_length=100,
    )

    description: str = Field(
        default="",
        max_length=2000,
    )

    investigator: str = Field(
        default="Local Analyst",
        max_length=120,
    )


class Case(CaseBase, table=True):
    id: int | None = Field(
        default=None,
        primary_key=True,
    )

    case_code: str = Field(
        index=True,
        unique=True,
        max_length=50,
    )

    status: str = Field(
        default="ACTIVE",
        index=True,
        max_length=30,
    )

    created_at: datetime = Field(
        default_factory=utc_now,
    )

    updated_at: datetime = Field(
        default_factory=utc_now,
    )


class CaseCreate(CaseBase):
    pass


class CasePublic(CaseBase):
    id: int
    case_code: str
    status: str
    created_at: datetime
    updated_at: datetime


# =========================================================
# EVIDENCE
# =========================================================


class Evidence(SQLModel, table=True):
    id: int | None = Field(
        default=None,
        primary_key=True,
    )

    evidence_code: str = Field(
        index=True,
        unique=True,
        max_length=50,
    )

    case_id: int = Field(
        index=True,
    )

    original_filename: str = Field(
        max_length=255,
    )

    stored_filename: str = Field(
        max_length=255,
    )

    stored_path: str = Field(
        max_length=1000,
    )

    file_extension: str = Field(
        default="none",
        max_length=50,
    )

    mime_type: str = Field(
        default="application/octet-stream",
        max_length=150,
    )

    file_size: int = Field(
        default=0,
    )

    sha256: str = Field(
        default="",
        max_length=128,
    )

    sha1: str = Field(
        default="",
        max_length=128,
    )

    md5: str = Field(
        default="",
        max_length=128,
    )

    entropy: float = Field(
        default=0.0,
    )

    integrity_status: str = Field(
        default="UNVERIFIED",
        max_length=50,
    )

    verified_at: datetime | None = Field(
        default=None,
    )

    status: str = Field(
        default="REGISTERED",
        max_length=50,
    )

    uploaded_at: datetime = Field(
        default_factory=utc_now,
    )


class EvidencePublic(SQLModel):
    id: int
    evidence_code: str
    case_id: int
    original_filename: str
    file_extension: str
    mime_type: str
    file_size: int
    sha256: str
    sha1: str
    md5: str
    entropy: float
    integrity_status: str
    verified_at: datetime | None
    status: str
    uploaded_at: datetime


# =========================================================
# GENERIC FEATURES
# =========================================================


class EvidenceFeature(SQLModel, table=True):
    id: int | None = Field(
        default=None,
        primary_key=True,
    )

    evidence_id: int = Field(
        index=True,
        unique=True,
    )

    case_id: int = Field(
        index=True,
    )

    file_size_bytes: int = 0
    entropy: float = 0.0
    filename_length: int = 0
    extension_length: int = 0

    is_executable: int = 0
    is_script: int = 0
    is_archive: int = 0
    is_document: int = 0
    is_image: int = 0
    is_database: int = 0

    is_hidden: int = 0
    has_double_extension: int = 0
    suspicious_extension: int = 0
    suspicious_keyword: int = 0
    high_entropy: int = 0

    mime_is_executable: int = 0
    mime_is_archive: int = 0

    label: int | None = Field(
        default=None,
        index=True,
    )

    label_name: str | None = Field(
        default=None,
        max_length=30,
    )

    labeled_at: datetime | None = Field(
        default=None,
    )

    extracted_at: datetime = Field(
        default_factory=utc_now,
    )


class EvidenceFeaturePublic(SQLModel):
    id: int
    evidence_id: int
    case_id: int

    file_size_bytes: int
    entropy: float
    filename_length: int
    extension_length: int

    is_executable: int
    is_script: int
    is_archive: int
    is_document: int
    is_image: int
    is_database: int
    is_hidden: int
    has_double_extension: int
    suspicious_extension: int
    suspicious_keyword: int
    high_entropy: int
    mime_is_executable: int
    mime_is_archive: int

    label: int | None
    label_name: str | None
    labeled_at: datetime | None

    extracted_at: datetime


class EvidenceLabelRequest(SQLModel):
    label: int


class DatasetStatus(SQLModel):
    total_features: int
    labeled_samples: int
    unlabeled_samples: int
    benign_samples: int
    malicious_samples: int
    ready_for_training: bool
    minimum_required: int


# =========================================================
# PE ML PREDICTIONS
# =========================================================


class MLPrediction(SQLModel, table=True):
    id: int | None = Field(
        default=None,
        primary_key=True,
    )

    case_id: int = Field(
        index=True,
    )

    evidence_id: int = Field(
        index=True,
    )

    model_name: str = Field(
        max_length=100,
    )

    predicted_label: int = Field(
        default=0,
    )

    predicted_class: str = Field(
        max_length=30,
    )

    benign_probability: float = Field(
        default=0.0,
    )

    malicious_probability: float = Field(
        default=0.0,
    )

    risk_level: str = Field(
        max_length=30,
    )

    created_at: datetime = Field(
        default_factory=utc_now,
    )


class MLPredictionPublic(SQLModel):
    id: int
    case_id: int
    evidence_id: int
    model_name: str
    predicted_label: int
    predicted_class: str
    benign_probability: float
    malicious_probability: float
    risk_level: str
    created_at: datetime


# =========================================================
# MULTI-ARTIFACT TRIAGE
# =========================================================


class ArtifactTriage(SQLModel, table=True):
    id: int | None = Field(
        default=None,
        primary_key=True,
    )

    case_id: int = Field(
        index=True,
    )

    evidence_id: int = Field(
        index=True,
    )

    analyzer: str = Field(
        max_length=100,
    )

    analysis_method: str = Field(
        max_length=500,
    )

    risk_score: float = Field(
        default=0.0,
    )

    risk_level: str = Field(
        default="UNASSESSED",
        max_length=30,
    )

    entropy: float | None = Field(
        default=None,
    )

    predicted_class: str | None = Field(
        default=None,
        max_length=50,
    )

    model_name: str | None = Field(
        default=None,
        max_length=100,
    )

    benign_probability: float | None = Field(
        default=None,
    )

    malicious_probability: float | None = Field(
        default=None,
    )

    image_width: int | None = Field(
        default=None,
    )

    image_height: int | None = Field(
        default=None,
    )

    findings_json: str = Field(
        default="[]",
    )

    indicators_json: str = Field(
        default="[]",
    )

    limitations: str = Field(
        default="",
        max_length=4000,
    )

    created_at: datetime = Field(
        default_factory=utc_now,
        index=True,
    )


# =========================================================
# AUDIT LEDGER
# =========================================================


class LedgerEntry(SQLModel, table=True):
    id: int | None = Field(
        default=None,
        primary_key=True,
    )

    case_id: int = Field(
        index=True,
    )

    event_type: str = Field(
        index=True,
        max_length=100,
    )

    event_data: str = Field(
        default="",
        max_length=4000,
    )

    timestamp: datetime = Field(
        default_factory=utc_now,
    )

    previous_hash: str = Field(
        default="GENESIS",
        max_length=128,
    )

    current_hash: str = Field(
        index=True,
        max_length=128,
    )


class LedgerEntryPublic(SQLModel):
    id: int
    case_id: int
    event_type: str
    event_data: str
    timestamp: datetime
    previous_hash: str
    current_hash: str