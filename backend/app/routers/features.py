from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated
import csv

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)

from fastapi.responses import FileResponse

from sqlmodel import (
    Session,
    select,
)

from ..database import (
    get_session,
)

from ..feature_extraction import (
    extract_ml_features,
)

from ..ledger import (
    create_ledger_entry,
)

from ..models import (
    Case,
    DatasetStatus,
    Evidence,
    EvidenceFeature,
    EvidenceFeaturePublic,
    EvidenceLabelRequest,
)


router = APIRouter(
    prefix="/api/cases",
    tags=["ML Features"],
)


SessionDep = Annotated[
    Session,
    Depends(get_session),
]


FEATURE_COLUMNS = [
    "file_size_bytes",
    "entropy",
    "filename_length",
    "extension_length",
    "is_executable",
    "is_script",
    "is_archive",
    "is_document",
    "is_image",
    "is_database",
    "is_hidden",
    "has_double_extension",
    "suspicious_extension",
    "suspicious_keyword",
    "high_entropy",
    "mime_is_executable",
    "mime_is_archive",
]


# =========================================================
# HELPERS
# =========================================================


def get_evidence_or_404(
    session: Session,
    case_id: int,
    evidence_id: int,
) -> Evidence:

    evidence = session.get(
        Evidence,
        evidence_id,
    )

    if (
        evidence is None
        or evidence.case_id
        != case_id
    ):
        raise HTTPException(
            status_code=404,
            detail="Evidence not found.",
        )

    return evidence


def get_feature_or_404(
    session: Session,
    case_id: int,
    evidence_id: int,
) -> EvidenceFeature:

    statement = (
        select(EvidenceFeature)
        .where(
            EvidenceFeature.evidence_id
            == evidence_id
        )
    )

    feature = (
        session.exec(
            statement
        ).first()
    )

    if (
        feature is None
        or feature.case_id
        != case_id
    ):
        raise HTTPException(
            status_code=404,
            detail=(
                "ML features have not "
                "been extracted yet."
            ),
        )

    return feature


def create_or_update_feature(
    session: Session,
    evidence: Evidence,
) -> EvidenceFeature:

    feature_values = (
        extract_ml_features(
            evidence
        )
    )

    statement = (
        select(EvidenceFeature)
        .where(
            EvidenceFeature.evidence_id
            == evidence.id
        )
    )

    existing = (
        session.exec(
            statement
        ).first()
    )

    if existing is None:

        feature = EvidenceFeature(
            evidence_id=evidence.id,
            case_id=evidence.case_id,
            **feature_values,
        )

        session.add(feature)

    else:

        for (
            key,
            value,
        ) in feature_values.items():

            setattr(
                existing,
                key,
                value,
            )

        feature = existing

        session.add(feature)

    session.commit()

    session.refresh(feature)

    return feature


# =========================================================
# EXTRACT FEATURES
# =========================================================


@router.post(
    "/{case_id}/evidence/{evidence_id}/features/extract",
    response_model=EvidenceFeaturePublic,
)
def extract_features(
    case_id: int,
    evidence_id: int,
    session: SessionDep,
):

    evidence = (
        get_evidence_or_404(
            session,
            case_id,
            evidence_id,
        )
    )

    feature = (
        create_or_update_feature(
            session,
            evidence,
        )
    )

    create_ledger_entry(
        session=session,
        case_id=case_id,
        event_type="FEATURES_EXTRACTED",
        event_data=(
            f"{evidence.evidence_code} | "
            f"FeatureSet={feature.id}"
        ),
    )

    return feature


# =========================================================
# GET ONE FEATURE SET
# =========================================================


@router.get(
    "/{case_id}/evidence/{evidence_id}/features",
    response_model=EvidenceFeaturePublic,
)
def get_features(
    case_id: int,
    evidence_id: int,
    session: SessionDep,
):

    get_evidence_or_404(
        session,
        case_id,
        evidence_id,
    )

    return get_feature_or_404(
        session,
        case_id,
        evidence_id,
    )


# =========================================================
# LABEL EVIDENCE
# =========================================================


@router.post(
    "/{case_id}/evidence/{evidence_id}/label",
    response_model=EvidenceFeaturePublic,
)
def label_evidence(
    case_id: int,
    evidence_id: int,
    payload: EvidenceLabelRequest,
    session: SessionDep,
):

    if payload.label not in (
        0,
        1,
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Label must be 0 "
                "(BENIGN) or 1 "
                "(MALICIOUS)."
            ),
        )

    evidence = (
        get_evidence_or_404(
            session,
            case_id,
            evidence_id,
        )
    )

    feature = (
        get_feature_or_404(
            session,
            case_id,
            evidence_id,
        )
    )

    feature.label = (
        payload.label
    )

    feature.label_name = (
        "BENIGN"
        if payload.label == 0
        else "MALICIOUS"
    )

    feature.labeled_at = (
        datetime.now(
            timezone.utc
        )
    )

    session.add(feature)

    session.commit()

    session.refresh(feature)

    create_ledger_entry(
        session=session,
        case_id=case_id,
        event_type="EVIDENCE_LABELED",
        event_data=(
            f"{evidence.evidence_code} | "
            f"Label={feature.label_name}"
        ),
    )

    return feature


# =========================================================
# GET ALL CASE FEATURES
# =========================================================


@router.get(
    "/{case_id}/features",
    response_model=list[
        EvidenceFeaturePublic
    ],
)
def get_case_features(
    case_id: int,
    session: SessionDep,
):

    forensic_case = session.get(
        Case,
        case_id,
    )

    if forensic_case is None:
        raise HTTPException(
            status_code=404,
            detail="Forensic case not found.",
        )

    statement = (
        select(EvidenceFeature)
        .where(
            EvidenceFeature.case_id
            == case_id
        )
        .order_by(
            EvidenceFeature.id.asc()
        )
    )

    return list(
        session.exec(
            statement
        ).all()
    )


# =========================================================
# DATASET STATUS
# =========================================================


@router.get(
    "/{case_id}/dataset/status",
    response_model=DatasetStatus,
)
def get_dataset_status(
    case_id: int,
    session: SessionDep,
):

    forensic_case = session.get(
        Case,
        case_id,
    )

    if forensic_case is None:
        raise HTTPException(
            status_code=404,
            detail="Forensic case not found.",
        )

    statement = (
        select(EvidenceFeature)
        .where(
            EvidenceFeature.case_id
            == case_id
        )
    )

    features = list(
        session.exec(
            statement
        ).all()
    )

    total = len(features)

    labeled = [
        item
        for item in features
        if item.label is not None
    ]

    benign = sum(
        1
        for item in labeled
        if item.label == 0
    )

    malicious = sum(
        1
        for item in labeled
        if item.label == 1
    )

    minimum_required = 20

    ready = (
        len(labeled)
        >= minimum_required
        and benign >= 5
        and malicious >= 5
    )

    return DatasetStatus(
        total_features=total,
        labeled_samples=len(labeled),
        unlabeled_samples=(
            total - len(labeled)
        ),
        benign_samples=benign,
        malicious_samples=malicious,
        ready_for_training=ready,
        minimum_required=minimum_required,
    )


# =========================================================
# EXPORT DATASET
# =========================================================


@router.get(
    "/{case_id}/dataset/export",
)
def export_dataset(
    case_id: int,
    session: SessionDep,
):

    forensic_case = session.get(
        Case,
        case_id,
    )

    if forensic_case is None:
        raise HTTPException(
            status_code=404,
            detail="Forensic case not found.",
        )

    statement = (
        select(EvidenceFeature)
        .where(
            EvidenceFeature.case_id
            == case_id
        )
        .where(
            EvidenceFeature.label
            != None
        )
    )

    features = list(
        session.exec(
            statement
        ).all()
    )

    if not features:
        raise HTTPException(
            status_code=400,
            detail=(
                "No labeled evidence "
                "available for export."
            ),
        )

    base_dir = (
        Path(__file__)
        .resolve()
        .parent
        .parent
        .parent
    )

    dataset_dir = (
        base_dir
        / "ml"
        / "data"
    )

    dataset_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_file = (
        dataset_dir
        / f"case_{case_id}_dataset.csv"
    )

    columns = (
        [
            "evidence_id",
            "case_id",
        ]
        + FEATURE_COLUMNS
        + [
            "label",
        ]
    )

    with output_file.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=columns,
        )

        writer.writeheader()

        for feature in features:

            row = {
                "evidence_id":
                    feature.evidence_id,

                "case_id":
                    feature.case_id,

                "label":
                    feature.label,
            }

            for column in FEATURE_COLUMNS:

                row[column] = getattr(
                    feature,
                    column,
                )

            writer.writerow(row)

    return FileResponse(
        path=output_file,
        filename=(
            f"case_{case_id}_dataset.csv"
        ),
        media_type="text/csv",
    )