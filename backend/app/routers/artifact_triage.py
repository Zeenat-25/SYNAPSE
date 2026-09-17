import json

from pathlib import Path
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)

from sqlmodel import (
    Session,
    select,
)

from ..artifact_triage import (
    triage_artifact,
)

from ..case_reasoning import (
    build_case_reasoning,
)

from ..database import (
    get_session,
)

from ..ledger import (
    create_ledger_entry,
)

from ..ml_inference import (
    MLModelUnavailableError,
    PEFeatureExtractionError,
    UnsupportedEvidenceError,
)

from ..models import (
    ArtifactTriage,
    Case,
    Evidence,
)


router = APIRouter(
    prefix="/api/triage",
    tags=["Multi-Artifact Triage"],
)


SessionDep = Annotated[
    Session,
    Depends(get_session),
]


def record_to_public(
    record: ArtifactTriage,
    evidence: Evidence,
) -> dict:

    try:

        findings = json.loads(
            record.findings_json
        )

    except json.JSONDecodeError:

        findings = []


    try:

        indicators = json.loads(
            record.indicators_json
        )

    except json.JSONDecodeError:

        indicators = []


    forensic_profile = {
        "domain": None,
        "artifact_type": None,
        "confidence": None,
        "extractor": None,
    }


    for finding in findings:

        if (
            isinstance(finding, dict)
            and finding.get("kind")
            == "FORENSIC_PROFILE"
        ):

            forensic_profile = {
                "domain": finding.get("domain"),
                "artifact_type": finding.get("artifact_type"),
                "confidence": finding.get("confidence"),
                "extractor": finding.get("extractor"),
            }

            break


    image_dimensions = None


    if (
        record.image_width
        is not None
        and
        record.image_height
        is not None
    ):

        image_dimensions = {
            "width":
                record.image_width,

            "height":
                record.image_height,
        }


    return {
        "id":
            record.id,

        "case_id":
            record.case_id,

        "evidence_id":
            record.evidence_id,

        "evidence_code":
            evidence.evidence_code,

        "filename":
            evidence.original_filename,

        "extension":
            evidence.file_extension,

        "analyzer":
            record.analyzer,

        "analysis_method":
            record.analysis_method,

        "domain":
            forensic_profile["domain"],

        "artifact_type":
            forensic_profile["artifact_type"],

        "confidence":
            forensic_profile["confidence"],

        "extractor":
            forensic_profile["extractor"],

        "risk_score":
            record.risk_score,

        "risk_level":
            record.risk_level,

        "entropy":
            record.entropy,

        "predicted_class":
            record.predicted_class,

        "model_name":
            record.model_name,

        "benign_probability":
            record.benign_probability,

        "malicious_probability":
            record.malicious_probability,

        "image_dimensions":
            image_dimensions,

        "findings":
            findings,

        "indicators":
            indicators,

        "limitations":
            record.limitations,

        "created_at":
            record.created_at,
    }


# =========================================================
# RUN TRIAGE + STORE RESULT
# =========================================================


@router.post(
    "/cases/{case_id}/evidence/{evidence_id}",
)
def analyze_evidence(
    case_id: int,
    evidence_id: int,
    session: SessionDep,
):

    forensic_case = session.get(
        Case,
        case_id,
    )


    if forensic_case is None:

        raise HTTPException(
            status_code=404,
            detail=(
                "Forensic case not found."
            ),
        )


    evidence = session.get(
        Evidence,
        evidence_id,
    )


    if (
        evidence is None
        or
        evidence.case_id
        != case_id
    ):

        raise HTTPException(
            status_code=404,
            detail=(
                "Evidence not found."
            ),
        )


    path = Path(
        evidence.stored_path
    )


    try:

        result = triage_artifact(
            path=path,
            extension=(
                evidence.file_extension
            ),
        )


    except FileNotFoundError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error),
        )


    except MLModelUnavailableError as error:

        raise HTTPException(
            status_code=503,
            detail=str(error),
        )


    except (
        PEFeatureExtractionError,
        UnsupportedEvidenceError,
    ) as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )


    except Exception as error:

        raise HTTPException(
            status_code=400,
            detail=(
                "Artifact analysis failed: "
                f"{error}"
            ),
        )


    dimensions = (
        result.get(
            "image_dimensions"
        )
    )


    record = ArtifactTriage(

        case_id=case_id,

        evidence_id=evidence_id,

        analyzer=result.get(
            "analyzer",
            "UNKNOWN_ANALYZER",
        ),

        analysis_method=result.get(
            "analysis_method",
            "Unknown",
        ),

        risk_score=float(
            result.get(
                "risk_score",
                0.0,
            )
        ),

        risk_level=result.get(
            "risk_level",
            "UNASSESSED",
        ),

        entropy=result.get(
            "entropy"
        ),

        predicted_class=result.get(
            "predicted_class"
        ),

        model_name=result.get(
            "model_name"
        ),

        benign_probability=result.get(
            "benign_probability"
        ),

        malicious_probability=result.get(
            "malicious_probability"
        ),

        image_width=(
            dimensions.get(
                "width"
            )
            if dimensions
            else None
        ),

        image_height=(
            dimensions.get(
                "height"
            )
            if dimensions
            else None
        ),

        findings_json=json.dumps(
            result.get(
                "findings",
                [],
            ),
            ensure_ascii=False,
        ),

        indicators_json=json.dumps(
            result.get(
                "indicators",
                [],
            ),
            ensure_ascii=False,
        ),

        limitations=result.get(
            "limitations",
            "",
        ),
    )


    session.add(
        record
    )

    session.commit()

    session.refresh(
        record
    )


    create_ledger_entry(
        session=session,

        case_id=case_id,

        event_type=(
            "MULTI_ARTIFACT_TRIAGE_COMPLETED"
        ),

        event_data=(
            f"{evidence.evidence_code} | "
            f"Analyzer="
            f"{record.analyzer} | "
            f"Risk="
            f"{record.risk_score:.2f}% | "
            f"Level="
            f"{record.risk_level}"
        ),
    )


    return record_to_public(
        record,
        evidence,
    )


# =========================================================
# GET LATEST RESULT FOR ONE ARTIFACT
# =========================================================


@router.get(
    "/cases/{case_id}/evidence/{evidence_id}",
)
def get_latest_triage(
    case_id: int,
    evidence_id: int,
    session: SessionDep,
):

    evidence = session.get(
        Evidence,
        evidence_id,
    )


    if (
        evidence is None
        or
        evidence.case_id
        != case_id
    ):

        raise HTTPException(
            status_code=404,
            detail="Evidence not found.",
        )


    statement = (
        select(ArtifactTriage)
        .where(
            ArtifactTriage.case_id
            == case_id
        )
        .where(
            ArtifactTriage.evidence_id
            == evidence_id
        )
        .order_by(
            ArtifactTriage.created_at.desc()
        )
    )


    record = (
        session.exec(
            statement
        ).first()
    )


    if record is None:

        raise HTTPException(
            status_code=404,
            detail=(
                "This evidence has not "
                "been triaged yet."
            ),
        )


    return record_to_public(
        record,
        evidence,
    )


# =========================================================
# GET LATEST RESULTS FOR WHOLE CASE
# =========================================================


@router.get(
    "/cases/{case_id}",
)
def get_case_triage(
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
            detail=(
                "Forensic case not found."
            ),
        )


    statement = (
        select(ArtifactTriage)
        .where(
            ArtifactTriage.case_id
            == case_id
        )
        .order_by(
            ArtifactTriage.created_at.desc()
        )
    )


    records = list(
        session.exec(
            statement
        ).all()
    )


    latest_by_evidence: dict[
        int,
        ArtifactTriage
    ] = {}


    for record in records:

        if (
            record.evidence_id
            not in latest_by_evidence
        ):

            latest_by_evidence[
                record.evidence_id
            ] = record


    results = []


    for (
        evidence_id,
        record,
    ) in latest_by_evidence.items():

        evidence = session.get(
            Evidence,
            evidence_id,
        )


        if evidence is None:
            continue


        results.append(
            record_to_public(
                record,
                evidence,
            )
        )


    results.sort(
        key=lambda item:
            item["created_at"],
        reverse=True,
    )


    return results


# =========================================================
# CASE-LEVEL FORENSIC REASONING
# =========================================================


@router.get(
    "/cases/{case_id}/reasoning",
)
def get_case_reasoning(
    case_id: int,
    session: SessionDep,
):

    try:

        return build_case_reasoning(
            session=session,
            case_id=case_id,
        )

    except ValueError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error),
        )


# =========================================================
# GET TRIAGE HISTORY
# =========================================================


@router.get(
    "/cases/{case_id}/evidence/{evidence_id}/history",
)
def get_triage_history(
    case_id: int,
    evidence_id: int,
    session: SessionDep,
):

    evidence = session.get(
        Evidence,
        evidence_id,
    )


    if (
        evidence is None
        or
        evidence.case_id
        != case_id
    ):

        raise HTTPException(
            status_code=404,
            detail="Evidence not found.",
        )


    statement = (
        select(ArtifactTriage)
        .where(
            ArtifactTriage.case_id
            == case_id
        )
        .where(
            ArtifactTriage.evidence_id
            == evidence_id
        )
        .order_by(
            ArtifactTriage.created_at.desc()
        )
    )


    records = list(
        session.exec(
            statement
        ).all()
    )


    return [
        record_to_public(
            record,
            evidence,
        )
        for record
        in records
    ]