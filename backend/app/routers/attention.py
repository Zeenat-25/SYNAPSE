from datetime import datetime, timezone
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

from ..attention_models import (
    AttentionCaseSummary,
    AttentionUpdate,
    EvidenceAttention,
    EvidenceAttentionPublic,
)

from ..database import (
    get_session,
)

from ..ledger import (
    create_ledger_entry,
)

from ..models import (
    Case,
    Evidence,
)


router = APIRouter(
    prefix="/api/attention",
    tags=["Investigator Attention"],
)


SessionDep = Annotated[
    Session,
    Depends(get_session),
]


def utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


# =========================================================
# RECORD / UPDATE ATTENTION
# =========================================================


@router.post(
    "/cases/{case_id}/evidence/{evidence_id}",
    response_model=EvidenceAttentionPublic,
)
def record_attention(
    case_id: int,
    evidence_id: int,
    payload: AttentionUpdate,
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


    statement = (
        select(EvidenceAttention)
        .where(
            EvidenceAttention.case_id
            == case_id
        )
        .where(
            EvidenceAttention.evidence_id
            == evidence_id
        )
    )


    attention = (
        session.exec(
            statement
        ).first()
    )


    now = utc_now()


    first_review = False


    if attention is None:

        attention = EvidenceAttention(
            case_id=case_id,
            evidence_id=evidence_id,
        )

        session.add(
            attention
        )

        session.flush()

        first_review = True


    if payload.new_view:

        previous_views = (
            attention.view_count
        )


        attention.view_count += 1


        if previous_views >= 1:

            attention.revisit_count += 1


        if (
            attention.first_viewed_at
            is None
        ):

            attention.first_viewed_at = (
                now
            )


        attention.last_viewed_at = (
            now
        )


    dwell = max(
        0.0,
        float(
            payload.dwell_seconds
        ),
    )


    focused = max(
        0.0,
        min(
            float(
                payload.focused_seconds
            ),
            dwell,
        ),
    )


    attention.total_view_seconds += (
        dwell
    )


    attention.focused_seconds += (
        focused
    )


    attention.longest_view_seconds = max(
        attention.longest_view_seconds,
        dwell,
    )


    attention.updated_at = (
        now
    )


    session.add(
        attention
    )

    session.commit()

    session.refresh(
        attention
    )


    if first_review:

        create_ledger_entry(
            session=session,

            case_id=case_id,

            event_type=(
                "EVIDENCE_REVIEW_STARTED"
            ),

            event_data=(
                f"{evidence.evidence_code} | "
                f"Investigator began reviewing "
                f"{evidence.original_filename}"
            ),
        )


    return attention


# =========================================================
# GET ATTENTION FOR ONE ARTIFACT
# =========================================================


@router.get(
    "/cases/{case_id}/evidence/{evidence_id}",
    response_model=EvidenceAttentionPublic,
)
def get_evidence_attention(
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
            detail=(
                "Evidence not found."
            ),
        )


    statement = (
        select(EvidenceAttention)
        .where(
            EvidenceAttention.case_id
            == case_id
        )
        .where(
            EvidenceAttention.evidence_id
            == evidence_id
        )
    )


    attention = (
        session.exec(
            statement
        ).first()
    )


    if attention is None:

        raise HTTPException(
            status_code=404,
            detail=(
                "This evidence has not "
                "been reviewed yet."
            ),
        )


    return attention


# =========================================================
# GET ALL ATTENTION RECORDS
# =========================================================


@router.get(
    "/cases/{case_id}",
    response_model=list[
        EvidenceAttentionPublic
    ],
)
def get_case_attention(
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
        select(EvidenceAttention)
        .where(
            EvidenceAttention.case_id
            == case_id
        )
        .order_by(
            EvidenceAttention.updated_at.desc()
        )
    )


    return list(
        session.exec(
            statement
        ).all()
    )


# =========================================================
# CASE ATTENTION SUMMARY
# =========================================================


@router.get(
    "/cases/{case_id}/summary",
    response_model=AttentionCaseSummary,
)
def get_attention_summary(
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


    evidence_statement = (
        select(Evidence)
        .where(
            Evidence.case_id
            == case_id
        )
    )


    evidence_items = list(
        session.exec(
            evidence_statement
        ).all()
    )


    attention_statement = (
        select(EvidenceAttention)
        .where(
            EvidenceAttention.case_id
            == case_id
        )
    )


    attention_items = list(
        session.exec(
            attention_statement
        ).all()
    )


    total_evidence = len(
        evidence_items
    )


    reviewed_evidence = len(
        [
            item
            for item
            in attention_items
            if item.view_count > 0
        ]
    )


    unreviewed_evidence = max(
        total_evidence
        -
        reviewed_evidence,
        0,
    )


    total_view_seconds = round(
        sum(
            item.total_view_seconds
            for item
            in attention_items
        ),
        2,
    )


    total_views = sum(
        item.view_count
        for item
        in attention_items
    )


    total_revisits = sum(
        item.revisit_count
        for item
        in attention_items
    )


    if reviewed_evidence > 0:

        average_view_seconds = round(
            total_view_seconds
            /
            reviewed_evidence,
            2,
        )

    else:

        average_view_seconds = 0.0


    if total_evidence > 0:

        coverage_percent = round(
            (
                reviewed_evidence
                /
                total_evidence
            )
            * 100,
            2,
        )

    else:

        coverage_percent = 0.0


    return AttentionCaseSummary(

        case_id=case_id,

        total_evidence=(
            total_evidence
        ),

        reviewed_evidence=(
            reviewed_evidence
        ),

        unreviewed_evidence=(
            unreviewed_evidence
        ),

        total_view_seconds=(
            total_view_seconds
        ),

        average_view_seconds=(
            average_view_seconds
        ),

        total_views=(
            total_views
        ),

        total_revisits=(
            total_revisits
        ),

        coverage_percent=(
            coverage_percent
        ),
    )