from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)

from sqlmodel import Session

from ..correlation_engine import (
    build_correlation_report,
)

from ..database import (
    get_session,
)

from ..ledger import (
    create_ledger_entry,
)

from ..models import (
    Case,
)


router = APIRouter(
    prefix="/api/correlation",
    tags=[
        "Advanced Evidence Correlation"
    ],
)


SessionDep = Annotated[
    Session,
    Depends(get_session),
]


# =========================================================
# LIVE CORRELATION REPORT
# =========================================================


@router.get(
    "/cases/{case_id}",
)
def get_case_correlations(
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


    return build_correlation_report(
        session=session,
        case_id=case_id,
    )


# =========================================================
# RECALCULATE + AUDIT
# =========================================================


@router.post(
    "/cases/{case_id}/recalculate",
)
def recalculate_case_correlations(
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


    report = (
        build_correlation_report(
            session=session,
            case_id=case_id,
        )
    )


    summary = (
        report[
            "summary"
        ]
    )


    create_ledger_entry(

        session=session,

        case_id=case_id,

        event_type=(
            "EVIDENCE_CORRELATION_COMPLETED"
        ),

        event_data=(
            "Advanced evidence correlation recalculated | "
            f"Relationships="
            f"{summary['total_relationships']} | "
            f"Strong="
            f"{summary['strong_relationships']} | "
            f"Medium="
            f"{summary['medium_relationships']} | "
            f"Clusters="
            f"{summary['clusters']}"
        ),
    )


    return report