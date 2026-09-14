from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)

from sqlmodel import Session

from ..blind_spot_engine import (
    build_blind_spot_report,
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
    prefix="/api/blind-spots",
    tags=["Blind Spot Detector"],
)


SessionDep = Annotated[
    Session,
    Depends(get_session),
]


# =========================================================
# GET LIVE BLIND SPOT REPORT
# =========================================================


@router.get(
    "/cases/{case_id}",
)
def get_blind_spots(
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


    return build_blind_spot_report(
        session=session,
        case_id=case_id,
    )


# =========================================================
# RECALCULATE + AUDIT
# =========================================================


@router.post(
    "/cases/{case_id}/recalculate",
)
def recalculate_blind_spots(
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


    result = build_blind_spot_report(
        session=session,
        case_id=case_id,
    )


    summary = result[
        "summary"
    ]


    create_ledger_entry(
        session=session,

        case_id=case_id,

        event_type=(
            "BLIND_SPOT_ANALYSIS_COMPLETED"
        ),

        event_data=(
            f"Analyzed="
            f"{summary['analyzed_evidence']} | "
            f"High="
            f"{summary['high_blind_spots']} | "
            f"Medium="
            f"{summary['medium_blind_spots']} | "
            f"Unreviewed="
            f"{summary['unreviewed_evidence']}"
        ),
    )


    return result