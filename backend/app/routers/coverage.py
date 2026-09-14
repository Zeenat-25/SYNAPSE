from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)

from sqlmodel import Session

from ..coverage_engine import (
    build_case_coverage_report,
)

from ..database import (
    get_session,
)

from ..models import (
    Case,
)


router = APIRouter(
    prefix="/api/coverage",
    tags=["Investigation Coverage"],
)


SessionDep = Annotated[
    Session,
    Depends(get_session),
]


# =========================================================
# COMPLETE CASE COVERAGE
# =========================================================


@router.get(
    "/cases/{case_id}",
)
def get_case_coverage(
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


    return build_case_coverage_report(
        session=session,
        case_id=case_id,
    )


# =========================================================
# ONE EVIDENCE COVERAGE
# =========================================================


@router.get(
    "/cases/{case_id}/evidence/{evidence_id}",
)
def get_evidence_coverage(
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


    report = (
        build_case_coverage_report(
            session=session,
            case_id=case_id,
        )
    )


    for item in report[
        "evidence_coverage"
    ]:

        if (
            item[
                "evidence_id"
            ]
            == evidence_id
        ):

            return item


    raise HTTPException(
        status_code=404,
        detail=(
            "Evidence not found."
        ),
    )