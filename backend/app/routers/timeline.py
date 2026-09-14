from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)

from sqlmodel import Session

from ..database import (
    get_session,
)

from ..models import (
    Case,
)

from ..replay_engine import (
    build_investigation_replay,
    get_replay_step,
)

from ..timeline_engine import (
    build_investigation_timeline,
)


router = APIRouter(
    prefix="/api/timeline",
    tags=[
        "Investigation Timeline"
    ],
)


SessionDep = Annotated[
    Session,
    Depends(get_session),
]


# =========================================================
# CASE CHECK
# =========================================================


def ensure_case_exists(
    session: Session,
    case_id: int,
) -> Case:

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


    return forensic_case


# =========================================================
# COMPLETE TIMELINE
# =========================================================


@router.get(
    "/cases/{case_id}",
)
def get_case_timeline(
    case_id: int,
    session: SessionDep,
):

    ensure_case_exists(
        session=session,
        case_id=case_id,
    )


    try:

        return (
            build_investigation_timeline(
                session=session,
                case_id=case_id,
            )
        )


    except ValueError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error


# =========================================================
# COMPLETE REPLAY
# =========================================================


@router.get(
    "/cases/{case_id}/replay",
)
def get_case_replay(
    case_id: int,
    session: SessionDep,
):

    ensure_case_exists(
        session=session,
        case_id=case_id,
    )


    try:

        return (
            build_investigation_replay(
                session=session,
                case_id=case_id,
            )
        )


    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error


# =========================================================
# ONE REPLAY STEP
# =========================================================


@router.get(
    "/cases/{case_id}/replay/{step}",
)
def get_case_replay_step(
    case_id: int,
    step: int,
    session: SessionDep,
):

    ensure_case_exists(
        session=session,
        case_id=case_id,
    )


    try:

        return (
            get_replay_step(
                session=session,
                case_id=case_id,
                step=step,
            )
        )


    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error