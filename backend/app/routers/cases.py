from datetime import datetime, timezone
from secrets import token_hex
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)

from sqlmodel import Session, select

from ..database import get_session
from ..ledger import create_ledger_entry

from ..models import (
    Case,
    CaseCreate,
    CasePublic,
    LedgerEntry,
    LedgerEntryPublic,
)


router = APIRouter(
    prefix="/api/cases",
    tags=["Cases"],
)


SessionDep = Annotated[
    Session,
    Depends(get_session),
]


def generate_case_code(
    session: Session,
) -> str:

    year = datetime.now(
        timezone.utc
    ).year

    while True:

        random_code = token_hex(3).upper()

        case_code = (
            f"CF-{year}-{random_code}"
        )

        statement = (
            select(Case)
            .where(
                Case.case_code == case_code
            )
        )

        existing_case = (
            session.exec(statement).first()
        )

        if existing_case is None:
            return case_code


@router.post(
    "",
    response_model=CasePublic,
    status_code=status.HTTP_201_CREATED,
)
def create_case(
    case_data: CaseCreate,
    session: SessionDep,
):

    clean_name = case_data.name.strip()

    if len(clean_name) < 2:
        raise HTTPException(
            status_code=422,
            detail=(
                "Case name must contain "
                "at least 2 characters."
            ),
        )

    investigator = (
        case_data.investigator.strip()
        or "Local Analyst"
    )

    case = Case(
        name=clean_name,

        case_type=(
            case_data.case_type.strip()
            or "Endpoint Investigation"
        ),

        description=(
            case_data.description.strip()
        ),

        investigator=investigator,

        case_code=generate_case_code(
            session
        ),

        status="ACTIVE",
    )

    session.add(case)
    session.commit()
    session.refresh(case)

    create_ledger_entry(
        session=session,
        case_id=case.id,
        event_type="CASE_CREATED",
        event_data=(
            f"Case {case.case_code} "
            f"created by "
            f"{case.investigator}"
        ),
    )

    return case


@router.get(
    "",
    response_model=list[CasePublic],
)
def get_cases(
    session: SessionDep,
):

    statement = (
        select(Case)
        .order_by(
            Case.created_at.desc()
        )
    )

    cases = session.exec(
        statement
    ).all()

    return list(cases)


@router.get(
    "/{case_id}",
    response_model=CasePublic,
)
def get_case(
    case_id: int,
    session: SessionDep,
):

    case = session.get(
        Case,
        case_id,
    )

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Forensic case not found.",
        )

    return case


@router.get(
    "/{case_id}/ledger",
    response_model=list[
        LedgerEntryPublic
    ],
)
def get_case_ledger(
    case_id: int,
    session: SessionDep,
):

    case = session.get(
        Case,
        case_id,
    )

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Forensic case not found.",
        )

    statement = (
        select(LedgerEntry)
        .where(
            LedgerEntry.case_id == case_id
        )
        .order_by(
            LedgerEntry.id.asc()
        )
    )

    entries = session.exec(
        statement
    ).all()

    return list(entries)


@router.delete(
    "/{case_id}",
    status_code=204,
)
def delete_case(
    case_id: int,
    session: SessionDep,
):

    case = session.get(
        Case,
        case_id,
    )

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Forensic case not found.",
        )

    create_ledger_entry(
        session=session,
        case_id=case_id,
        event_type="CASE_DELETE_REQUESTED",
        event_data=(
            f"Deletion requested "
            f"for {case.case_code}"
        ),
    )

    session.delete(case)
    session.commit()

    return None