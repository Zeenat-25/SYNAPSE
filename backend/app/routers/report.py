from __future__ import annotations

import hashlib
import re

from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)

from fastapi.responses import Response

from sqlmodel import Session

from ..database import (
    get_session,
)

from ..ledger import (
    create_ledger_entry,
)

from ..models import (
    Case,
)

from ..report_engine import (
    build_forensic_report,
)

from ..report_pdf import (
    build_forensic_pdf,
)


router = APIRouter(
    prefix="/api/report",
    tags=[
        "Forensic Report"
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
            detail="Forensic case not found.",
        )

    return forensic_case


# =========================================================
# PDF EXPORT METADATA
# =========================================================


def enable_pdf_export_metadata(
    report: dict,
    case_id: int,
) -> dict:

    export = report.setdefault(
        "export",
        {},
    )

    export["json_ready"] = True
    export["pdf_ready"] = True
    export["pdf_phase"] = "15B"
    export["pdf_method"] = "POST"

    export["pdf_endpoint"] = (
        f"/api/report/cases/{case_id}/pdf"
    )

    return report


# =========================================================
# SAFE FILE NAME
# =========================================================


def sanitize_filename_part(
    value: str,
) -> str:

    value = value.strip()

    value = re.sub(
        r"[^A-Za-z0-9._-]+",
        "_",
        value,
    )

    value = value.strip(
        "._"
    )

    return value or "case"


def build_pdf_filename(
    forensic_case: Case,
) -> str:

    case_code = (
        sanitize_filename_part(
            forensic_case.case_code
        )
    )

    case_name = (
        sanitize_filename_part(
            forensic_case.name
        )
    )

    return (
        f"SYNAPSE_"
        f"{case_code}_"
        f"{case_name}_"
        f"Forensic_Report.pdf"
    )


# =========================================================
# COMPLETE STRUCTURED REPORT
# =========================================================


@router.get(
    "/cases/{case_id}",
)
def get_case_report(
    case_id: int,
    session: SessionDep,
):

    ensure_case_exists(
        session=session,
        case_id=case_id,
    )

    try:

        report = (
            build_forensic_report(
                session=session,
                case_id=case_id,
            )
        )

        return (
            enable_pdf_export_metadata(
                report=report,
                case_id=case_id,
            )
        )

    except ValueError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error


# =========================================================
# EXECUTIVE SUMMARY
# =========================================================


@router.get(
    "/cases/{case_id}/summary",
)
def get_case_report_summary(
    case_id: int,
    session: SessionDep,
):

    ensure_case_exists(
        session=session,
        case_id=case_id,
    )

    try:

        report = (
            build_forensic_report(
                session=session,
                case_id=case_id,
            )
        )

        report = (
            enable_pdf_export_metadata(
                report=report,
                case_id=case_id,
            )
        )

        return {
            "case":
                report["case"],

            "generated_at":
                report["generated_at"],

            "executive_summary":
                report["executive_summary"],

            "limitations":
                report["limitations"],

            "export":
                report["export"],
        }

    except ValueError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error


# =========================================================
# PDF EXPORT
# =========================================================


@router.post(
    "/cases/{case_id}/pdf",
    response_class=Response,
)
def export_case_report_pdf(
    case_id: int,
    session: SessionDep,
):

    forensic_case = (
        ensure_case_exists(
            session=session,
            case_id=case_id,
        )
    )

    try:

        report = (
            build_forensic_report(
                session=session,
                case_id=case_id,
            )
        )

        report = (
            enable_pdf_export_metadata(
                report=report,
                case_id=case_id,
            )
        )

        pdf_bytes = (
            build_forensic_pdf(
                report
            )
        )

    except ValueError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error),
        ) from error

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to generate forensic "
                f"PDF report: {error}"
            ),
        ) from error


    pdf_sha256 = (
        hashlib.sha256(
            pdf_bytes
        )
        .hexdigest()
    )


    filename = (
        build_pdf_filename(
            forensic_case
        )
    )


    create_ledger_entry(
        session=session,
        case_id=case_id,
        event_type="FORENSIC_REPORT_EXPORTED",
        event_data=(
            f"Filename={filename} | "
            f"SHA256={pdf_sha256} | "
            f"Size={len(pdf_bytes)} bytes | "
            f"ReportVersion="
            f"{report.get('report_version', '1.0')}"
        ),
    )


    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition":
                (
                    "attachment; "
                    f'filename="{filename}"'
                ),

            "Content-Length":
                str(
                    len(
                        pdf_bytes
                    )
                ),

            "X-SYNAPSE-Report-SHA256":
                pdf_sha256,

            "X-SYNAPSE-Report-Version":
                str(
                    report.get(
                        "report_version",
                        "1.0",
                    )
                ),
        },
    )