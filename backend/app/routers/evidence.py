from datetime import datetime, timezone
from pathlib import Path
from secrets import token_hex
from typing import Annotated
from uuid import uuid4

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    UploadFile,
    status,
)

from sqlmodel import (
    Session,
    select,
)

from ..database import (
    get_session,
)

from ..evidence_storage import (
    get_case_evidence_directory,
    is_supabase_reference,
    materialize_evidence_file,
    persist_evidence_file,
)

from ..feature_extraction import (
    extract_ml_features,
)

from ..forensics import (
    calculate_entropy,
    calculate_hashes,
    get_extension,
)

from ..ledger import (
    create_ledger_entry,
)

from ..models import (
    Case,
    Evidence,
    EvidenceFeature,
    EvidencePublic,
)


router = APIRouter(
    prefix="/api/cases",
    tags=["Evidence"],
)


SessionDep = Annotated[
    Session,
    Depends(get_session),
]


MAX_FILE_SIZE = (
    100
    * 1024
    * 1024
)


def generate_evidence_code(
    session: Session,
) -> str:

    while True:

        code = (
            f"EV-{token_hex(4).upper()}"
        )

        statement = (
            select(Evidence)
            .where(
                Evidence.evidence_code
                == code
            )
        )

        existing = (
            session.exec(
                statement
            ).first()
        )

        if existing is None:
            return code


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


@router.post(
    "/{case_id}/evidence",
    response_model=EvidencePublic,
    status_code=status.HTTP_201_CREATED,
)
async def upload_evidence(
    case_id: int,
    session: SessionDep,
    file: UploadFile = File(...),
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

    original_filename = (
        Path(
            file.filename
            or ""
        ).name
    )

    if not original_filename:

        raise HTTPException(
            status_code=400,
            detail=(
                "Uploaded file has "
                "no valid filename."
            ),
        )

    extension = get_extension(
        original_filename
    )

    safe_extension = (
        ""
        if extension == "none"
        else extension
    )

    stored_filename = (
        f"{uuid4().hex}"
        f"{safe_extension}"
    )

    case_directory = (
        get_case_evidence_directory(
            case_id
        )
    )

    destination = (
        case_directory
        / stored_filename
    )

    total_size = 0

    chunk_size = (
        1024
        * 1024
    )

    try:

        with destination.open(
            "wb"
        ) as output_file:

            while True:

                chunk = await file.read(
                    chunk_size
                )

                if not chunk:
                    break

                total_size += len(
                    chunk
                )

                if (
                    total_size
                    > MAX_FILE_SIZE
                ):

                    raise HTTPException(
                        status_code=413,
                        detail=(
                            "File exceeds "
                            "the 100 MB "
                            "MVP upload limit."
                        ),
                    )

                output_file.write(
                    chunk
                )

    except Exception:

        if destination.exists():
            destination.unlink()

        raise

    finally:

        await file.close()

    if total_size == 0:

        if destination.exists():
            destination.unlink()

        raise HTTPException(
            status_code=400,
            detail=(
                "Empty files cannot "
                "be uploaded."
            ),
        )

    hashes = calculate_hashes(
        destination
    )

    entropy = calculate_entropy(
        destination
    )

    mime_type = (
        file.content_type
        or "application/octet-stream"
    )

    try:

        durable_stored_path = (
            persist_evidence_file(
                local_path=destination,
                case_id=case_id,
                stored_filename=(
                    stored_filename
                ),
                content_type=mime_type,
            )
        )

    except Exception as error:

        if destination.exists():
            destination.unlink()

        raise HTTPException(
            status_code=502,
            detail=(
                "Evidence could not be "
                "saved to durable storage."
            ),
        ) from error

    evidence = Evidence(

        evidence_code=(
            generate_evidence_code(
                session
            )
        ),

        case_id=case_id,

        original_filename=(
            original_filename
        ),

        stored_filename=(
            stored_filename
        ),

        stored_path=(
            durable_stored_path
        ),

        file_extension=extension,

        mime_type=mime_type,

        file_size=total_size,

        sha256=hashes[
            "sha256"
        ],

        sha1=hashes[
            "sha1"
        ],

        md5=hashes[
            "md5"
        ],

        entropy=entropy,

        integrity_status=(
            "VERIFIED"
        ),

        verified_at=(
            datetime.now(
                timezone.utc
            )
        ),

        status="REGISTERED",
    )

    session.add(
        evidence
    )

    session.commit()

    session.refresh(
        evidence
    )

    # =====================================================
    # AUTOMATIC FEATURE EXTRACTION
    # =====================================================

    feature_values = (
        extract_ml_features(
            evidence
        )
    )

    feature = EvidenceFeature(

        evidence_id=evidence.id,

        case_id=case_id,

        **feature_values,
    )

    session.add(
        feature
    )

    session.commit()

    session.refresh(
        feature
    )

    create_ledger_entry(

        session=session,

        case_id=case_id,

        event_type=(
            "EVIDENCE_REGISTERED"
        ),

        event_data=(
            f"{evidence.evidence_code} | "
            f"{evidence.original_filename} | "
            f"SHA256={evidence.sha256}"
        ),
    )

    create_ledger_entry(

        session=session,

        case_id=case_id,

        event_type=(
            "FEATURES_EXTRACTED"
        ),

        event_data=(
            f"{evidence.evidence_code} | "
            f"FeatureSet={feature.id}"
        ),
    )

    # Supabase now owns the durable copy.
    # Remove only the temporary Render copy.
    if (
        is_supabase_reference(
            durable_stored_path
        )
        and destination.exists()
    ):
        destination.unlink()

    return evidence


@router.get(
    "/{case_id}/evidence",
    response_model=list[
        EvidencePublic
    ],
)
def get_case_evidence(
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
        select(Evidence)
        .where(
            Evidence.case_id
            == case_id
        )
        .order_by(
            Evidence.uploaded_at.desc()
        )
    )

    results = (
        session.exec(
            statement
        ).all()
    )

    return list(
        results
    )


@router.get(
    "/{case_id}/evidence/{evidence_id}",
    response_model=EvidencePublic,
)
def get_evidence(
    case_id: int,
    evidence_id: int,
    session: SessionDep,
):

    return get_evidence_or_404(
        session=session,
        case_id=case_id,
        evidence_id=evidence_id,
    )


@router.post(
    "/{case_id}/evidence/{evidence_id}/verify",
    response_model=EvidencePublic,
)
def verify_evidence_integrity(
    case_id: int,
    evidence_id: int,
    session: SessionDep,
):

    evidence = (
        get_evidence_or_404(
            session=session,
            case_id=case_id,
            evidence_id=evidence_id,
        )
    )

    try:

        file_path = (
            materialize_evidence_file(
                stored_path=(
                    evidence.stored_path
                ),
                case_id=case_id,
                stored_filename=(
                    evidence.stored_filename
                ),
                force_refresh=True,
            )
        )

    except FileNotFoundError:

        evidence.integrity_status = (
            "MISSING"
        )

        session.add(
            evidence
        )

        session.commit()

        session.refresh(
            evidence
        )

        create_ledger_entry(

            session=session,

            case_id=case_id,

            event_type=(
                "EVIDENCE_MISSING"
            ),

            event_data=(
                f"{evidence.evidence_code} | "
                f"{evidence.original_filename}"
            ),
        )

        return evidence

    except Exception as error:

        raise HTTPException(
            status_code=503,
            detail=(
                "Evidence storage is "
                "temporarily unavailable."
            ),
        ) from error

    current_hashes = (
        calculate_hashes(
            file_path
        )
    )

    current_sha256 = (
        current_hashes[
            "sha256"
        ]
    )

    if (
        current_sha256
        == evidence.sha256
    ):

        evidence.integrity_status = (
            "VERIFIED"
        )

        event_type = (
            "INTEGRITY_VERIFIED"
        )

    else:

        evidence.integrity_status = (
            "FAILED"
        )

        event_type = (
            "INTEGRITY_FAILURE"
        )

    evidence.verified_at = (
        datetime.now(
            timezone.utc
        )
    )

    session.add(
        evidence
    )

    session.commit()

    session.refresh(
        evidence
    )

    create_ledger_entry(

        session=session,

        case_id=case_id,

        event_type=event_type,

        event_data=(
            f"{evidence.evidence_code} | "
            f"{evidence.original_filename} | "
            f"Original={evidence.sha256} | "
            f"Current={current_sha256}"
        ),
    )

    return evidence