from pathlib import Path
from typing import Annotated
from uuid import uuid4

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    UploadFile,
)

from sqlmodel import (
    Session,
)

from ..database import (
    get_session,
)

from ..dataset_importer import (
    import_feature_dataset,
)

from ..ledger import (
    create_ledger_entry,
)

from ..models import (
    Case,
)


router = APIRouter(
    prefix="/api/dataset",
    tags=["Dataset Import"],
)


SessionDep = Annotated[
    Session,
    Depends(get_session),
]


BASE_DIR = (
    Path(__file__)
    .resolve()
    .parent
    .parent
    .parent
)


IMPORT_DIR = (
    BASE_DIR
    / "ml"
    / "imports"
)


IMPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


@router.post(
    "/cases/{case_id}/import",
)
async def import_dataset(
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
            detail=(
                "Forensic case not found."
            ),
        )


    original_name = (
        Path(
            file.filename
            or ""
        ).name
    )


    if not original_name:

        raise HTTPException(
            status_code=400,
            detail=(
                "Dataset filename is invalid."
            ),
        )


    if (
        Path(original_name)
        .suffix.lower()
        != ".csv"
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "Only CSV datasets "
                "are supported."
            ),
        )


    stored_name = (
        f"{uuid4().hex}.csv"
    )


    destination = (
        IMPORT_DIR
        / stored_name
    )


    try:

        with destination.open(
            "wb"
        ) as output:

            while True:

                chunk = await file.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                output.write(
                    chunk
                )

    finally:

        await file.close()


    result = (
        import_feature_dataset(
            session=session,
            case_id=case_id,
            csv_path=destination,
        )
    )


    if not result.get(
        "success"
    ):

        raise HTTPException(
            status_code=400,
            detail=result,
        )


    create_ledger_entry(

        session=session,

        case_id=case_id,

        event_type=(
            "DATASET_IMPORTED"
        ),

        event_data=(
            f"File={original_name} | "
            f"Imported="
            f"{result['imported']} | "
            f"Benign="
            f"{result['benign']} | "
            f"Malicious="
            f"{result['malicious']}"
        ),
    )


    return result