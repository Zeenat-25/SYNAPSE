import csv
from pathlib import Path

from sqlmodel import (
    Session,
    select,
)

from .models import (
    EvidenceFeature,
)


REQUIRED_COLUMNS = [
    "file_size_bytes",
    "entropy",
    "filename_length",
    "extension_length",
    "is_executable",
    "is_script",
    "is_archive",
    "is_document",
    "is_image",
    "is_database",
    "is_hidden",
    "has_double_extension",
    "suspicious_extension",
    "suspicious_keyword",
    "high_entropy",
    "mime_is_executable",
    "mime_is_archive",
    "label",
]


def parse_int(
    value: str,
    default: int = 0,
) -> int:

    try:
        return int(
            float(value)
        )
    except (
        TypeError,
        ValueError,
    ):
        return default


def parse_float(
    value: str,
    default: float = 0.0,
) -> float:

    try:
        return float(value)
    except (
        TypeError,
        ValueError,
    ):
        return default


def validate_dataset_columns(
    columns: list[str],
) -> list[str]:

    missing = [
        column
        for column
        in REQUIRED_COLUMNS
        if column not in columns
    ]

    return missing


def import_feature_dataset(
    session: Session,
    case_id: int,
    csv_path: Path,
) -> dict:

    if not csv_path.exists():

        return {
            "success": False,
            "message": (
                "Dataset file does not exist."
            ),
            "imported": 0,
            "skipped": 0,
        }


    imported = 0
    skipped = 0

    benign = 0
    malicious = 0


    with csv_path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:

        reader = csv.DictReader(file)

        if reader.fieldnames is None:

            return {
                "success": False,
                "message": (
                    "Dataset has no header row."
                ),
                "imported": 0,
                "skipped": 0,
            }


        missing = (
            validate_dataset_columns(
                list(
                    reader.fieldnames
                )
            )
        )


        if missing:

            return {
                "success": False,

                "message": (
                    "Dataset is missing "
                    "required columns."
                ),

                "missing_columns":
                    missing,

                "imported": 0,

                "skipped": 0,
            }


        synthetic_id = (
            1_000_000
        )


        statement = (
            select(EvidenceFeature)
            .where(
                EvidenceFeature.case_id
                == case_id
            )
            .order_by(
                EvidenceFeature.evidence_id
                .desc()
            )
        )


        existing = list(
            session.exec(
                statement
            ).all()
        )


        if existing:

            highest = max(
                item.evidence_id
                for item in existing
            )

            synthetic_id = max(
                synthetic_id,
                highest + 1,
            )


        for row in reader:

            label = parse_int(
                row.get(
                    "label",
                    "",
                ),
                default=-1,
            )


            if label not in (
                0,
                1,
            ):

                skipped += 1
                continue


            feature = EvidenceFeature(

                evidence_id=synthetic_id,

                case_id=case_id,

                file_size_bytes=(
                    parse_int(
                        row[
                            "file_size_bytes"
                        ]
                    )
                ),

                entropy=(
                    parse_float(
                        row[
                            "entropy"
                        ]
                    )
                ),

                filename_length=(
                    parse_int(
                        row[
                            "filename_length"
                        ]
                    )
                ),

                extension_length=(
                    parse_int(
                        row[
                            "extension_length"
                        ]
                    )
                ),

                is_executable=(
                    parse_int(
                        row[
                            "is_executable"
                        ]
                    )
                ),

                is_script=(
                    parse_int(
                        row[
                            "is_script"
                        ]
                    )
                ),

                is_archive=(
                    parse_int(
                        row[
                            "is_archive"
                        ]
                    )
                ),

                is_document=(
                    parse_int(
                        row[
                            "is_document"
                        ]
                    )
                ),

                is_image=(
                    parse_int(
                        row[
                            "is_image"
                        ]
                    )
                ),

                is_database=(
                    parse_int(
                        row[
                            "is_database"
                        ]
                    )
                ),

                is_hidden=(
                    parse_int(
                        row[
                            "is_hidden"
                        ]
                    )
                ),

                has_double_extension=(
                    parse_int(
                        row[
                            "has_double_extension"
                        ]
                    )
                ),

                suspicious_extension=(
                    parse_int(
                        row[
                            "suspicious_extension"
                        ]
                    )
                ),

                suspicious_keyword=(
                    parse_int(
                        row[
                            "suspicious_keyword"
                        ]
                    )
                ),

                high_entropy=(
                    parse_int(
                        row[
                            "high_entropy"
                        ]
                    )
                ),

                mime_is_executable=(
                    parse_int(
                        row[
                            "mime_is_executable"
                        ]
                    )
                ),

                mime_is_archive=(
                    parse_int(
                        row[
                            "mime_is_archive"
                        ]
                    )
                ),

                label=label,

                label_name=(
                    "BENIGN"
                    if label == 0
                    else "MALICIOUS"
                ),
            )


            session.add(
                feature
            )


            if label == 0:
                benign += 1
            else:
                malicious += 1


            synthetic_id += 1

            imported += 1


        session.commit()


    return {

        "success": True,

        "message": (
            "Dataset imported successfully."
        ),

        "imported":
            imported,

        "skipped":
            skipped,

        "benign":
            benign,

        "malicious":
            malicious,
    }