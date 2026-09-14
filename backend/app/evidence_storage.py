from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"

EVIDENCE_ROOT = DATA_DIR / "evidence"


def get_case_evidence_directory(
    case_id: int,
) -> Path:

    directory = (
        EVIDENCE_ROOT
        / f"case_{case_id}"
    )

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return directory