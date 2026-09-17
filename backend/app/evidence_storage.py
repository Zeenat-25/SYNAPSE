from __future__ import annotations

from pathlib import Path

from .database import DATA_DIR


# Evidence uses the SAME persistent data directory as synapse.db.
# Local default: backend/data/evidence/
# Render with SYNAPSE_DATA_DIR=/var/data: /var/data/evidence/

EVIDENCE_ROOT = DATA_DIR / "evidence"

EVIDENCE_ROOT.mkdir(
    parents=True,
    exist_ok=True,
)


def get_case_evidence_directory(
    case_id: int,
) -> Path:
    directory = EVIDENCE_ROOT / f"case_{case_id}"

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return directory
