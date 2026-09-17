from __future__ import annotations

import os
from pathlib import Path
from threading import Lock
from typing import Final

from supabase import Client, create_client

from .database import DATA_DIR


# =========================================================
# LOCAL CACHE / FALLBACK STORAGE
# =========================================================
#
# Local development without Supabase:
#   backend/data/evidence/case_<id>/
#
# Render production with Supabase configured:
#   Files are uploaded to the private Supabase Storage bucket.
#   A small local cache is still used temporarily when SYNAPSE
#   needs a real filesystem Path for hashing, PE analysis,
#   PDF/text extraction, OCR, verification, etc.
# =========================================================

EVIDENCE_ROOT: Final[Path] = (
    DATA_DIR
    / "evidence"
)

EVIDENCE_CACHE_ROOT: Final[Path] = (
    DATA_DIR
    / "evidence_cache"
)

EVIDENCE_ROOT.mkdir(
    parents=True,
    exist_ok=True,
)

EVIDENCE_CACHE_ROOT.mkdir(
    parents=True,
    exist_ok=True,
)


# =========================================================
# SUPABASE STORAGE CONFIGURATION
# =========================================================

SUPABASE_URL: Final[str] = (
    os.getenv(
        "SUPABASE_URL",
        "",
    )
    .strip()
    .rstrip("/")
)

SUPABASE_SECRET_KEY: Final[str] = (
    os.getenv(
        "SUPABASE_SECRET_KEY",
        "",
    )
    .strip()
)

SUPABASE_BUCKET: Final[str] = (
    os.getenv(
        "SUPABASE_BUCKET",
        "synapse-evidence",
    )
    .strip()
)

SUPABASE_REFERENCE_PREFIX: Final[str] = (
    "supabase://"
)


_supabase_client: Client | None = None
_supabase_client_lock = Lock()


def using_supabase_storage() -> bool:
    """
    True only when all server-side Supabase Storage settings
    are available.

    Local development can therefore continue to use the local
    filesystem without requiring Supabase credentials.
    """

    return bool(
        SUPABASE_URL
        and SUPABASE_SECRET_KEY
        and SUPABASE_BUCKET
    )


def get_supabase_client() -> Client:
    """
    Lazily create one Supabase client for the backend process.

    The secret key must remain server-side only.
    """

    global _supabase_client

    if not using_supabase_storage():
        raise RuntimeError(
            "Supabase Storage is not configured. "
            "Set SUPABASE_URL, SUPABASE_SECRET_KEY, "
            "and SUPABASE_BUCKET."
        )

    if _supabase_client is not None:
        return _supabase_client

    with _supabase_client_lock:

        if _supabase_client is None:
            _supabase_client = create_client(
                SUPABASE_URL,
                SUPABASE_SECRET_KEY,
            )

    return _supabase_client


# =========================================================
# PATH HELPERS
# =========================================================

def get_case_evidence_directory(
    case_id: int,
) -> Path:
    """
    Return a local working directory for uploads.

    In production this directory is only temporary/cache storage.
    The durable copy is stored in Supabase Storage.
    """

    directory = (
        EVIDENCE_ROOT
        / f"case_{case_id}"
    )

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return directory


def get_case_cache_directory(
    case_id: int,
) -> Path:
    """
    Local cache used when a Supabase object must be materialized
    into a real filesystem Path for forensic analysis.
    """

    directory = (
        EVIDENCE_CACHE_ROOT
        / f"case_{case_id}"
    )

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return directory


def get_storage_object_path(
    case_id: int,
    stored_filename: str,
) -> str:
    """
    Object key inside the private bucket.

    Example:
        case_12/3b9a....pdf
    """

    safe_filename = (
        Path(stored_filename)
        .name
    )

    if not safe_filename:
        raise ValueError(
            "Stored filename is invalid."
        )

    return (
        f"case_{case_id}/"
        f"{safe_filename}"
    )


def make_supabase_reference(
    object_path: str,
) -> str:
    """
    Store a durable, non-public reference in Evidence.stored_path.

    Example:
        supabase://synapse-evidence/case_12/file.pdf
    """

    clean_path = (
        object_path
        .strip()
        .lstrip("/")
    )

    return (
        f"{SUPABASE_REFERENCE_PREFIX}"
        f"{SUPABASE_BUCKET}/"
        f"{clean_path}"
    )


def is_supabase_reference(
    stored_path: str,
) -> bool:

    return (
        stored_path
        .strip()
        .startswith(
            SUPABASE_REFERENCE_PREFIX
        )
    )


def parse_supabase_reference(
    stored_path: str,
) -> tuple[str, str]:
    """
    Return:
        (bucket_name, object_path)
    """

    value = (
        stored_path
        .strip()
    )

    if not is_supabase_reference(
        value
    ):
        raise ValueError(
            "Not a Supabase Storage reference."
        )

    remainder = value[
        len(
            SUPABASE_REFERENCE_PREFIX
        ):
    ]

    bucket, separator, object_path = (
        remainder.partition("/")
    )

    if (
        not separator
        or not bucket
        or not object_path
    ):
        raise ValueError(
            "Invalid Supabase Storage reference."
        )

    return (
        bucket,
        object_path,
    )


# =========================================================
# DURABLE UPLOAD
# =========================================================

def persist_evidence_file(
    *,
    local_path: Path,
    case_id: int,
    stored_filename: str,
    content_type: str,
) -> str:
    """
    Persist evidence durably.

    Production:
        upload -> Supabase Storage
        return -> supabase://... reference

    Local development without Supabase:
        keep the local file
        return its absolute filesystem path
    """

    if not local_path.exists():
        raise FileNotFoundError(
            f"Evidence file not found: "
            f"{local_path}"
        )

    if not using_supabase_storage():
        return str(
            local_path.resolve()
        )

    client = (
        get_supabase_client()
    )

    object_path = (
        get_storage_object_path(
            case_id=case_id,
            stored_filename=(
                stored_filename
            ),
        )
    )

    mime_type = (
        content_type
        or "application/octet-stream"
    )

    with local_path.open(
        "rb"
    ) as input_file:

        client.storage.from_(
            SUPABASE_BUCKET
        ).upload(
            path=object_path,
            file=input_file,
            file_options={
                "content-type":
                    mime_type,
                "cache-control":
                    "0",
                "upsert":
                    "false",
            },
        )

    return (
        make_supabase_reference(
            object_path
        )
    )


# =========================================================
# MATERIALIZE FOR FORENSIC ANALYSIS
# =========================================================

def materialize_evidence_file(
    *,
    stored_path: str,
    case_id: int,
    stored_filename: str,
    force_refresh: bool = False,
) -> Path:
    """
    Return a real local Path for the evidence.

    Local Evidence.stored_path:
        simply validates and returns that Path.

    Supabase Evidence.stored_path:
        downloads the private object into the local cache and
        returns the cached Path.

    Existing forensic code can then safely hash/read/analyze the
    returned Path without knowing where the durable object lives.
    """

    if not is_supabase_reference(
        stored_path
    ):

        local_path = Path(
            stored_path
        )

        if not local_path.exists():
            raise FileNotFoundError(
                "Stored evidence file "
                "does not exist."
            )

        return local_path

    bucket, object_path = (
        parse_supabase_reference(
            stored_path
        )
    )

    safe_filename = (
        Path(stored_filename)
        .name
    )

    if not safe_filename:
        safe_filename = (
            Path(object_path)
            .name
        )

    cache_directory = (
        get_case_cache_directory(
            case_id
        )
    )

    cached_path = (
        cache_directory
        / safe_filename
    )

    if (
        cached_path.exists()
        and not force_refresh
    ):
        return cached_path

    client = (
        get_supabase_client()
    )

    file_bytes = (
        client.storage
        .from_(bucket)
        .download(
            object_path
        )
    )

    if not isinstance(
        file_bytes,
        (
            bytes,
            bytearray,
        ),
    ):
        raise RuntimeError(
            "Supabase Storage returned "
            "an unexpected download response."
        )

    temporary_path = (
        cached_path
        .with_suffix(
            cached_path.suffix
            + ".part"
        )
    )

    temporary_path.write_bytes(
        bytes(file_bytes)
    )

    temporary_path.replace(
        cached_path
    )

    return cached_path


# =========================================================
# OPTIONAL CLEANUP HELPERS
# =========================================================

def remove_cached_evidence_file(
    *,
    case_id: int,
    stored_filename: str,
) -> None:

    safe_filename = (
        Path(stored_filename)
        .name
    )

    if not safe_filename:
        return

    cached_path = (
        get_case_cache_directory(
            case_id
        )
        / safe_filename
    )

    if cached_path.exists():
        cached_path.unlink()


def delete_persisted_evidence_file(
    *,
    stored_path: str,
) -> None:
    """
    Delete a Supabase-backed evidence object if a future delete
    workflow needs it.

    Local files are intentionally not deleted here because existing
    local-development workflows may manage them separately.
    """

    if not is_supabase_reference(
        stored_path
    ):
        return

    bucket, object_path = (
        parse_supabase_reference(
            stored_path
        )
    )

    client = (
        get_supabase_client()
    )

    client.storage.from_(
        bucket
    ).remove(
        [
            object_path
        ]
    )
