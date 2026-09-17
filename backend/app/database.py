from __future__ import annotations

import os
from pathlib import Path
from typing import Generator

from sqlalchemy import inspect, text
from sqlmodel import Session, SQLModel, create_engine


# =========================================================
# DATABASE CONFIGURATION
# =========================================================
# Production (Render):
#   DATABASE_URL = Supabase Session Pooler PostgreSQL URL
#
# Local development:
#   If DATABASE_URL is not set, SYNAPSE falls back to:
#   backend/data/synapse.db
#
# This means:
#   - Render -> Supabase PostgreSQL
#   - Local PC -> SQLite
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = BASE_DIR / "data"

DATA_DIR = Path(
    os.getenv(
        "SYNAPSE_DATA_DIR",
        str(DEFAULT_DATA_DIR),
    )
).expanduser()

DATA_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

raw_database_url = os.getenv(
    "DATABASE_URL",
    "",
).strip()


def normalize_database_url(url: str) -> str:
    """
    Make Supabase/standard PostgreSQL URLs use psycopg v3.

    Supabase normally gives:
        postgresql://...

    SQLAlchemy + psycopg v3 uses:
        postgresql+psycopg://...
    """
    if url.startswith(
        "postgres://"
    ):
        return url.replace(
            "postgres://",
            "postgresql+psycopg://",
            1,
        )

    if url.startswith(
        "postgresql://"
    ):
        return url.replace(
            "postgresql://",
            "postgresql+psycopg://",
            1,
        )

    return url


if raw_database_url:
    DATABASE_URL = normalize_database_url(
        raw_database_url
    )
    USING_SQLITE = False
else:
    DATABASE_FILE = (
        DATA_DIR
        / "synapse.db"
    )

    DATABASE_URL = (
        f"sqlite:///"
        f"{DATABASE_FILE.as_posix()}"
    )

    USING_SQLITE = True


if USING_SQLITE:
    engine = create_engine(
        DATABASE_URL,
        echo=False,
        connect_args={
            "check_same_thread": False,
        },
    )
else:
    engine = create_engine(
        DATABASE_URL,
        echo=False,
        pool_pre_ping=True,
    )


# =========================================================
# LIGHTWEIGHT LOCAL SQLITE MIGRATIONS
# =========================================================
# Supabase starts as a fresh PostgreSQL database, so
# SQLModel.metadata.create_all() creates the current schema.
#
# These ALTER TABLE migrations are retained only for older
# local SQLite databases that may already exist.
# =========================================================

def add_missing_columns(
    table_name: str,
    migrations: dict[str, str],
) -> None:

    if not USING_SQLITE:
        return

    inspector = inspect(
        engine
    )

    if (
        table_name
        not in inspector.get_table_names()
    ):
        return

    existing_columns = {
        column["name"]
        for column
        in inspector.get_columns(
            table_name
        )
    }

    with engine.begin() as connection:

        for (
            column_name,
            definition,
        ) in migrations.items():

            if (
                column_name
                in existing_columns
            ):
                continue

            connection.execute(
                text(
                    f"""
                    ALTER TABLE {table_name}
                    ADD COLUMN {column_name}
                    {definition}
                    """
                )
            )


def migrate_database() -> None:

    if not USING_SQLITE:
        return

    add_missing_columns(
        "evidence",
        {
            "file_extension":
                "TEXT NOT NULL DEFAULT 'none'",
            "sha256":
                "TEXT NOT NULL DEFAULT ''",
            "sha1":
                "TEXT NOT NULL DEFAULT ''",
            "md5":
                "TEXT NOT NULL DEFAULT ''",
            "entropy":
                "FLOAT NOT NULL DEFAULT 0.0",
            "integrity_status":
                "TEXT NOT NULL DEFAULT 'UNVERIFIED'",
            "verified_at":
                "DATETIME",
        },
    )

    add_missing_columns(
        "evidencefeature",
        {
            "label":
                "INTEGER",
            "label_name":
                "TEXT",
            "labeled_at":
                "DATETIME",
        },
    )


def create_db_and_tables() -> None:
    SQLModel.metadata.create_all(
        engine
    )
    migrate_database()


def get_session() -> Generator[
    Session,
    None,
    None,
]:
    with Session(
        engine
    ) as session:
        yield session
