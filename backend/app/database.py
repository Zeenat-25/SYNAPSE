from pathlib import Path
from typing import Generator

from sqlalchemy import inspect, text

from sqlmodel import (
    Session,
    SQLModel,
    create_engine,
)


BASE_DIR = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)


DATA_DIR = (
    BASE_DIR
    / "data"
)


DATA_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


DATABASE_FILE = (
    DATA_DIR
    / "synapse.db"
)


DATABASE_URL = (
    f"sqlite:///"
    f"{DATABASE_FILE.as_posix()}"
)


engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={
        "check_same_thread": False,
    },
)


def add_missing_columns(
    table_name: str,
    migrations: dict[str, str],
) -> None:

    inspector = inspect(engine)

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
                not in existing_columns
            ):

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

    with Session(engine) as session:
        yield session