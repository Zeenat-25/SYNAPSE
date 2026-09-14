import hashlib
import json
from datetime import datetime, timezone

from sqlmodel import Session, select

from .models import LedgerEntry


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def calculate_ledger_hash(
    case_id: int,
    event_type: str,
    event_data: str,
    timestamp: str,
    previous_hash: str,
) -> str:

    payload = {
        "case_id": case_id,
        "event_type": event_type,
        "event_data": event_data,
        "timestamp": timestamp,
        "previous_hash": previous_hash,
    }

    serialized = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(
        serialized.encode("utf-8")
    ).hexdigest()


def get_last_case_entry(
    session: Session,
    case_id: int,
) -> LedgerEntry | None:

    statement = (
        select(LedgerEntry)
        .where(
            LedgerEntry.case_id == case_id
        )
        .order_by(
            LedgerEntry.id.desc()
        )
    )

    return session.exec(statement).first()


def create_ledger_entry(
    session: Session,
    case_id: int,
    event_type: str,
    event_data: str,
) -> LedgerEntry:

    previous_entry = get_last_case_entry(
        session,
        case_id,
    )

    if previous_entry:
        previous_hash = previous_entry.current_hash
    else:
        previous_hash = "GENESIS"

    timestamp = utc_iso()

    current_hash = calculate_ledger_hash(
        case_id=case_id,
        event_type=event_type,
        event_data=event_data,
        timestamp=timestamp,
        previous_hash=previous_hash,
    )

    ledger_entry = LedgerEntry(
        case_id=case_id,
        event_type=event_type,
        event_data=event_data,
        timestamp=datetime.fromisoformat(timestamp),
        previous_hash=previous_hash,
        current_hash=current_hash,
    )

    session.add(ledger_entry)
    session.commit()
    session.refresh(ledger_entry)

    return ledger_entry