from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from sqlmodel import (
    Session,
    select,
)

from .attention_models import (
    EvidenceAttention,
)

from .models import (
    Case,
    Evidence,
    LedgerEntry,
)


# =========================================================
# CATEGORY ORDER
# =========================================================


CATEGORY_ORDER = {
    "EVIDENCE": 1,
    "INTEGRITY": 2,
    "ANALYSIS": 3,
    "REVIEW": 4,
    "CORRELATION": 5,
    "COVERAGE": 6,
    "AI": 7,
    "AUDIT": 8,
}


# =========================================================
# EVENT CATEGORY
# =========================================================


def classify_event(
    event_type: str,
) -> str:

    value = (
        event_type
        .strip()
        .upper()
    )


    if any(
        keyword in value
        for keyword in [
            "EVIDENCE_REGISTER",
            "EVIDENCE_UPLOAD",
            "EVIDENCE_ADDED",
            "FEATURE",
        ]
    ):

        return "EVIDENCE"


    if any(
        keyword in value
        for keyword in [
            "INTEGRITY",
            "HASH_VERIF",
            "VERIFIED",
        ]
    ):

        return "INTEGRITY"


    if any(
        keyword in value
        for keyword in [
            "TRIAGE",
            "ML_",
            "EXPLANATION",
            "ANALYSIS",
        ]
    ):

        return "ANALYSIS"


    if any(
        keyword in value
        for keyword in [
            "CORRELATION",
            "GRAPH",
            "CLUSTER",
        ]
    ):

        return "CORRELATION"


    if any(
        keyword in value
        for keyword in [
            "BLIND_SPOT",
            "BLINDSPOT",
            "COVERAGE",
            "ATTENTION",
        ]
    ):

        return "COVERAGE"


    if any(
        keyword in value
        for keyword in [
            "AI_ANALYST",
            "ANALYST_QUERY",
            "GEMINI",
        ]
    ):

        return "AI"


    return "AUDIT"


# =========================================================
# EVENT SEVERITY
# =========================================================


def infer_severity(
    event_type: str,
    event_data: str,
) -> str:

    combined = (
        f"{event_type} {event_data}"
        .upper()
    )


    if any(
        keyword in combined
        for keyword in [
            "INTEGRITY_FAILURE",
            "INTEGRITY FAILED",
            "HIGH RISK",
            "HIGH_BLIND",
            "HIGH BLIND",
        ]
    ):

        return "HIGH"


    if any(
        keyword in combined
        for keyword in [
            "SUSPICIOUS",
            "FAILURE",
            "MEDIUM",
            "WARNING",
        ]
    ):

        return "MEDIUM"


    if any(
        keyword in combined
        for keyword in [
            "VERIFIED",
            "COMPLETED",
            "REGISTERED",
            "SUCCESS",
        ]
    ):

        return "INFO"


    return "INFO"


# =========================================================
# HUMAN-READABLE TITLES
# =========================================================


def title_from_event(
    event_type: str,
) -> str:

    titles = {

        "AI_ANALYST_QUERY":
            "AI Analyst Query",

        "EVIDENCE_CORRELATION_COMPLETED":
            "Evidence Correlation Completed",

        "MULTI_ARTIFACT_TRIAGE_COMPLETED":
            "Forensic Triage Completed",

        "ML_TRIAGE_COMPLETED":
            "PE Machine-Learning Triage Completed",

        "ML_EXPLANATION_GENERATED":
            "ML Explanation Generated",

        "INTEGRITY_VERIFIED":
            "Evidence Integrity Verified",

        "INTEGRITY_FAILURE":
            "Evidence Integrity Failure",

        "EVIDENCE_REGISTERED":
            "Evidence Registered",

        "EVIDENCE_FEATURES_EXTRACTED":
            "Forensic Features Extracted",

        "EVIDENCE_GRAPH_REBUILT":
            "Evidence Graph Rebuilt",

        "BLIND_SPOT_RECALCULATED":
            "Blind Spot Analysis Recalculated",
    }


    if event_type in titles:

        return titles[
            event_type
        ]


    return (
        event_type
        .replace(
            "_",
            " ",
        )
        .title()
    )


# =========================================================
# FIND EVIDENCE REFERENCES
# =========================================================


def find_related_evidence(
    event_data: str,
    evidence_items: list[Evidence],
) -> list[dict]:

    related = []


    normalized_data = (
        event_data
        or ""
    ).lower()


    for evidence in evidence_items:

        code = (
            evidence.evidence_code
            or ""
        )


        filename = (
            evidence.original_filename
            or ""
        )


        matched = False


        if (
            code
            and
            code.lower()
            in normalized_data
        ):

            matched = True


        if (
            not matched
            and
            filename
            and
            filename.lower()
            in normalized_data
        ):

            matched = True


        if matched:

            related.append(
                {
                    "evidence_id":
                        evidence.id,

                    "evidence_code":
                        evidence.evidence_code,

                    "filename":
                        evidence.original_filename,
                }
            )


    return related


# =========================================================
# LEDGER EVENTS
# =========================================================


def build_ledger_events(
    ledger_entries: list[LedgerEntry],
    evidence_items: list[Evidence],
) -> list[dict]:

    output = []


    for entry in ledger_entries:

        category = (
            classify_event(
                entry.event_type
            )
        )


        related_evidence = (
            find_related_evidence(
                event_data=(
                    entry.event_data
                    or ""
                ),
                evidence_items=(
                    evidence_items
                ),
            )
        )


        output.append(
            {
                "timeline_id":
                    f"ledger-{entry.id}",

                "source":
                    "CHAIN_OF_CUSTODY",

                "source_id":
                    entry.id,

                "event_type":
                    entry.event_type,

                "category":
                    category,

                "title":
                    title_from_event(
                        entry.event_type
                    ),

                "description":
                    entry.event_data,

                "timestamp":
                    entry.timestamp,

                "severity":
                    infer_severity(
                        entry.event_type,
                        entry.event_data
                        or "",
                    ),

                "related_evidence":
                    related_evidence,

                "metadata":
                    {
                        "previous_hash":
                            entry.previous_hash,

                        "current_hash":
                            entry.current_hash,
                    },
            }
        )


    return output


# =========================================================
# REVIEW EVENTS
# =========================================================


def build_review_events(
    attention_records:
        list[EvidenceAttention],
    evidence_map:
        dict[int, Evidence],
) -> list[dict]:

    output = []


    for attention in attention_records:

        evidence = (
            evidence_map.get(
                attention.evidence_id
            )
        )


        if evidence is None:

            continue


        if (
            attention.first_viewed_at
            is not None
        ):

            output.append(
                {
                    "timeline_id":
                        (
                            f"review-first-"
                            f"{attention.id}"
                        ),

                    "source":
                        "INVESTIGATOR_ATTENTION",

                    "source_id":
                        attention.id,

                    "event_type":
                        "EVIDENCE_REVIEW_STARTED",

                    "category":
                        "REVIEW",

                    "title":
                        "Evidence Review Started",

                    "description":
                        (
                            f"Investigator opened "
                            f"{evidence.evidence_code} "
                            f"({evidence.original_filename})."
                        ),

                    "timestamp":
                        attention.first_viewed_at,

                    "severity":
                        "INFO",

                    "related_evidence":
                        [
                            {
                                "evidence_id":
                                    evidence.id,

                                "evidence_code":
                                    evidence.evidence_code,

                                "filename":
                                    evidence.original_filename,
                            }
                        ],

                    "metadata":
                        {
                            "view_count":
                                attention.view_count,

                            "revisit_count":
                                attention.revisit_count,

                            "total_view_seconds":
                                round(
                                    float(
                                        attention
                                        .total_view_seconds
                                    ),
                                    2,
                                ),

                            "focused_seconds":
                                round(
                                    float(
                                        attention
                                        .focused_seconds
                                    ),
                                    2,
                                ),

                            "longest_view_seconds":
                                round(
                                    float(
                                        attention
                                        .longest_view_seconds
                                    ),
                                    2,
                                ),
                        },
                }
            )


        if (
            attention.last_viewed_at
            is not None
            and
            attention.first_viewed_at
            is not None
            and
            attention.last_viewed_at
            >
            attention.first_viewed_at
            and
            attention.revisit_count
            > 0
        ):

            output.append(
                {
                    "timeline_id":
                        (
                            f"review-latest-"
                            f"{attention.id}"
                        ),

                    "source":
                        "INVESTIGATOR_ATTENTION",

                    "source_id":
                        attention.id,

                    "event_type":
                        "EVIDENCE_REVIEW_REVISITED",

                    "category":
                        "REVIEW",

                    "title":
                        "Evidence Revisited",

                    "description":
                        (
                            f"Investigator revisited "
                            f"{evidence.evidence_code} "
                            f"({evidence.original_filename})."
                        ),

                    "timestamp":
                        attention.last_viewed_at,

                    "severity":
                        "INFO",

                    "related_evidence":
                        [
                            {
                                "evidence_id":
                                    evidence.id,

                                "evidence_code":
                                    evidence.evidence_code,

                                "filename":
                                    evidence.original_filename,
                            }
                        ],

                    "metadata":
                        {
                            "view_count":
                                attention.view_count,

                            "revisit_count":
                                attention.revisit_count,

                            "focused_seconds":
                                round(
                                    float(
                                        attention
                                        .focused_seconds
                                    ),
                                    2,
                                ),
                        },
                }
            )


    return output


# =========================================================
# FALLBACK EVIDENCE REGISTRATION EVENTS
# =========================================================
#
# Some older evidence may predate ledger event naming.
# We ensure every artifact still appears in the timeline.
# =========================================================


def build_missing_registration_events(
    evidence_items: list[Evidence],
    timeline_events: list[dict],
) -> list[dict]:

    output = []


    registered_ids: set[int] = set()


    for event in timeline_events:

        if (
            event[
                "category"
            ]
            != "EVIDENCE"
        ):

            continue


        for related in event.get(
            "related_evidence",
            [],
        ):

            evidence_id = (
                related.get(
                    "evidence_id"
                )
            )


            if evidence_id:

                registered_ids.add(
                    evidence_id
                )


    for evidence in evidence_items:

        if evidence.id in registered_ids:

            continue


        output.append(
            {
                "timeline_id":
                    (
                        f"evidence-registration-"
                        f"{evidence.id}"
                    ),

                "source":
                    "EVIDENCE_RECORD",

                "source_id":
                    evidence.id,

                "event_type":
                    "EVIDENCE_REGISTERED",

                "category":
                    "EVIDENCE",

                "title":
                    "Evidence Registered",

                "description":
                    (
                        f"{evidence.evidence_code} "
                        f"({evidence.original_filename}) "
                        "was registered in the case."
                    ),

                "timestamp":
                    evidence.uploaded_at,

                "severity":
                    "INFO",

                "related_evidence":
                    [
                        {
                            "evidence_id":
                                evidence.id,

                            "evidence_code":
                                evidence.evidence_code,

                            "filename":
                                evidence.original_filename,
                        }
                    ],

                "metadata":
                    {
                        "file_extension":
                            evidence.file_extension,

                        "file_size":
                            evidence.file_size,

                        "sha256":
                            evidence.sha256,

                        "integrity_status":
                            evidence.integrity_status,
                    },
            }
        )


    return output


# =========================================================
# SUMMARY
# =========================================================


def build_timeline_summary(
    events: list[dict],
) -> dict:

    category_counts: dict[
        str,
        int
    ] = defaultdict(
        int
    )


    severity_counts: dict[
        str,
        int
    ] = defaultdict(
        int
    )


    evidence_ids: set[int] = set()


    for event in events:

        category_counts[
            event[
                "category"
            ]
        ] += 1


        severity_counts[
            event[
                "severity"
            ]
        ] += 1


        for related in event.get(
            "related_evidence",
            [],
        ):

            evidence_id = (
                related.get(
                    "evidence_id"
                )
            )


            if evidence_id:

                evidence_ids.add(
                    evidence_id
                )


    first_timestamp = (
        events[0][
            "timestamp"
        ]
        if events
        else None
    )


    last_timestamp = (
        events[-1][
            "timestamp"
        ]
        if events
        else None
    )


    return {
        "total_events":
            len(
                events
            ),

        "evidence_touched":
            len(
                evidence_ids
            ),

        "category_counts":
            dict(
                category_counts
            ),

        "severity_counts":
            dict(
                severity_counts
            ),

        "first_event_at":
            first_timestamp,

        "latest_event_at":
            last_timestamp,
    }


# =========================================================
# TIMELINE BUILD
# =========================================================


def build_investigation_timeline(
    session: Session,
    case_id: int,
) -> dict:

    forensic_case = session.get(
        Case,
        case_id,
    )


    if forensic_case is None:

        raise ValueError(
            "Forensic case not found."
        )


    evidence_statement = (
        select(Evidence)
        .where(
            Evidence.case_id
            == case_id
        )
        .order_by(
            Evidence.id.asc()
        )
    )


    evidence_items = list(
        session.exec(
            evidence_statement
        ).all()
    )


    evidence_map = {
        item.id:
            item

        for item
        in evidence_items
    }


    ledger_statement = (
        select(LedgerEntry)
        .where(
            LedgerEntry.case_id
            == case_id
        )
        .order_by(
            LedgerEntry.timestamp.asc()
        )
    )


    ledger_entries = list(
        session.exec(
            ledger_statement
        ).all()
    )


    attention_statement = (
        select(EvidenceAttention)
        .where(
            EvidenceAttention.case_id
            == case_id
        )
    )


    attention_records = list(
        session.exec(
            attention_statement
        ).all()
    )


    ledger_events = (
        build_ledger_events(
            ledger_entries=(
                ledger_entries
            ),
            evidence_items=(
                evidence_items
            ),
        )
    )


    review_events = (
        build_review_events(
            attention_records=(
                attention_records
            ),
            evidence_map=(
                evidence_map
            ),
        )
    )


    fallback_events = (
        build_missing_registration_events(
            evidence_items=(
                evidence_items
            ),
            timeline_events=(
                ledger_events
            ),
        )
    )


    events = (
        ledger_events
        +
        review_events
        +
        fallback_events
    )


    events.sort(
        key=lambda item: (
            item[
                "timestamp"
            ],
            CATEGORY_ORDER.get(
                item[
                    "category"
                ],
                99,
            ),
            item[
                "timeline_id"
            ],
        )
    )


    summary = (
        build_timeline_summary(
            events
        )
    )


    return {
        "case_id":
            forensic_case.id,

        "case_code":
            forensic_case.case_code,

        "case_name":
            forensic_case.name,

        "summary":
            summary,

        "events":
            events,

        "categories":
            [
                "EVIDENCE",
                "INTEGRITY",
                "ANALYSIS",
                "REVIEW",
                "CORRELATION",
                "COVERAGE",
                "AI",
                "AUDIT",
            ],

        "methodology":
            [
                (
                    "Chain-of-custody ledger entries "
                    "provide the primary investigation history."
                ),

                (
                    "Investigator review activity is added "
                    "from SYNAPSE attention telemetry."
                ),

                (
                    "Evidence registration records are used "
                    "as a fallback when older evidence does "
                    "not have a matching ledger event."
                ),

                (
                    "Review activity reflects observable "
                    "platform interaction and does not prove "
                    "human comprehension."
                ),
            ],

        "disclaimer":
            (
                "The investigation timeline reconstructs "
                "observable SYNAPSE activity. It should not "
                "be interpreted as a complete reconstruction "
                "of every action performed outside the "
                "platform."
            ),
    }