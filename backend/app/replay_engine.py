from __future__ import annotations

import re

from copy import deepcopy

from typing import Any

from sqlmodel import Session

from .timeline_engine import (
    build_investigation_timeline,
)


# =========================================================
# EVENT GROUPS
# =========================================================


TRIAGE_EVENTS = {
    "MULTI_ARTIFACT_TRIAGE_COMPLETED",
    "ML_TRIAGE_COMPLETED",
}


INTEGRITY_SUCCESS_EVENTS = {
    "INTEGRITY_VERIFIED",
}


INTEGRITY_FAILURE_EVENTS = {
    "INTEGRITY_FAILURE",
}


CORRELATION_EVENTS = {
    "EVIDENCE_CORRELATION_COMPLETED",
}


AI_EVENTS = {
    "AI_ANALYST_QUERY",
}


# =========================================================
# EVIDENCE IDS FROM TIMELINE EVENT
# =========================================================


def related_evidence_ids(
    event: dict,
) -> list[int]:

    output: list[int] = []


    for item in event.get(
        "related_evidence",
        [],
    ):

        evidence_id = (
            item.get(
                "evidence_id"
            )
        )


        if (
            isinstance(
                evidence_id,
                int,
            )
            and
            evidence_id not in output
        ):

            output.append(
                evidence_id
            )


    return output


# =========================================================
# EVENT DATA METRICS
# =========================================================
#
# Phase 13 correlation logging writes data such as:
#
# Relationships=3 | Strong=1 | Medium=2 | Clusters=1
#
# These values are deterministic engine outputs, so Replay
# can restore the most recently known correlation state.
# =========================================================


def extract_numeric_metric(
    text: str | None,
    metric_name: str,
) -> int | None:

    if not text:

        return None


    pattern = (
        rf"\b"
        rf"{re.escape(metric_name)}"
        rf"\s*=\s*(\d+)"
        rf"\b"
    )


    match = re.search(
        pattern,
        text,
        flags=re.IGNORECASE,
    )


    if match is None:

        return None


    try:

        return int(
            match.group(
                1
            )
        )


    except (
        TypeError,
        ValueError,
    ):

        return None


# =========================================================
# REPLAY STAGE
# =========================================================
#
# This is only a deterministic UI-oriented stage label.
# It is NOT a forensic conclusion about the case.
# =========================================================


def determine_replay_stage(
    state: dict,
) -> str:

    if (
        state[
            "registered_evidence"
        ]
        == 0
    ):

        return "EMPTY"


    if (
        state[
            "analysis_runs"
        ]
        == 0
    ):

        return "INGESTION"


    if (
        state[
            "reviewed_evidence"
        ]
        == 0
    ):

        return "TRIAGE"


    if (
        state[
            "correlation_runs"
        ]
        == 0
    ):

        return "INVESTIGATION"


    if (
        state[
            "ai_queries"
        ]
        == 0
    ):

        return "CORRELATION"


    return "AI_ASSISTED"


# =========================================================
# EMPTY INTERNAL STATE
# =========================================================


def create_initial_state() -> dict:

    return {

        "_registered_ids":
            set(),

        "_analyzed_ids":
            set(),

        "_reviewed_ids":
            set(),

        "_verified_ids":
            set(),

        "_active_integrity_failure_ids":
            set(),

        "analysis_runs":
            0,

        "integrity_checks":
            0,

        "integrity_failures_total":
            0,

        "correlation_runs":
            0,

        "correlation_relationships":
            0,

        "strong_correlations":
            0,

        "medium_correlations":
            0,

        "correlation_clusters":
            0,

        "coverage_events":
            0,

        "blind_spot_runs":
            0,

        "ai_queries":
            0,

        "audit_events":
            0,
    }


# =========================================================
# PUBLIC STATE
# =========================================================


def serialize_state(
    state: dict,
) -> dict:

    public_state = {

        "registered_evidence":
            len(
                state[
                    "_registered_ids"
                ]
            ),

        "analyzed_evidence":
            len(
                state[
                    "_analyzed_ids"
                ]
            ),

        "reviewed_evidence":
            len(
                state[
                    "_reviewed_ids"
                ]
            ),

        "integrity_verified":
            len(
                state[
                    "_verified_ids"
                ]
            ),

        "active_integrity_failures":
            len(
                state[
                    "_active_integrity_failure_ids"
                ]
            ),

        "analysis_runs":
            state[
                "analysis_runs"
            ],

        "integrity_checks":
            state[
                "integrity_checks"
            ],

        "integrity_failures_total":
            state[
                "integrity_failures_total"
            ],

        "correlation_runs":
            state[
                "correlation_runs"
            ],

        "correlation_relationships":
            state[
                "correlation_relationships"
            ],

        "strong_correlations":
            state[
                "strong_correlations"
            ],

        "medium_correlations":
            state[
                "medium_correlations"
            ],

        "correlation_clusters":
            state[
                "correlation_clusters"
            ],

        "coverage_events":
            state[
                "coverage_events"
            ],

        "blind_spot_runs":
            state[
                "blind_spot_runs"
            ],

        "ai_queries":
            state[
                "ai_queries"
            ],

        "audit_events":
            state[
                "audit_events"
            ],
    }


    public_state[
        "replay_stage"
    ] = (
        determine_replay_stage(
            public_state
        )
    )


    return public_state


# =========================================================
# DELTA
# =========================================================


def empty_delta() -> dict:

    return {

        "registered":
            [],

        "analyzed":
            [],

        "reviewed":
            [],

        "integrity_verified":
            [],

        "integrity_failed":
            [],

        "correlation_updated":
            False,

        "coverage_updated":
            False,

        "ai_used":
            False,
    }


# =========================================================
# ADD SET ITEM
# =========================================================


def add_new_ids(
    target_set: set[int],
    evidence_ids: list[int],
) -> list[int]:

    added = []


    for evidence_id in evidence_ids:

        if evidence_id in target_set:

            continue


        target_set.add(
            evidence_id
        )


        added.append(
            evidence_id
        )


    return added


# =========================================================
# APPLY EVENT
# =========================================================


def apply_event_to_state(
    state: dict,
    event: dict,
) -> dict:

    delta = (
        empty_delta()
    )


    event_type = str(
        event.get(
            "event_type",
            "",
        )
    ).upper()


    category = str(
        event.get(
            "category",
            "AUDIT",
        )
    ).upper()


    description = str(
        event.get(
            "description",
            "",
        )
        or ""
    )


    evidence_ids = (
        related_evidence_ids(
            event
        )
    )


    # =====================================================
    # EVIDENCE REGISTRATION
    # =====================================================

    if (
        event_type
        == "EVIDENCE_REGISTERED"
    ):

        delta[
            "registered"
        ] = (
            add_new_ids(
                state[
                    "_registered_ids"
                ],
                evidence_ids,
            )
        )


    # =====================================================
    # ANALYSIS
    # =====================================================

    if event_type in TRIAGE_EVENTS:

        state[
            "analysis_runs"
        ] += 1


        delta[
            "analyzed"
        ] = (
            add_new_ids(
                state[
                    "_analyzed_ids"
                ],
                evidence_ids,
            )
        )


    # =====================================================
    # REVIEW
    # =====================================================

    if category == "REVIEW":

        delta[
            "reviewed"
        ] = (
            add_new_ids(
                state[
                    "_reviewed_ids"
                ],
                evidence_ids,
            )
        )


    # =====================================================
    # INTEGRITY VERIFIED
    # =====================================================

    if (
        event_type
        in INTEGRITY_SUCCESS_EVENTS
    ):

        state[
            "integrity_checks"
        ] += 1


        delta[
            "integrity_verified"
        ] = (
            add_new_ids(
                state[
                    "_verified_ids"
                ],
                evidence_ids,
            )
        )


        for evidence_id in evidence_ids:

            state[
                "_active_integrity_failure_ids"
            ].discard(
                evidence_id
            )


    # =====================================================
    # INTEGRITY FAILURE
    # =====================================================

    if (
        event_type
        in INTEGRITY_FAILURE_EVENTS
        or
        "INTEGRITY_FAILURE"
        in event_type
    ):

        state[
            "integrity_checks"
        ] += 1


        state[
            "integrity_failures_total"
        ] += 1


        delta[
            "integrity_failed"
        ] = (
            add_new_ids(
                state[
                    "_active_integrity_failure_ids"
                ],
                evidence_ids,
            )
        )


        for evidence_id in evidence_ids:

            state[
                "_verified_ids"
            ].discard(
                evidence_id
            )


    # =====================================================
    # CORRELATION
    # =====================================================

    if event_type in CORRELATION_EVENTS:

        state[
            "correlation_runs"
        ] += 1


        delta[
            "correlation_updated"
        ] = True


        relationships = (
            extract_numeric_metric(
                description,
                "Relationships",
            )
        )


        strong = (
            extract_numeric_metric(
                description,
                "Strong",
            )
        )


        medium = (
            extract_numeric_metric(
                description,
                "Medium",
            )
        )


        clusters = (
            extract_numeric_metric(
                description,
                "Clusters",
            )
        )


        if relationships is not None:

            state[
                "correlation_relationships"
            ] = relationships


        if strong is not None:

            state[
                "strong_correlations"
            ] = strong


        if medium is not None:

            state[
                "medium_correlations"
            ] = medium


        if clusters is not None:

            state[
                "correlation_clusters"
            ] = clusters


    # =====================================================
    # COVERAGE / BLIND SPOTS
    # =====================================================

    if category == "COVERAGE":

        state[
            "coverage_events"
        ] += 1


        delta[
            "coverage_updated"
        ] = True


        if (
            "BLIND_SPOT"
            in event_type
            or
            "BLINDSPOT"
            in event_type
        ):

            state[
                "blind_spot_runs"
            ] += 1


    # =====================================================
    # AI
    # =====================================================

    if (
        event_type in AI_EVENTS
        or
        category == "AI"
    ):

        state[
            "ai_queries"
        ] += 1


        delta[
            "ai_used"
        ] = True


    # =====================================================
    # AUDIT COUNT
    # =====================================================

    if (
        event.get(
            "source"
        )
        == "CHAIN_OF_CUSTODY"
    ):

        state[
            "audit_events"
        ] += 1


    return delta


# =========================================================
# MILESTONE
# =========================================================


def milestone_for_snapshot(
    snapshot: dict,
) -> str | None:

    event = (
        snapshot[
            "event"
        ]
    )


    state = (
        snapshot[
            "state"
        ]
    )


    event_type = (
        event[
            "event_type"
        ]
    )


    if (
        event_type
        == "EVIDENCE_REGISTERED"
        and
        state[
            "registered_evidence"
        ]
        == 1
    ):

        return (
            "FIRST_EVIDENCE_REGISTERED"
        )


    if (
        event_type in TRIAGE_EVENTS
        and
        state[
            "analysis_runs"
        ]
        == 1
    ):

        return (
            "FIRST_FORENSIC_ANALYSIS"
        )


    if (
        event[
            "category"
        ]
        == "REVIEW"
        and
        state[
            "reviewed_evidence"
        ]
        == 1
    ):

        return (
            "FIRST_INVESTIGATOR_REVIEW"
        )


    if (
        event_type
        in CORRELATION_EVENTS
        and
        state[
            "correlation_runs"
        ]
        == 1
    ):

        return (
            "FIRST_CORRELATION_ANALYSIS"
        )


    if (
        event_type in AI_EVENTS
        and
        state[
            "ai_queries"
        ]
        == 1
    ):

        return (
            "FIRST_AI_ANALYST_QUERY"
        )


    if (
        event[
            "severity"
        ]
        == "HIGH"
    ):

        return (
            "HIGH_SEVERITY_EVENT"
        )


    return None


# =========================================================
# BUILD REPLAY
# =========================================================


def build_investigation_replay(
    session: Session,
    case_id: int,
) -> dict:

    timeline = (
        build_investigation_timeline(
            session=session,
            case_id=case_id,
        )
    )


    events = (
        timeline.get(
            "events",
            [],
        )
    )


    total_steps = len(
        events
    )


    state = (
        create_initial_state()
    )


    snapshots = []

    milestones = []


    for index, event in enumerate(
        events,
        start=1,
    ):

        before = (
            serialize_state(
                state
            )
        )


        delta = (
            apply_event_to_state(
                state=state,
                event=event,
            )
        )


        after = (
            serialize_state(
                state
            )
        )


        progress_percent = (

            round(
                (
                    index
                    /
                    total_steps
                    *
                    100
                ),
                2,
            )

            if total_steps > 0

            else 100.0
        )


        snapshot = {

            "step":
                index,

            "total_steps":
                total_steps,

            "progress_percent":
                progress_percent,

            "timestamp":
                event[
                    "timestamp"
                ],

            "event":
                deepcopy(
                    event
                ),

            "state_before":
                before,

            "state":
                after,

            "delta":
                delta,
        }


        milestone = (
            milestone_for_snapshot(
                snapshot
            )
        )


        snapshot[
            "milestone"
        ] = milestone


        if milestone:

            milestones.append(
                {
                    "step":
                        index,

                    "timestamp":
                        event[
                            "timestamp"
                        ],

                    "milestone":
                        milestone,

                    "title":
                        event[
                            "title"
                        ],

                    "event_type":
                        event[
                            "event_type"
                        ],
                }
            )


        snapshots.append(
            snapshot
        )


    final_state = (
        serialize_state(
            state
        )
    )


    return {

        "case_id":
            timeline[
                "case_id"
            ],

        "case_code":
            timeline[
                "case_code"
            ],

        "case_name":
            timeline[
                "case_name"
            ],

        "total_steps":
            total_steps,

        "initial_state":
            serialize_state(
                create_initial_state()
            ),

        "final_state":
            final_state,

        "milestones":
            milestones,

        "snapshots":
            snapshots,

        "methodology":
            [
                (
                    "Replay state is reconstructed "
                    "chronologically from SYNAPSE "
                    "timeline events."
                ),

                (
                    "Evidence counts use unique evidence "
                    "identifiers, so repeated triage or "
                    "review events do not inflate the "
                    "number of analyzed or reviewed "
                    "artifacts."
                ),

                (
                    "Correlation relationship and cluster "
                    "counts use the latest deterministic "
                    "correlation metrics recorded in the "
                    "timeline."
                ),

                (
                    "Replay stage labels are derived for "
                    "navigation and visualization only; "
                    "they are not forensic conclusions."
                ),
            ],

        "disclaimer":
            (
                "Investigation Replay reconstructs "
                "observable SYNAPSE platform activity. "
                "It cannot reconstruct actions performed "
                "outside SYNAPSE or investigator reasoning "
                "that was not recorded by the system."
            ),
    }


# =========================================================
# SINGLE REPLAY STEP
# =========================================================


def get_replay_step(
    session: Session,
    case_id: int,
    step: int,
) -> dict:

    replay = (
        build_investigation_replay(
            session=session,
            case_id=case_id,
        )
    )


    if step < 1:

        raise ValueError(
            "Replay step must be at least 1."
        )


    if (
        step
        >
        replay[
            "total_steps"
        ]
    ):

        raise ValueError(
            (
                "Replay step exceeds the "
                "available investigation history."
            )
        )


    snapshot = (
        replay[
            "snapshots"
        ][
            step - 1
        ]
    )


    return {

        "case_id":
            replay[
                "case_id"
            ],

        "case_code":
            replay[
                "case_code"
            ],

        "case_name":
            replay[
                "case_name"
            ],

        "step":
            step,

        "total_steps":
            replay[
                "total_steps"
            ],

        "snapshot":
            snapshot,

        "previous_step":
            (
                step - 1
                if step > 1
                else None
            ),

        "next_step":
            (
                step + 1

                if step
                <
                replay[
                    "total_steps"
                ]

                else None
            ),

        "disclaimer":
            replay[
                "disclaimer"
            ],
    }