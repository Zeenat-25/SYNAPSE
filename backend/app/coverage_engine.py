from __future__ import annotations

from sqlmodel import (
    Session,
    select,
)

from .attention_models import (
    EvidenceAttention,
)

from .models import (
    ArtifactTriage,
    Evidence,
    LedgerEntry,
)


# =========================================================
# COVERAGE HEURISTIC
# =========================================================
#
# This score is intentionally transparent.
#
# It does NOT claim to measure human understanding.
# It measures observable review coverage inside SYNAPSE.
#
# Components:
#
# 35% focused review duration
# 15% number of views
# 10% revisits
# 10% visible-tab ratio
# 30% investigation actions
#
# Total = 100%
# =========================================================


FULL_FOCUSED_SECONDS = 60.0
FULL_VIEW_COUNT = 3
FULL_REVISIT_COUNT = 2


def clamp(
    value: float,
    minimum: float = 0.0,
    maximum: float = 100.0,
) -> float:

    return max(
        minimum,
        min(
            value,
            maximum,
        ),
    )


# =========================================================
# LATEST TRIAGE PER EVIDENCE
# =========================================================


def get_latest_triage_map(
    session: Session,
    case_id: int,
) -> dict[int, ArtifactTriage]:

    statement = (
        select(ArtifactTriage)
        .where(
            ArtifactTriage.case_id
            == case_id
        )
        .order_by(
            ArtifactTriage.created_at.desc()
        )
    )


    records = list(
        session.exec(
            statement
        ).all()
    )


    latest: dict[
        int,
        ArtifactTriage
    ] = {}


    for record in records:

        if (
            record.evidence_id
            not in latest
        ):

            latest[
                record.evidence_id
            ] = record


    return latest


# =========================================================
# ATTENTION MAP
# =========================================================


def get_attention_map(
    session: Session,
    case_id: int,
) -> dict[int, EvidenceAttention]:

    statement = (
        select(EvidenceAttention)
        .where(
            EvidenceAttention.case_id
            == case_id
        )
    )


    records = list(
        session.exec(
            statement
        ).all()
    )


    return {
        record.evidence_id:
            record

        for record
        in records
    }


# =========================================================
# LEDGER
# =========================================================


def get_case_ledger(
    session: Session,
    case_id: int,
) -> list[LedgerEntry]:

    statement = (
        select(LedgerEntry)
        .where(
            LedgerEntry.case_id
            == case_id
        )
        .order_by(
            LedgerEntry.timestamp.asc()
        )
    )


    return list(
        session.exec(
            statement
        ).all()
    )


def has_integrity_verification(
    evidence: Evidence,
    ledger: list[LedgerEntry],
) -> bool:

    for entry in ledger:

        if (
            entry.event_type
            == "INTEGRITY_VERIFIED"
            and
            evidence.evidence_code
            in entry.event_data
        ):

            return True


    return False


# =========================================================
# COVERAGE LEVEL
# =========================================================


def coverage_level(
    score: float,
) -> str:

    if score <= 0:

        return "UNREVIEWED"


    if score < 25:

        return "MINIMAL"


    if score < 50:

        return "PARTIAL"


    if score < 75:

        return "STRONG"


    return "THOROUGH"


# =========================================================
# COVERAGE REASONS
# =========================================================


def build_coverage_reasons(
    attention: EvidenceAttention | None,
    triage_completed: bool,
    integrity_verified: bool,
    coverage_score: float,
) -> list[str]:

    reasons: list[str] = []


    if attention is None:

        reasons.append(
            "No investigator review session has been recorded."
        )

    else:

        if attention.focused_seconds < 10:

            reasons.append(
                "Focused review time is below 10 seconds."
            )


        if attention.view_count <= 1:

            reasons.append(
                "Evidence has been opened only once."
            )


        if attention.revisit_count == 0:

            reasons.append(
                "No revisit has been recorded."
            )


        if attention.total_view_seconds > 0:

            ratio = (
                attention.focused_seconds
                /
                attention.total_view_seconds
            )


            if ratio < 0.5:

                reasons.append(
                    "Less than half of dwell time occurred "
                    "while the SYNAPSE tab was visible."
                )


    if not triage_completed:

        reasons.append(
            "Forensic triage has not been completed."
        )


    if not integrity_verified:

        reasons.append(
            "No investigator-triggered integrity "
            "verification is recorded."
        )


    if coverage_score >= 75:

        reasons.append(
            "Observable investigation coverage is thorough."
        )

    elif coverage_score >= 50:

        reasons.append(
            "Observable investigation coverage is strong."
        )


    return reasons


# =========================================================
# ONE EVIDENCE COVERAGE
# =========================================================


def calculate_evidence_coverage(
    evidence: Evidence,
    attention: EvidenceAttention | None,
    triage: ArtifactTriage | None,
    ledger: list[LedgerEntry],
) -> dict:

    # -----------------------------------------------------
    # FOCUSED DURATION
    # -----------------------------------------------------

    focused_seconds = (
        max(
            0.0,
            attention.focused_seconds,
        )
        if attention
        else 0.0
    )


    focused_duration_score = (
        min(
            focused_seconds
            /
            FULL_FOCUSED_SECONDS,
            1.0,
        )
        * 100
    )


    # -----------------------------------------------------
    # VIEW COUNT
    # -----------------------------------------------------

    view_count = (
        attention.view_count
        if attention
        else 0
    )


    view_score = (
        min(
            view_count
            /
            FULL_VIEW_COUNT,
            1.0,
        )
        * 100
    )


    # -----------------------------------------------------
    # REVISITS
    # -----------------------------------------------------

    revisit_count = (
        attention.revisit_count
        if attention
        else 0
    )


    revisit_score = (
        min(
            revisit_count
            /
            FULL_REVISIT_COUNT,
            1.0,
        )
        * 100
    )


    # -----------------------------------------------------
    # VISIBLE-TAB RATIO
    # -----------------------------------------------------

    total_view_seconds = (
        attention.total_view_seconds
        if attention
        else 0.0
    )


    if total_view_seconds > 0:

        focus_ratio = clamp(
            (
                focused_seconds
                /
                total_view_seconds
            )
            * 100
        )

    else:

        focus_ratio = 0.0


    # -----------------------------------------------------
    # INVESTIGATION ACTIONS
    #
    # Two transparent actions currently count:
    #
    # 1. Forensic triage completed
    # 2. Investigator manually verified integrity
    # -----------------------------------------------------

    triage_completed = (
        triage is not None
    )


    integrity_verified = (
        has_integrity_verification(
            evidence=evidence,
            ledger=ledger,
        )
    )


    completed_actions = 0


    if triage_completed:

        completed_actions += 1


    if integrity_verified:

        completed_actions += 1


    applicable_actions = 2


    action_score = (
        completed_actions
        /
        applicable_actions
        *
        100
    )


    # -----------------------------------------------------
    # FINAL COVERAGE SCORE
    #
    # Focused duration  35%
    # Views             15%
    # Revisits          10%
    # Visible ratio     10%
    # Actions           30%
    # -----------------------------------------------------

    coverage_score = (

        focused_duration_score
        * 0.35

        +

        view_score
        * 0.15

        +

        revisit_score
        * 0.10

        +

        focus_ratio
        * 0.10

        +

        action_score
        * 0.30
    )


    coverage_score = round(
        clamp(
            coverage_score
        ),
        2,
    )


    reasons = build_coverage_reasons(
        attention=attention,
        triage_completed=(
            triage_completed
        ),
        integrity_verified=(
            integrity_verified
        ),
        coverage_score=(
            coverage_score
        ),
    )


    return {

        "evidence_id":
            evidence.id,

        "evidence_code":
            evidence.evidence_code,

        "filename":
            evidence.original_filename,

        "extension":
            evidence.file_extension,

        "coverage_score":
            coverage_score,

        "coverage_level":
            coverage_level(
                coverage_score
            ),

        "components":
            {

                "focused_duration":
                    round(
                        focused_duration_score,
                        2,
                    ),

                "views":
                    round(
                        view_score,
                        2,
                    ),

                "revisits":
                    round(
                        revisit_score,
                        2,
                    ),

                "visible_tab_ratio":
                    round(
                        focus_ratio,
                        2,
                    ),

                "investigation_actions":
                    round(
                        action_score,
                        2,
                    ),
            },

        "attention":
            {

                "view_count":
                    view_count,

                "revisit_count":
                    revisit_count,

                "total_view_seconds":
                    round(
                        total_view_seconds,
                        2,
                    ),

                "focused_seconds":
                    round(
                        focused_seconds,
                        2,
                    ),
            },

        "actions":
            {

                "triage_completed":
                    triage_completed,

                "integrity_verified":
                    integrity_verified,

                "completed":
                    completed_actions,

                "applicable":
                    applicable_actions,
            },

        "forensic_risk":
            (
                round(
                    triage.risk_score,
                    2,
                )
                if triage
                else None
            ),

        "risk_level":
            (
                triage.risk_level
                if triage
                else None
            ),

        "reasons":
            reasons,
    }


# =========================================================
# CASE COVERAGE REPORT
# =========================================================


def build_case_coverage_report(
    session: Session,
    case_id: int,
) -> dict:

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


    attention_map = (
        get_attention_map(
            session=session,
            case_id=case_id,
        )
    )


    triage_map = (
        get_latest_triage_map(
            session=session,
            case_id=case_id,
        )
    )


    ledger = (
        get_case_ledger(
            session=session,
            case_id=case_id,
        )
    )


    coverage_items = []


    for evidence in evidence_items:

        coverage_items.append(
            calculate_evidence_coverage(

                evidence=evidence,

                attention=(
                    attention_map.get(
                        evidence.id
                    )
                ),

                triage=(
                    triage_map.get(
                        evidence.id
                    )
                ),

                ledger=ledger,
            )
        )


    reviewed = [
        item
        for item
        in coverage_items
        if item[
            "coverage_score"
        ] > 0
    ]


    strong_or_better = [
        item
        for item
        in coverage_items
        if item[
            "coverage_score"
        ] >= 50
    ]


    thorough = [
        item
        for item
        in coverage_items
        if item[
            "coverage_score"
        ] >= 75
    ]


    if coverage_items:

        average_coverage = round(
            sum(
                item[
                    "coverage_score"
                ]
                for item
                in coverage_items
            )
            /
            len(
                coverage_items
            ),
            2,
        )


        lowest_coverage = min(
            item[
                "coverage_score"
            ]
            for item
            in coverage_items
        )


        highest_coverage = max(
            item[
                "coverage_score"
            ]
            for item
            in coverage_items
        )

    else:

        average_coverage = 0.0
        lowest_coverage = 0.0
        highest_coverage = 0.0


    coverage_items.sort(
        key=lambda item:
            item[
                "coverage_score"
            ]
    )


    return {

        "case_id":
            case_id,

        "formula":
            (
                "coverage = "
                "35% focused duration + "
                "15% views + "
                "10% revisits + "
                "10% visible-tab ratio + "
                "30% investigation actions"
            ),

        "thresholds":
            {

                "full_focused_seconds":
                    FULL_FOCUSED_SECONDS,

                "full_view_count":
                    FULL_VIEW_COUNT,

                "full_revisit_count":
                    FULL_REVISIT_COUNT,
            },

        "summary":
            {

                "total_evidence":
                    len(
                        coverage_items
                    ),

                "reviewed_evidence":
                    len(
                        reviewed
                    ),

                "unreviewed_evidence":
                    (
                        len(
                            coverage_items
                        )
                        -
                        len(
                            reviewed
                        )
                    ),

                "strong_or_better":
                    len(
                        strong_or_better
                    ),

                "thoroughly_covered":
                    len(
                        thorough
                    ),

                "average_coverage":
                    average_coverage,

                "lowest_coverage":
                    round(
                        lowest_coverage,
                        2,
                    ),

                "highest_coverage":
                    round(
                        highest_coverage,
                        2,
                    ),
            },

        "evidence_coverage":
            coverage_items,

        "disclaimer":
            (
                "Coverage measures observable investigation "
                "activity inside SYNAPSE. It does not prove "
                "human understanding, comprehension, intent, "
                "or investigative correctness."
            ),
    }