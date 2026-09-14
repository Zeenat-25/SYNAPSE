from __future__ import annotations

import json

from collections import defaultdict

from datetime import (
    datetime,
    timezone,
)

from sqlmodel import (
    Session,
    select,
)

from .blind_spot_engine import (
    build_blind_spot_report,
)

from .coverage_engine import (
    build_case_coverage_report,
)

from .graph_engine import (
    build_case_graph,
)

from .models import (
    ArtifactTriage,
    Case,
    Evidence,
    LedgerEntry,
)

from .timeline_engine import (
    build_investigation_timeline,
)


# =========================================================
# HELPERS
# =========================================================


def utc_now() -> datetime:

    return datetime.now(
        timezone.utc
    )


def iso_or_none(
    value,
) -> str | None:

    if value is None:

        return None


    if hasattr(
        value,
        "isoformat",
    ):

        return value.isoformat()


    return str(
        value
    )


def safe_json_list(
    value: str | None,
) -> list:

    if not value:

        return []


    try:

        parsed = json.loads(
            value
        )


        if isinstance(
            parsed,
            list,
        ):

            return parsed


    except (
        json.JSONDecodeError,
        TypeError,
    ):

        pass


    return []


# =========================================================
# LATEST TRIAGE
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
# LEDGER REPORT
# =========================================================


def build_ledger_report(
    session: Session,
    case_id: int,
) -> dict:

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


    entries = list(
        session.exec(
            statement
        ).all()
    )


    event_counts: dict[
        str,
        int
    ] = defaultdict(
        int
    )


    for entry in entries:

        event_counts[
            entry.event_type
        ] += 1


    first_event = (
        entries[0]
        if entries
        else None
    )


    latest_event = (
        entries[-1]
        if entries
        else None
    )


    recent_entries = []


    for entry in entries[
        -20:
    ]:

        recent_entries.append(
            {
                "id":
                    entry.id,

                "event_type":
                    entry.event_type,

                "event_data":
                    entry.event_data,

                "timestamp":
                    iso_or_none(
                        entry.timestamp
                    ),

                "previous_hash":
                    entry.previous_hash,

                "current_hash":
                    entry.current_hash,
            }
        )


    return {

        "total_entries":
            len(
                entries
            ),

        "event_counts":
            dict(
                sorted(
                    event_counts.items()
                )
            ),

        "first_event":
            (
                {
                    "event_type":
                        first_event.event_type,

                    "timestamp":
                        iso_or_none(
                            first_event.timestamp
                        ),
                }

                if first_event

                else None
            ),

        "latest_event":
            (
                {
                    "event_type":
                        latest_event.event_type,

                    "timestamp":
                        iso_or_none(
                            latest_event.timestamp
                        ),

                    "current_hash":
                        latest_event.current_hash,
                }

                if latest_event

                else None
            ),

        "recent_entries":
            recent_entries,

        "note":
            (
                "The report includes the recorded "
                "tamper-evident chain-of-custody entries. "
                "This section does not independently "
                "recalculate the ledger hash chain."
            ),
    }


# =========================================================
# GRAPH RELATION MAP
# =========================================================


def build_evidence_relationship_map(
    graph: dict,
) -> dict[int, list[dict]]:

    nodes_by_id = {

        node[
            "id"
        ]:
            node

        for node
        in graph.get(
            "nodes",
            []
        )
    }


    relationship_map: dict[
        int,
        list[dict]
    ] = defaultdict(
        list
    )


    for edge in graph.get(
        "edges",
        [],
    ):

        if (
            edge.get(
                "type"
            )
            == "CONTAINS"
        ):

            continue


        source_node = (
            nodes_by_id.get(
                edge.get(
                    "source"
                )
            )
        )


        target_node = (
            nodes_by_id.get(
                edge.get(
                    "target"
                )
            )
        )


        if (
            not source_node
            or
            not target_node
        ):

            continue


        source_evidence_id = (
            source_node.get(
                "evidence_id"
            )
        )


        target_evidence_id = (
            target_node.get(
                "evidence_id"
            )
        )


        if (
            not source_evidence_id
            or
            not target_evidence_id
        ):

            continue


        source_record = {

            "related_evidence_id":
                target_evidence_id,

            "related_evidence_code":
                target_node.get(
                    "subtitle"
                ),

            "related_filename":
                target_node.get(
                    "label"
                ),

            "relation_type":
                edge.get(
                    "type"
                ),

            "strength":
                edge.get(
                    "strength"
                ),

            "level":
                edge.get(
                    "level"
                ),

            "indicator_type":
                edge.get(
                    "indicator_type"
                ),

            "indicator_value":
                edge.get(
                    "indicator_value"
                ),

            "reason":
                edge.get(
                    "reason"
                ),
        }


        target_record = {

            "related_evidence_id":
                source_evidence_id,

            "related_evidence_code":
                source_node.get(
                    "subtitle"
                ),

            "related_filename":
                source_node.get(
                    "label"
                ),

            "relation_type":
                edge.get(
                    "type"
                ),

            "strength":
                edge.get(
                    "strength"
                ),

            "level":
                edge.get(
                    "level"
                ),

            "indicator_type":
                edge.get(
                    "indicator_type"
                ),

            "indicator_value":
                edge.get(
                    "indicator_value"
                ),

            "reason":
                edge.get(
                    "reason"
                ),
        }


        relationship_map[
            source_evidence_id
        ].append(
            source_record
        )


        relationship_map[
            target_evidence_id
        ].append(
            target_record
        )


    for evidence_id in (
        relationship_map
    ):

        relationship_map[
            evidence_id
        ].sort(
            key=lambda item:
                float(
                    item.get(
                        "strength"
                    )
                    or 0
                ),
            reverse=True,
        )


    return dict(
        relationship_map
    )


# =========================================================
# EVIDENCE REPORT
# =========================================================


def build_evidence_report(
    session: Session,
    case_id: int,
    coverage_report: dict,
    blind_spot_report: dict,
    graph: dict,
) -> list[dict]:

    statement = (
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
            statement
        ).all()
    )


    triage_map = (
        get_latest_triage_map(
            session=session,
            case_id=case_id,
        )
    )


    coverage_map = {

        item[
            "evidence_id"
        ]:
            item

        for item
        in coverage_report.get(
            "evidence_coverage",
            [],
        )
    }


    blind_spot_map = {

        item[
            "evidence_id"
        ]:
            item

        for item
        in blind_spot_report.get(
            "blind_spots",
            [],
        )
    }


    relationship_map = (
        build_evidence_relationship_map(
            graph
        )
    )


    output = []


    for evidence in evidence_items:

        triage = (
            triage_map.get(
                evidence.id
            )
        )


        coverage = (
            coverage_map.get(
                evidence.id
            )
        )


        blind_spot = (
            blind_spot_map.get(
                evidence.id
            )
        )


        findings = (
            safe_json_list(
                triage.findings_json
            )

            if triage

            else []
        )


        indicators = (
            safe_json_list(
                triage.indicators_json
            )

            if triage

            else []
        )


        output.append(
            {

                "evidence_id":
                    evidence.id,

                "evidence_code":
                    evidence.evidence_code,

                "filename":
                    evidence.original_filename,

                "file_extension":
                    evidence.file_extension,

                "mime_type":
                    evidence.mime_type,

                "file_size":
                    evidence.file_size,

                "entropy":
                    evidence.entropy,

                "status":
                    evidence.status,

                "uploaded_at":
                    iso_or_none(
                        evidence.uploaded_at
                    ),

                "integrity":
                    {
                        "status":
                            evidence.integrity_status,

                        "verified_at":
                            iso_or_none(
                                evidence.verified_at
                            ),

                        "sha256":
                            evidence.sha256,

                        "sha1":
                            evidence.sha1,

                        "md5":
                            evidence.md5,
                    },

                "triage":
                    (

                        {
                            "analyzer":
                                triage.analyzer,

                            "analysis_method":
                                triage.analysis_method,

                            "risk_score":
                                triage.risk_score,

                            "risk_level":
                                triage.risk_level,

                            "predicted_class":
                                triage.predicted_class,

                            "model_name":
                                triage.model_name,

                            "benign_probability":
                                triage.benign_probability,

                            "malicious_probability":
                                triage.malicious_probability,

                            "findings":
                                findings,

                            "indicators":
                                indicators,

                            "limitations":
                                triage.limitations,

                            "created_at":
                                iso_or_none(
                                    triage.created_at
                                ),
                        }

                        if triage

                        else None
                    ),

                "coverage":
                    (
                        {
                            "coverage_score":
                                coverage.get(
                                    "coverage_score"
                                ),

                            "coverage_level":
                                coverage.get(
                                    "coverage_level"
                                ),

                            "components":
                                coverage.get(
                                    "components"
                                ),

                            "actions":
                                coverage.get(
                                    "actions"
                                ),

                            "attention":
                                coverage.get(
                                    "attention"
                                ),
                        }

                        if coverage

                        else None
                    ),

                "blind_spot":
                    (
                        {
                            "blind_spot_score":
                                blind_spot.get(
                                    "blind_spot_score"
                                ),

                            "severity":
                                blind_spot.get(
                                    "severity"
                                ),

                            "reasons":
                                blind_spot.get(
                                    "reasons",
                                    [],
                                ),
                        }

                        if blind_spot

                        else None
                    ),

                "relationships":
                    relationship_map.get(
                        evidence.id,
                        [],
                    ),
            }
        )


    return output


# =========================================================
# EXECUTIVE SUMMARY
# =========================================================


def build_executive_summary(
    evidence_report: list[dict],
    coverage_report: dict,
    blind_spot_report: dict,
    graph: dict,
    timeline: dict,
    ledger_report: dict,
) -> dict:

    analyzed = [
        item

        for item
        in evidence_report

        if item[
            "triage"
        ]
        is not None
    ]


    untriaged = [
        item

        for item
        in evidence_report

        if item[
            "triage"
        ]
        is None
    ]


    high_risk = [
        item

        for item
        in analyzed

        if item[
            "triage"
        ][
            "risk_level"
        ]
        == "HIGH RISK"
    ]


    suspicious = [
        item

        for item
        in analyzed

        if item[
            "triage"
        ][
            "risk_level"
        ]
        == "SUSPICIOUS"
    ]


    low_risk = [
        item

        for item
        in analyzed

        if item[
            "triage"
        ][
            "risk_level"
        ]
        == "LOW RISK"
    ]


    integrity_failures = [
        item

        for item
        in evidence_report

        if str(
            item[
                "integrity"
            ][
                "status"
            ]
        ).upper()
        in {
            "FAILED",
            "FAILURE",
            "INTEGRITY_FAILURE",
        }
    ]


    top_risk = sorted(
        analyzed,
        key=lambda item:
            float(
                item[
                    "triage"
                ][
                    "risk_score"
                ]
                or 0
            ),
        reverse=True,
    )[:5]


    top_blind_spots = sorted(
        blind_spot_report.get(
            "blind_spots",
            [],
        ),
        key=lambda item:
            float(
                item.get(
                    "blind_spot_score"
                )
                or 0
            ),
        reverse=True,
    )[:5]


    return {

        "total_evidence":
            len(
                evidence_report
            ),

        "analyzed_evidence":
            len(
                analyzed
            ),

        "untriaged_evidence":
            len(
                untriaged
            ),

        "high_risk_evidence":
            len(
                high_risk
            ),

        "suspicious_evidence":
            len(
                suspicious
            ),

        "low_risk_evidence":
            len(
                low_risk
            ),

        "integrity_failures":
            len(
                integrity_failures
            ),

        "average_coverage":
            coverage_report.get(
                "summary",
                {},
            ).get(
                "average_coverage",
                0,
            ),

        "high_blind_spots":
            blind_spot_report.get(
                "summary",
                {},
            ).get(
                "high_blind_spots",
                0,
            ),

        "medium_blind_spots":
            blind_spot_report.get(
                "summary",
                {},
            ).get(
                "medium_blind_spots",
                0,
            ),

        "correlation_relationships":
            graph.get(
                "summary",
                {},
            ).get(
                "correlation_links",
                0,
            ),

        "strong_correlations":
            graph.get(
                "summary",
                {},
            ).get(
                "strong_correlations",
                0,
            ),

        "correlation_clusters":
            graph.get(
                "summary",
                {},
            ).get(
                "clusters",
                0,
            ),

        "timeline_events":
            timeline.get(
                "summary",
                {},
            ).get(
                "total_events",
                0,
            ),

        "chain_of_custody_entries":
            ledger_report.get(
                "total_entries",
                0,
            ),

        "top_risk_evidence":
            [
                {
                    "evidence_id":
                        item[
                            "evidence_id"
                        ],

                    "evidence_code":
                        item[
                            "evidence_code"
                        ],

                    "filename":
                        item[
                            "filename"
                        ],

                    "risk_score":
                        item[
                            "triage"
                        ][
                            "risk_score"
                        ],

                    "risk_level":
                        item[
                            "triage"
                        ][
                            "risk_level"
                        ],
                }

                for item
                in top_risk
            ],

        "top_blind_spots":
            [
                {
                    "evidence_id":
                        item.get(
                            "evidence_id"
                        ),

                    "evidence_code":
                        item.get(
                            "evidence_code"
                        ),

                    "filename":
                        item.get(
                            "filename"
                        ),

                    "forensic_risk":
                        item.get(
                            "forensic_risk"
                        ),

                    "coverage_score":
                        item.get(
                            "coverage_score"
                        ),

                    "blind_spot_score":
                        item.get(
                            "blind_spot_score"
                        ),

                    "severity":
                        item.get(
                            "severity"
                        ),
                }

                for item
                in top_blind_spots
            ],
    }


# =========================================================
# CORRELATION REPORT SECTION
# =========================================================


def build_correlation_section(
    graph: dict,
) -> dict:

    relationships = []


    nodes_by_id = {

        node[
            "id"
        ]:
            node

        for node
        in graph.get(
            "nodes",
            [],
        )
    }


    for edge in graph.get(
        "edges",
        [],
    ):

        if (
            edge.get(
                "type"
            )
            == "CONTAINS"
        ):

            continue


        source = (
            nodes_by_id.get(
                edge.get(
                    "source"
                )
            )
        )


        target = (
            nodes_by_id.get(
                edge.get(
                    "target"
                )
            )
        )


        relationships.append(
            {
                "relation_type":
                    edge.get(
                        "type"
                    ),

                "strength":
                    edge.get(
                        "strength"
                    ),

                "level":
                    edge.get(
                        "level"
                    ),

                "source_evidence_code":
                    (
                        source.get(
                            "subtitle"
                        )
                        if source
                        else None
                    ),

                "source_filename":
                    (
                        source.get(
                            "label"
                        )
                        if source
                        else None
                    ),

                "target_evidence_code":
                    (
                        target.get(
                            "subtitle"
                        )
                        if target
                        else None
                    ),

                "target_filename":
                    (
                        target.get(
                            "label"
                        )
                        if target
                        else None
                    ),

                "indicator_type":
                    edge.get(
                        "indicator_type"
                    ),

                "indicator_value":
                    edge.get(
                        "indicator_value"
                    ),

                "reason":
                    edge.get(
                        "reason"
                    ),
            }
        )


    relationships.sort(
        key=lambda item:
            float(
                item.get(
                    "strength"
                )
                or 0
            ),
        reverse=True,
    )


    return {

        "summary":
            graph.get(
                "summary",
                {},
            ),

        "relationships":
            relationships,

        "clusters":
            graph.get(
                "clusters",
                [],
            ),

        "disclaimer":
            graph.get(
                "disclaimer"
            ),
    }


# =========================================================
# TIMELINE REPORT SECTION
# =========================================================


def build_timeline_section(
    timeline: dict,
) -> dict:

    events = (
        timeline.get(
            "events",
            []
        )
    )


    recent_events = []


    for event in events[
        -30:
    ]:

        recent_events.append(
            {
                "timeline_id":
                    event.get(
                        "timeline_id"
                    ),

                "event_type":
                    event.get(
                        "event_type"
                    ),

                "category":
                    event.get(
                        "category"
                    ),

                "title":
                    event.get(
                        "title"
                    ),

                "description":
                    event.get(
                        "description"
                    ),

                "timestamp":
                    iso_or_none(
                        event.get(
                            "timestamp"
                        )
                    ),

                "severity":
                    event.get(
                        "severity"
                    ),

                "related_evidence":
                    event.get(
                        "related_evidence",
                        [],
                    ),
            }
        )


    return {

        "summary":
            timeline.get(
                "summary",
                {},
            ),

        "recent_events":
            recent_events,

        "methodology":
            timeline.get(
                "methodology",
                [],
            ),

        "disclaimer":
            timeline.get(
                "disclaimer"
            ),
    }


# =========================================================
# COMPLETE FORENSIC REPORT
# =========================================================


def build_forensic_report(
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


    coverage_report = (
        build_case_coverage_report(
            session=session,
            case_id=case_id,
        )
    )


    blind_spot_report = (
        build_blind_spot_report(
            session=session,
            case_id=case_id,
        )
    )


    graph = (
        build_case_graph(
            session=session,
            case_id=case_id,
        )
    )


    timeline = (
        build_investigation_timeline(
            session=session,
            case_id=case_id,
        )
    )


    ledger_report = (
        build_ledger_report(
            session=session,
            case_id=case_id,
        )
    )


    evidence_report = (
        build_evidence_report(
            session=session,
            case_id=case_id,
            coverage_report=(
                coverage_report
            ),
            blind_spot_report=(
                blind_spot_report
            ),
            graph=graph,
        )
    )


    executive_summary = (
        build_executive_summary(
            evidence_report=(
                evidence_report
            ),
            coverage_report=(
                coverage_report
            ),
            blind_spot_report=(
                blind_spot_report
            ),
            graph=graph,
            timeline=timeline,
            ledger_report=(
                ledger_report
            ),
        )
    )


    correlation_section = (
        build_correlation_section(
            graph
        )
    )


    timeline_section = (
        build_timeline_section(
            timeline
        )
    )


    generated_at = (
        utc_now()
    )


    return {

        "report_version":
            "1.0",

        "report_type":
            (
                "SYNAPSE Digital Forensic "
                "Investigation Report"
            ),

        "generated_at":
            generated_at.isoformat(),

        "case":
            {
                "id":
                    forensic_case.id,

                "case_code":
                    forensic_case.case_code,

                "name":
                    forensic_case.name,

                "case_type":
                    forensic_case.case_type,

                "description":
                    forensic_case.description,

                "investigator":
                    forensic_case.investigator,

                "status":
                    forensic_case.status,

                "created_at":
                    iso_or_none(
                        forensic_case.created_at
                    ),

                "updated_at":
                    iso_or_none(
                        forensic_case.updated_at
                    ),
            },

        "executive_summary":
            executive_summary,

        "evidence":
            evidence_report,

        "coverage":
            {
                "formula":
                    coverage_report.get(
                        "formula"
                    ),

                "summary":
                    coverage_report.get(
                        "summary",
                        {},
                    ),

                "evidence_coverage":
                    coverage_report.get(
                        "evidence_coverage",
                        [],
                    ),

                "disclaimer":
                    coverage_report.get(
                        "disclaimer"
                    ),
            },

        "blind_spots":
            {
                "formula":
                    blind_spot_report.get(
                        "formula"
                    ),

                "coverage_formula":
                    blind_spot_report.get(
                        "coverage_formula"
                    ),

                "summary":
                    blind_spot_report.get(
                        "summary",
                        {},
                    ),

                "items":
                    blind_spot_report.get(
                        "blind_spots",
                        [],
                    ),

                "disclaimer":
                    blind_spot_report.get(
                        "disclaimer"
                    ),
            },

        "correlations":
            correlation_section,

        "timeline":
            timeline_section,

        "chain_of_custody":
            ledger_report,

        "methodology":
            [
                (
                    "Evidence integrity is represented "
                    "using cryptographic hashes recorded "
                    "by SYNAPSE."
                ),

                (
                    "PE executable risk may originate "
                    "from the trained SYNAPSE PE machine-"
                    "learning model."
                ),

                (
                    "Non-PE artifact risk may originate "
                    "from deterministic static forensic "
                    "heuristics rather than machine learning."
                ),

                (
                    "Evidence correlations are created "
                    "deterministically from observable "
                    "properties and extracted indicators."
                ),

                (
                    "Coverage represents observable "
                    "investigator interaction inside "
                    "SYNAPSE."
                ),

                (
                    "Blind Spot scoring combines forensic "
                    "risk with investigation coverage for "
                    "review prioritization."
                ),

                (
                    "Timeline information reconstructs "
                    "observable SYNAPSE events and review "
                    "telemetry."
                ),
            ],

        "limitations":
            [
                (
                    "Forensic risk scores from different "
                    "analyzers are prioritization signals "
                    "and are not uniformly calibrated "
                    "probabilities."
                ),

                (
                    "Static findings do not by themselves "
                    "prove maliciousness."
                ),

                (
                    "High entropy alone does not prove "
                    "packing, encryption, steganography "
                    "or malicious intent."
                ),

                (
                    "Shared indicators and evidence "
                    "correlations do not prove common "
                    "origin, ownership, coordination "
                    "or causation."
                ),

                (
                    "Investigation coverage records "
                    "observable platform activity and "
                    "does not prove investigator "
                    "comprehension."
                ),

                (
                    "The investigation timeline cannot "
                    "reconstruct actions performed "
                    "outside SYNAPSE."
                ),

                (
                    "The report supports investigator "
                    "decision-making and does not replace "
                    "qualified forensic judgment."
                ),
            ],

        "export":
            {
                "json_ready":
                    True,

                "pdf_ready":
                    False,

                "pdf_phase":
                    "15B",
            },
    }