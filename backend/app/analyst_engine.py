from __future__ import annotations

import json

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
# SAFE JSON
# =========================================================


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
# LEDGER SUMMARY
# =========================================================


def get_ledger_summary(
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
    ] = {}


    for entry in entries:

        event_counts[
            entry.event_type
        ] = (
            event_counts.get(
                entry.event_type,
                0,
            )
            +
            1
        )


    recent_events = []


    for entry in entries[
        -12:
    ]:

        recent_events.append(
            {
                "event_type":
                    entry.event_type,

                "event_data":
                    entry.event_data,

                "timestamp":
                    entry.timestamp.isoformat(),
            }
        )


    return {
        "total_events":
            len(
                entries
            ),

        "event_counts":
            event_counts,

        "recent_events":
            recent_events,
    }


# =========================================================
# EVIDENCE CONTEXT
# =========================================================


def build_evidence_context(
    session: Session,
    case_id: int,
    coverage_report: dict,
    blind_spot_report: dict,
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
        in coverage_report[
            "evidence_coverage"
        ]
    }


    blind_spot_map = {

        item[
            "evidence_id"
        ]:
            item

        for item
        in blind_spot_report[
            "blind_spots"
        ]
    }


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


        findings = []

        indicators = []


        if triage:

            findings = safe_json_list(
                triage.findings_json
            )


            indicators = safe_json_list(
                triage.indicators_json
            )


        output.append(
            {

                "evidence_id":
                    evidence.id,

                "evidence_code":
                    evidence.evidence_code,

                "filename":
                    evidence.original_filename,

                "extension":
                    evidence.file_extension,

                "mime_type":
                    evidence.mime_type,

                "file_size":
                    evidence.file_size,

                "entropy":
                    evidence.entropy,

                "integrity_status":
                    evidence.integrity_status,

                "sha256":
                    evidence.sha256,

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

                            "findings":
                                findings,

                            "indicators":
                                indicators,

                            "limitations":
                                triage.limitations,
                        }

                        if triage

                        else None
                    ),

                "coverage":
                    (

                        {
                            "coverage_score":
                                coverage[
                                    "coverage_score"
                                ],

                            "coverage_level":
                                coverage[
                                    "coverage_level"
                                ],

                            "components":
                                coverage[
                                    "components"
                                ],

                            "actions":
                                coverage[
                                    "actions"
                                ],

                            "attention":
                                coverage[
                                    "attention"
                                ],
                        }

                        if coverage

                        else None
                    ),

                "blind_spot":
                    (

                        {
                            "blind_spot_score":
                                blind_spot[
                                    "blind_spot_score"
                                ],

                            "severity":
                                blind_spot[
                                    "severity"
                                ],

                            "reasons":
                                blind_spot[
                                    "reasons"
                                ],
                        }

                        if blind_spot

                        else None
                    ),
            }
        )


    return output


# =========================================================
# PRIORITY QUEUE
# =========================================================


def build_priority_queue(
    evidence_context: list[dict],
) -> list[dict]:

    priorities = []


    for item in evidence_context:

        triage = (
            item[
                "triage"
            ]
        )


        coverage = (
            item[
                "coverage"
            ]
        )


        blind_spot = (
            item[
                "blind_spot"
            ]
        )


        if triage is None:

            priority_score = 20.0


            reasons = [
                (
                    "Evidence has not yet "
                    "completed forensic triage."
                )
            ]


        else:

            risk = float(
                triage[
                    "risk_score"
                ]
            )


            coverage_score = (

                float(
                    coverage[
                        "coverage_score"
                    ]
                )

                if coverage

                else 0.0
            )


            blind_score = (

                float(
                    blind_spot[
                        "blind_spot_score"
                    ]
                )

                if blind_spot

                else 0.0
            )


            priority_score = (

                blind_score
                * 0.50

                +

                risk
                * 0.35

                +

                (
                    100.0
                    -
                    coverage_score
                )
                * 0.15
            )


            reasons = []


            if risk >= 70:

                reasons.append(
                    "High forensic risk."
                )

            elif risk >= 35:

                reasons.append(
                    "Suspicious forensic indicators."
                )


            if blind_score >= 50:

                reasons.append(
                    "High Blind Spot score."
                )

            elif blind_score >= 25:

                reasons.append(
                    "Meaningful review gap."
                )


            if coverage_score < 25:

                reasons.append(
                    "Investigation coverage is minimal."
                )


            if not reasons:

                reasons.append(
                    "No major priority condition detected."
                )


        priorities.append(
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

                "priority_score":
                    round(
                        min(
                            max(
                                priority_score,
                                0.0,
                            ),
                            100.0,
                        ),
                        2,
                    ),

                "forensic_risk":
                    (
                        triage[
                            "risk_score"
                        ]

                        if triage

                        else None
                    ),

                "coverage_score":
                    (
                        coverage[
                            "coverage_score"
                        ]

                        if coverage

                        else None
                    ),

                "blind_spot_score":
                    (
                        blind_spot[
                            "blind_spot_score"
                        ]

                        if blind_spot

                        else None
                    ),

                "reasons":
                    reasons,
            }
        )


    priorities.sort(
        key=lambda item:
            item[
                "priority_score"
            ],
        reverse=True,
    )


    return priorities


# =========================================================
# CORRELATION INTELLIGENCE
# =========================================================


def build_correlation_intelligence(
    graph: dict,
) -> dict:

    relationships = [
        edge

        for edge
        in graph.get(
            "edges",
            [],
        )

        if edge.get(
            "type"
        )
        != "CONTAINS"
    ]


    nodes = {
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


    strongest_relationships = sorted(
        relationships,
        key=lambda item:
            item.get(
                "strength",
                0,
            ),
        reverse=True,
    )[:15]


    normalized_relationships = []


    for relation in strongest_relationships:

        source = nodes.get(
            relation.get(
                "source"
            )
        )


        target = nodes.get(
            relation.get(
                "target"
            )
        )


        normalized_relationships.append(
            {

                "relation_type":
                    relation.get(
                        "type"
                    ),

                "strength":
                    relation.get(
                        "strength"
                    ),

                "level":
                    relation.get(
                        "level"
                    ),

                "reason":
                    relation.get(
                        "reason"
                    ),

                "indicator_type":
                    relation.get(
                        "indicator_type"
                    ),

                "indicator_value":
                    relation.get(
                        "indicator_value"
                    ),

                "source":
                    (
                        {
                            "evidence_id":
                                source.get(
                                    "evidence_id"
                                ),

                            "evidence_code":
                                source.get(
                                    "subtitle"
                                ),

                            "filename":
                                source.get(
                                    "label"
                                ),

                            "risk":
                                source.get(
                                    "risk"
                                ),

                            "risk_level":
                                source.get(
                                    "risk_level"
                                ),
                        }

                        if source

                        else None
                    ),

                "target":
                    (
                        {
                            "evidence_id":
                                target.get(
                                    "evidence_id"
                                ),

                            "evidence_code":
                                target.get(
                                    "subtitle"
                                ),

                            "filename":
                                target.get(
                                    "label"
                                ),

                            "risk":
                                target.get(
                                    "risk"
                                ),

                            "risk_level":
                                target.get(
                                    "risk_level"
                                ),
                        }

                        if target

                        else None
                    ),
            }
        )


    cluster_context = []


    for cluster in graph.get(
        "clusters",
        [],
    )[:10]:

        cluster_context.append(
            {

                "cluster_id":
                    cluster.get(
                        "cluster_id"
                    ),

                "member_count":
                    cluster.get(
                        "member_count"
                    ),

                "relationship_count":
                    cluster.get(
                        "relationship_count"
                    ),

                "maximum_strength":
                    cluster.get(
                        "maximum_strength"
                    ),

                "average_strength":
                    cluster.get(
                        "average_strength"
                    ),

                "relation_types":
                    cluster.get(
                        "relation_types",
                        [],
                    ),

                "members":
                    cluster.get(
                        "members",
                        [],
                    ),
            }
        )


    relationship_type_counts = (
        graph.get(
            "summary",
            {},
        )
        .get(
            "relationship_types",
            {},
        )
    )


    infrastructure_relationships = [
        item

        for item
        in normalized_relationships

        if item[
            "relation_type"
        ]
        in {
            "SHARED_IP",
            "SHARED_DOMAIN",
            "SHARED_URL",
        }
    ]


    duplicate_relationships = [
        item

        for item
        in normalized_relationships

        if item[
            "relation_type"
        ]
        in {
            "SAME_SHA256",
            "SHARED_HASH",
        }
    ]


    identity_collision_relationships = [
        item

        for item
        in normalized_relationships

        if item[
            "relation_type"
        ]
        == "SAME_FILENAME_DIFFERENT_HASH"
    ]


    observations = []


    if infrastructure_relationships:

        observations.append(
            (
                f"{len(infrastructure_relationships)} "
                "strongest listed relationship(s) involve "
                "shared network infrastructure such as "
                "IPs, domains, or URLs."
            )
        )


    if duplicate_relationships:

        observations.append(
            (
                f"{len(duplicate_relationships)} "
                "strongest listed relationship(s) involve "
                "identical or shared hash indicators."
            )
        )


    if identity_collision_relationships:

        observations.append(
            (
                f"{len(identity_collision_relationships)} "
                "filename collision relationship(s) were "
                "detected where visible filenames match "
                "but file content differs."
            )
        )


    if cluster_context:

        observations.append(
            (
                f"{len(cluster_context)} correlation "
                "cluster(s) are currently available "
                "for investigator review."
            )
        )


    if not normalized_relationships:

        observations.append(
            (
                "No deterministic cross-evidence "
                "correlations are currently available."
            )
        )


    return {

        "relationship_count":
            len(
                relationships
            ),

        "relationship_type_counts":
            relationship_type_counts,

        "strongest_relationships":
            normalized_relationships,

        "clusters":
            cluster_context,

        "infrastructure_relationships":
            infrastructure_relationships,

        "duplicate_relationships":
            duplicate_relationships,

        "filename_collisions":
            identity_collision_relationships,

        "observations":
            observations,

        "interpretation_rules":
            [
                (
                    "A shared IP, domain, or URL shows "
                    "observable infrastructure overlap. "
                    "It does not prove common ownership "
                    "or malicious coordination."
                ),
                (
                    "SAME_SHA256 means the artifacts "
                    "contain identical file content."
                ),
                (
                    "SAME_FILENAME_DIFFERENT_HASH means "
                    "the visible filenames match while "
                    "the underlying file content differs."
                ),
                (
                    "A correlation cluster is a connected "
                    "group of artifacts linked by one or "
                    "more deterministic relationships."
                ),
                (
                    "Correlation strength is a prioritization "
                    "weight defined by SYNAPSE rules. "
                    "It is not a probability of common origin."
                ),
            ],
    }


# =========================================================
# CASE BRIEF
# =========================================================


def build_case_brief(
    case: Case,
    evidence_context: list[dict],
    coverage_report: dict,
    blind_spot_report: dict,
    priority_queue: list[dict],
    correlation_intelligence: dict,
) -> dict:

    analyzed = [
        item

        for item
        in evidence_context

        if item[
            "triage"
        ]
        is not None
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


    untriaged = [
        item

        for item
        in evidence_context

        if item[
            "triage"
        ]
        is None
    ]


    top_priority = (
        priority_queue[
            :5
        ]
    )


    observations: list[
        str
    ] = []


    if high_risk:

        observations.append(
            (
                f"{len(high_risk)} evidence item(s) "
                "currently have HIGH RISK "
                "forensic triage results."
            )
        )


    if suspicious:

        observations.append(
            (
                f"{len(suspicious)} evidence item(s) "
                "contain suspicious forensic indicators."
            )
        )


    if (
        blind_spot_report[
            "summary"
        ][
            "high_blind_spots"
        ]
        > 0
    ):

        observations.append(
            (
                f"{blind_spot_report['summary']['high_blind_spots']} "
                "high-priority Blind Spot(s) are present."
            )
        )


    if untriaged:

        observations.append(
            (
                f"{len(untriaged)} evidence item(s) "
                "have not been triaged."
            )
        )


    if (
        correlation_intelligence[
            "relationship_count"
        ]
        > 0
    ):

        observations.append(
            (
                f"{correlation_intelligence['relationship_count']} "
                "deterministic cross-evidence "
                "relationship(s) are available."
            )
        )


    if (
        correlation_intelligence[
            "clusters"
        ]
    ):

        observations.append(
            (
                f"{len(correlation_intelligence['clusters'])} "
                "correlation cluster(s) may deserve "
                "investigator review."
            )
        )


    if not observations:

        observations.append(
            (
                "No major high-priority condition "
                "is currently present in the "
                "available SYNAPSE data."
            )
        )


    next_actions = []


    for item in top_priority[
        :3
    ]:

        next_actions.append(
            {
                "evidence_id":
                    item[
                        "evidence_id"
                    ],

                "filename":
                    item[
                        "filename"
                    ],

                "recommendation":
                    (
                        "Review this artifact next and "
                        "validate its forensic findings."
                    ),

                "reason":
                    "; ".join(
                        item[
                            "reasons"
                        ]
                    ),
            }
        )


    if (
        correlation_intelligence[
            "clusters"
        ]
    ):

        strongest_cluster = (
            correlation_intelligence[
                "clusters"
            ][0]
        )


        next_actions.append(
            {
                "evidence_id":
                    0,

                "filename":
                    strongest_cluster[
                        "cluster_id"
                    ],

                "recommendation":
                    (
                        "Review the correlation cluster "
                        "and validate the shared indicators "
                        "between its member artifacts."
                    ),

                "reason":
                    (
                        f"{strongest_cluster['member_count']} "
                        "artifacts are linked by "
                        f"{strongest_cluster['relationship_count']} "
                        "deterministic relationship(s)."
                    ),
            }
        )


    return {

        "case_id":
            case.id,

        "case_code":
            case.case_code,

        "case_name":
            case.name,

        "status":
            case.status,

        "headline":
            (
                f"{len(evidence_context)} evidence item(s), "
                f"{len(analyzed)} analyzed, "
                f"{len(high_risk)} high risk, "
                f"{blind_spot_report['summary']['high_blind_spots']} "
                "high Blind Spot(s), "
                f"{correlation_intelligence['relationship_count']} "
                "correlation(s)."
            ),

        "coverage":
            {
                "average":
                    coverage_report[
                        "summary"
                    ][
                        "average_coverage"
                    ],

                "strong_or_better":
                    coverage_report[
                        "summary"
                    ][
                        "strong_or_better"
                    ],

                "thorough":
                    coverage_report[
                        "summary"
                    ][
                        "thoroughly_covered"
                    ],
            },

        "correlations":
            {
                "relationships":
                    correlation_intelligence[
                        "relationship_count"
                    ],

                "clusters":
                    len(
                        correlation_intelligence[
                            "clusters"
                        ]
                    ),

                "relationship_types":
                    correlation_intelligence[
                        "relationship_type_counts"
                    ],
            },

        "observations":
            observations,

        "recommended_next_actions":
            next_actions,

        "top_priority":
            top_priority,

        "disclaimer":
            (
                "This brief is generated only from "
                "observable SYNAPSE case data. "
                "Correlations identify shared forensic "
                "properties and do not establish common "
                "origin, malicious coordination, guilt, "
                "intent, or causation."
            ),
    }


# =========================================================
# COMPLETE ANALYST CONTEXT
# =========================================================


def build_analyst_context(
    session: Session,
    case_id: int,
) -> dict:

    case = session.get(
        Case,
        case_id,
    )


    if case is None:

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


    ledger_summary = (
        get_ledger_summary(
            session=session,
            case_id=case_id,
        )
    )


    evidence_context = (
        build_evidence_context(
            session=session,
            case_id=case_id,
            coverage_report=(
                coverage_report
            ),
            blind_spot_report=(
                blind_spot_report
            ),
        )
    )


    priority_queue = (
        build_priority_queue(
            evidence_context
        )
    )


    correlation_intelligence = (
        build_correlation_intelligence(
            graph
        )
    )


    brief = (
        build_case_brief(
            case=case,
            evidence_context=(
                evidence_context
            ),
            coverage_report=(
                coverage_report
            ),
            blind_spot_report=(
                blind_spot_report
            ),
            priority_queue=(
                priority_queue
            ),
            correlation_intelligence=(
                correlation_intelligence
            ),
        )
    )


    return {

        "case":
            {
                "id":
                    case.id,

                "case_code":
                    case.case_code,

                "name":
                    case.name,

                "case_type":
                    case.case_type,

                "description":
                    case.description,

                "investigator":
                    case.investigator,

                "status":
                    case.status,
            },

        "brief":
            brief,

        "evidence":
            evidence_context,

        "priority_queue":
            priority_queue,

        "coverage_summary":
            coverage_report[
                "summary"
            ],

        "blind_spot_summary":
            blind_spot_report[
                "summary"
            ],

        "graph_summary":
            graph[
                "summary"
            ],

        "graph":
            {
                "nodes":
                    graph[
                        "nodes"
                    ],

                "edges":
                    graph[
                        "edges"
                    ],

                "clusters":
                    graph.get(
                        "clusters",
                        [],
                    ),
            },

        "correlation_intelligence":
            correlation_intelligence,

        "ledger":
            ledger_summary,

        "grounding_rules":
            [
                (
                    "Only make claims supported by "
                    "the supplied SYNAPSE case context."
                ),
                (
                    "Never invent a relationship between "
                    "evidence items."
                ),
                (
                    "Only describe a cross-evidence "
                    "correlation if it exists in the "
                    "deterministic graph or correlation "
                    "context."
                ),
                (
                    "A shared indicator does not prove "
                    "common origin or malicious coordination."
                ),
                (
                    "Correlation strength is a SYNAPSE "
                    "priority weight, not a probability."
                ),
                (
                    "Clearly distinguish forensic risk "
                    "from Blind Spot priority."
                ),
                (
                    "Do not claim that heuristic findings "
                    "prove maliciousness."
                ),
                (
                    "Do not claim that coverage proves "
                    "human understanding."
                ),
                (
                    "The investigator retains final "
                    "decision authority."
                ),
            ],
    }