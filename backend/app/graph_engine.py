from __future__ import annotations

from sqlmodel import (
    Session,
    select,
)

from .correlation_engine import (
    build_correlation_report,
)

from .models import (
    ArtifactTriage,
    Case,
    Evidence,
    MLPrediction,
)


# =========================================================
# LATEST ML PREDICTIONS
# =========================================================


def get_latest_predictions(
    session: Session,
    case_id: int,
) -> dict[int, MLPrediction]:

    statement = (
        select(MLPrediction)
        .where(
            MLPrediction.case_id
            == case_id
        )
        .order_by(
            MLPrediction.created_at.desc()
        )
    )


    records = list(
        session.exec(
            statement
        ).all()
    )


    latest: dict[
        int,
        MLPrediction
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
# LATEST PERSISTED TRIAGE
# =========================================================


def get_latest_triage(
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
# RISK RESOLUTION
# =========================================================
#
# Preferred:
#   ArtifactTriage
#
# Fallback:
#   old PE MLPrediction
#
# This means PDF/TXT/PNG/etc. can finally display risk in the
# graph instead of only PE files.
# =========================================================


def resolve_evidence_risk(
    evidence_id: int,
    triage_map: dict[
        int,
        ArtifactTriage
    ],
    prediction_map: dict[
        int,
        MLPrediction
    ],
) -> dict:

    triage = (
        triage_map.get(
            evidence_id
        )
    )


    if triage is not None:

        return {
            "risk":
                round(
                    float(
                        triage.risk_score
                    ),
                    2,
                ),

            "risk_level":
                triage.risk_level,

            "risk_source":
                "ArtifactTriage",

            "analyzer":
                triage.analyzer,
        }


    prediction = (
        prediction_map.get(
            evidence_id
        )
    )


    if prediction is not None:

        return {
            "risk":
                round(
                    float(
                        prediction
                        .malicious_probability
                    )
                    * 100,
                    2,
                ),

            "risk_level":
                prediction.risk_level,

            "risk_source":
                "MLPrediction",

            "analyzer":
                prediction.model_name,
        }


    return {
        "risk":
            None,

        "risk_level":
            None,

        "risk_source":
            None,

        "analyzer":
            None,
    }


# =========================================================
# CORRELATION EDGE LABEL
# =========================================================


def build_relation_label(
    relation: dict,
) -> str:

    relation_type = (
        relation[
            "relation_type"
        ]
    )


    indicator_value = (
        relation.get(
            "indicator_value"
        )
    )


    labels = {

        "SAME_SHA256":
            "Exact file duplicate",

        "SHARED_HASH":
            "Shared hash indicator",

        "SHARED_IP":
            "Shared IP address",

        "SHARED_DOMAIN":
            "Shared domain",

        "SHARED_URL":
            "Shared URL",

        "SHARED_EMAIL":
            "Shared email indicator",

        "SHARED_INDICATOR":
            "Shared forensic indicator",

        "SAME_FILENAME_DIFFERENT_HASH":
            (
                "Same filename, "
                "different content"
            ),
    }


    base_label = (
        labels.get(
            relation_type,
            relation_type.replace(
                "_",
                " ",
            ).title(),
        )
    )


    if not indicator_value:

        return base_label


    value = str(
        indicator_value
    )


    if len(value) > 42:

        value = (
            value[:39]
            +
            "..."
        )


    return (
        f"{base_label}: "
        f"{value}"
    )


# =========================================================
# CASE GRAPH
# =========================================================


def build_case_graph(
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


    prediction_map = (
        get_latest_predictions(
            session=session,
            case_id=case_id,
        )
    )


    triage_map = (
        get_latest_triage(
            session=session,
            case_id=case_id,
        )
    )


    correlation_report = (
        build_correlation_report(
            session=session,
            case_id=case_id,
        )
    )


    nodes: list[dict] = []

    edges: list[dict] = []


    # =====================================================
    # CASE NODE
    # =====================================================

    case_node_id = (
        f"case-{case_id}"
    )


    nodes.append(
        {
            "id":
                case_node_id,

            "type":
                "case",

            "label":
                forensic_case.name,

            "subtitle":
                forensic_case.case_code,

            "status":
                forensic_case.status,

            "evidence_id":
                None,

            "extension":
                None,

            "size":
                None,

            "entropy":
                None,

            "integrity":
                None,

            "risk":
                None,

            "risk_level":
                None,

            "risk_source":
                None,

            "analyzer":
                None,
        }
    )


    # =====================================================
    # EVIDENCE NODES
    # =====================================================

    high_risk_nodes = 0

    suspicious_nodes = 0

    analyzed_nodes = 0


    for evidence in evidence_items:

        risk_data = (
            resolve_evidence_risk(
                evidence_id=(
                    evidence.id
                ),
                triage_map=(
                    triage_map
                ),
                prediction_map=(
                    prediction_map
                ),
            )
        )


        if (
            risk_data[
                "risk"
            ]
            is not None
        ):

            analyzed_nodes += 1


        if (
            risk_data[
                "risk_level"
            ]
            == "HIGH RISK"
        ):

            high_risk_nodes += 1


        if (
            risk_data[
                "risk_level"
            ]
            == "SUSPICIOUS"
        ):

            suspicious_nodes += 1


        evidence_node_id = (
            f"evidence-{evidence.id}"
        )


        nodes.append(
            {
                "id":
                    evidence_node_id,

                "type":
                    "evidence",

                "label":
                    evidence.original_filename,

                "subtitle":
                    evidence.evidence_code,

                "status":
                    evidence.status,

                "evidence_id":
                    evidence.id,

                "extension":
                    evidence.file_extension,

                "size":
                    evidence.file_size,

                "entropy":
                    evidence.entropy,

                "integrity":
                    evidence.integrity_status,

                "risk":
                    risk_data[
                        "risk"
                    ],

                "risk_level":
                    risk_data[
                        "risk_level"
                    ],

                "risk_source":
                    risk_data[
                        "risk_source"
                    ],

                "analyzer":
                    risk_data[
                        "analyzer"
                    ],
            }
        )


        # -------------------------------------------------
        # CASE CONTAINS EVIDENCE
        # -------------------------------------------------

        edges.append(
            {
                "id":
                    (
                        f"contains-"
                        f"{case_id}-"
                        f"{evidence.id}"
                    ),

                "source":
                    case_node_id,

                "target":
                    evidence_node_id,

                "type":
                    "CONTAINS",

                "label":
                    "Contains",

                "strength":
                    100.0,

                "level":
                    "STRUCTURAL",

                "indicator_type":
                    None,

                "indicator_value":
                    None,

                "reason":
                    (
                        "Evidence belongs to "
                        "this forensic case."
                    ),
            }
        )


    # =====================================================
    # ADVANCED FORENSIC CORRELATION EDGES
    # =====================================================

    relation_type_counts: dict[
        str,
        int
    ] = {}


    strong_correlations = 0

    medium_correlations = 0

    weak_correlations = 0


    for index, relation in enumerate(
        correlation_report[
            "relationships"
        ]
    ):

        relation_type = (
            relation[
                "relation_type"
            ]
        )


        relation_type_counts[
            relation_type
        ] = (
            relation_type_counts.get(
                relation_type,
                0,
            )
            +
            1
        )


        level = (
            relation[
                "level"
            ]
        )


        if level == "STRONG":

            strong_correlations += 1

        elif level == "MEDIUM":

            medium_correlations += 1

        else:

            weak_correlations += 1


        source_id = (
            relation[
                "source_evidence_id"
            ]
        )


        target_id = (
            relation[
                "target_evidence_id"
            ]
        )


        edges.append(
            {
                "id":
                    (
                        f"correlation-"
                        f"{index + 1}-"
                        f"{source_id}-"
                        f"{target_id}"
                    ),

                "source":
                    (
                        f"evidence-"
                        f"{source_id}"
                    ),

                "target":
                    (
                        f"evidence-"
                        f"{target_id}"
                    ),

                "type":
                    relation_type,

                "label":
                    build_relation_label(
                        relation
                    ),

                "strength":
                    relation[
                        "strength"
                    ],

                "level":
                    relation[
                        "level"
                    ],

                "indicator_type":
                    relation.get(
                        "indicator_type"
                    ),

                "indicator_value":
                    relation.get(
                        "indicator_value"
                    ),

                "reason":
                    relation[
                        "reason"
                    ],
            }
        )


    # =====================================================
    # COMPATIBILITY COUNTS
    #
    # Old frontend types expected these fields.
    # We keep them until the frontend graph is upgraded.
    # =====================================================

    duplicate_links = (
        relation_type_counts.get(
            "SAME_SHA256",
            0,
        )
    )


    summary = {

        "total_nodes":
            len(
                nodes
            ),

        "total_edges":
            len(
                edges
            ),

        "evidence_nodes":
            len(
                evidence_items
            ),

        "analyzed_nodes":
            analyzed_nodes,

        "high_risk_nodes":
            high_risk_nodes,

        "suspicious_nodes":
            suspicious_nodes,

        "correlated_evidence":
            correlation_report[
                "summary"
            ][
                "correlated_evidence"
            ],

        "uncorrelated_evidence":
            correlation_report[
                "summary"
            ][
                "uncorrelated_evidence"
            ],

        "correlation_links":
            correlation_report[
                "summary"
            ][
                "total_relationships"
            ],

        "strong_correlations":
            strong_correlations,

        "medium_correlations":
            medium_correlations,

        "weak_correlations":
            weak_correlations,

        "clusters":
            correlation_report[
                "summary"
            ][
                "clusters"
            ],

        "relationship_types":
            relation_type_counts,

        # ---------------------------------------------
        # Legacy fields kept temporarily.
        # ---------------------------------------------

        "duplicate_links":
            duplicate_links,

        "same_type_links":
            0,

        "entropy_links":
            0,

        "risk_similarity_links":
            0,
    }


    return {

        "success":
            True,

        "case_id":
            case_id,

        "case_code":
            forensic_case.case_code,

        "nodes":
            nodes,

        "edges":
            edges,

        "clusters":
            correlation_report[
                "clusters"
            ],

        "summary":
            summary,

        "methodology":
            (
                correlation_report[
                    "methodology"
                ]
            ),

        "disclaimer":
            (
                "Evidence relationships are based on "
                "observable forensic properties and "
                "shared indicators. Correlation does "
                "not by itself establish common origin, "
                "maliciousness, intent, or causation."
            ),
    }