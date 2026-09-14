from __future__ import annotations

import ipaddress
import json

from collections import defaultdict, deque

from pathlib import Path

from urllib.parse import (
    urlsplit,
    urlunsplit,
)

from sqlmodel import (
    Session,
    select,
)

from .models import (
    ArtifactTriage,
    Evidence,
)


# =========================================================
# CONSTANTS
# =========================================================


STRONG_THRESHOLD = 80.0
MEDIUM_THRESHOLD = 60.0


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
# NORMALIZATION
# =========================================================


def normalize_indicator_type(
    indicator_type: str,
) -> str:

    value = (
        indicator_type
        .strip()
        .upper()
        .replace(
            "-",
            "_",
        )
        .replace(
            " ",
            "_",
        )
    )


    aliases = {

        "IP":
            "IP_ADDRESS",

        "IPV4":
            "IP_ADDRESS",

        "IP_ADDRESS_V4":
            "IP_ADDRESS",

        "DOMAIN_NAME":
            "DOMAIN",

        "HOST":
            "DOMAIN",

        "HOSTNAME":
            "DOMAIN",

        "URI":
            "URL",

        "WEB_URL":
            "URL",

        "EMAIL_ADDRESS":
            "EMAIL",

        "SHA_256":
            "SHA256",

        "SHA_1":
            "SHA1",

    }


    return aliases.get(
        value,
        value,
    )


def normalize_url(
    value: str,
) -> str | None:

    candidate = (
        value
        .strip()
    )


    if not candidate:

        return None


    try:

        parsed = urlsplit(
            candidate
        )


        if not parsed.scheme:

            parsed = urlsplit(
                f"http://{candidate}"
            )


        hostname = (
            parsed.hostname
            or ""
        ).lower()


        if not hostname:

            return None


        scheme = (
            parsed.scheme.lower()
            if parsed.scheme
            else "http"
        )


        port = (
            f":{parsed.port}"
            if parsed.port
            else ""
        )


        netloc = (
            f"{hostname}{port}"
        )


        path = (
            parsed.path
            or "/"
        )


        normalized = (
            urlunsplit(
                (
                    scheme,
                    netloc,
                    path,
                    parsed.query,
                    "",
                )
            )
        )


        return normalized.rstrip(
            "/"
        )


    except Exception:

        return None


def extract_domain_from_url(
    value: str,
) -> str | None:

    candidate = (
        value.strip()
    )


    if not candidate:

        return None


    try:

        parsed = urlsplit(
            candidate
        )


        if not parsed.hostname:

            parsed = urlsplit(
                f"http://{candidate}"
            )


        hostname = (
            parsed.hostname
            or ""
        ).strip().lower()


        if not hostname:

            return None


        return hostname.rstrip(
            "."
        )


    except Exception:

        return None


def normalize_indicator_value(
    indicator_type: str,
    value: str,
) -> str | None:

    raw = (
        str(value)
        .strip()
    )


    if not raw:

        return None


    kind = (
        normalize_indicator_type(
            indicator_type
        )
    )


    if kind == "IP_ADDRESS":

        try:

            return str(
                ipaddress.ip_address(
                    raw
                )
            )

        except ValueError:

            return None


    if kind == "DOMAIN":

        return (
            raw
            .lower()
            .rstrip(
                "."
            )
        )


    if kind == "URL":

        return normalize_url(
            raw
        )


    if kind in {
        "SHA256",
        "SHA1",
        "MD5",
        "HASH",
    }:

        return (
            raw
            .lower()
            .replace(
                " ",
                "",
            )
        )


    if kind == "EMAIL":

        return raw.lower()


    return raw.lower()


# =========================================================
# TRIAGE INDICATORS
# =========================================================


def extract_indicator_records(
    evidence: Evidence,
    triage: ArtifactTriage | None,
) -> list[dict]:

    if triage is None:

        return []


    raw_indicators = (
        safe_json_list(
            triage.indicators_json
        )
    )


    records: list[dict] = []


    for indicator in raw_indicators:

        if not isinstance(
            indicator,
            dict,
        ):

            continue


        raw_type = str(
            indicator.get(
                "type",
                "",
            )
        )


        raw_value = str(
            indicator.get(
                "value",
                "",
            )
        )


        normalized_type = (
            normalize_indicator_type(
                raw_type
            )
        )


        normalized_value = (
            normalize_indicator_value(
                normalized_type,
                raw_value,
            )
        )


        if not normalized_value:

            continue


        records.append(
            {
                "evidence_id":
                    evidence.id,

                "evidence_code":
                    evidence.evidence_code,

                "filename":
                    evidence.original_filename,

                "type":
                    normalized_type,

                "value":
                    normalized_value,

                "original_value":
                    raw_value,
            }
        )


        # -------------------------------------------------
        # URL → DOMAIN derived indicator
        #
        # Two files may reference different paths on the
        # same host. That is still a useful correlation.
        # -------------------------------------------------

        if normalized_type == "URL":

            domain = (
                extract_domain_from_url(
                    normalized_value
                )
            )


            if domain:

                records.append(
                    {
                        "evidence_id":
                            evidence.id,

                        "evidence_code":
                            evidence.evidence_code,

                        "filename":
                            evidence.original_filename,

                        "type":
                            "DERIVED_DOMAIN",

                        "value":
                            domain,

                        "original_value":
                            domain,
                    }
                )


    return records


# =========================================================
# RELATION STRENGTH
# =========================================================


def relation_strength(
    relation_type: str,
) -> float:

    strengths = {

        "SAME_SHA256":
            100.0,

        "SHARED_HASH":
            95.0,

        "SHARED_URL":
            90.0,

        "SHARED_IP":
            85.0,

        "SHARED_EMAIL":
            80.0,

        "SHARED_DOMAIN":
            78.0,

        "SAME_FILENAME_DIFFERENT_HASH":
            65.0,

        "SHARED_INDICATOR":
            70.0,
    }


    return strengths.get(
        relation_type,
        60.0,
    )


def relation_level(
    strength: float,
) -> str:

    if strength >= STRONG_THRESHOLD:

        return "STRONG"


    if strength >= MEDIUM_THRESHOLD:

        return "MEDIUM"


    return "WEAK"


# =========================================================
# RELATION TYPE FROM IOC
# =========================================================


def indicator_relation_type(
    indicator_type: str,
) -> str:

    if indicator_type in {
        "SHA256",
        "SHA1",
        "MD5",
        "HASH",
    }:

        return "SHARED_HASH"


    if indicator_type == "URL":

        return "SHARED_URL"


    if indicator_type == "IP_ADDRESS":

        return "SHARED_IP"


    if indicator_type in {
        "DOMAIN",
        "DERIVED_DOMAIN",
    }:

        return "SHARED_DOMAIN"


    if indicator_type == "EMAIL":

        return "SHARED_EMAIL"


    return "SHARED_INDICATOR"


# =========================================================
# PAIR KEY
# =========================================================


def pair_key(
    first_id: int,
    second_id: int,
) -> tuple[int, int]:

    return tuple(
        sorted(
            (
                first_id,
                second_id,
            )
        )
    )


# =========================================================
# RELATION BUILDER
# =========================================================


def make_relation(
    first: Evidence,
    second: Evidence,
    relation_type: str,
    reason: str,
    indicator_type: str | None = None,
    indicator_value: str | None = None,
) -> dict:

    strength = (
        relation_strength(
            relation_type
        )
    )


    return {

        "source_evidence_id":
            first.id,

        "source_evidence_code":
            first.evidence_code,

        "source_filename":
            first.original_filename,

        "target_evidence_id":
            second.id,

        "target_evidence_code":
            second.evidence_code,

        "target_filename":
            second.original_filename,

        "relation_type":
            relation_type,

        "strength":
            strength,

        "level":
            relation_level(
                strength
            ),

        "indicator_type":
            indicator_type,

        "indicator_value":
            indicator_value,

        "reason":
            reason,
    }


# =========================================================
# EXACT FILE RELATIONSHIPS
# =========================================================


def build_file_relations(
    evidence_items: list[Evidence],
) -> list[dict]:

    relations: list[dict] = []


    # -----------------------------------------------------
    # Same SHA-256
    # -----------------------------------------------------

    hash_groups: dict[
        str,
        list[Evidence]
    ] = defaultdict(
        list
    )


    for evidence in evidence_items:

        sha256 = (
            evidence.sha256
            or ""
        ).strip().lower()


        if sha256:

            hash_groups[
                sha256
            ].append(
                evidence
            )


    for sha256, items in (
        hash_groups.items()
    ):

        if len(items) < 2:

            continue


        for index in range(
            len(items)
        ):

            for other_index in range(
                index + 1,
                len(items),
            ):

                first = items[
                    index
                ]

                second = items[
                    other_index
                ]


                relations.append(
                    make_relation(

                        first=first,

                        second=second,

                        relation_type=(
                            "SAME_SHA256"
                        ),

                        reason=(
                            "Both evidence items have "
                            "the exact same SHA-256 hash."
                        ),

                        indicator_type=(
                            "SHA256"
                        ),

                        indicator_value=(
                            sha256
                        ),
                    )
                )


    # -----------------------------------------------------
    # Same filename but different hashes
    #
    # This does NOT prove maliciousness.
    # It simply deserves investigator attention because
    # two different files are using the same visible name.
    # -----------------------------------------------------

    filename_groups: dict[
        str,
        list[Evidence]
    ] = defaultdict(
        list
    )


    for evidence in evidence_items:

        normalized_name = (
            evidence.original_filename
            .strip()
            .lower()
        )


        if normalized_name:

            filename_groups[
                normalized_name
            ].append(
                evidence
            )


    for filename, items in (
        filename_groups.items()
    ):

        if len(items) < 2:

            continue


        for index in range(
            len(items)
        ):

            for other_index in range(
                index + 1,
                len(items),
            ):

                first = items[
                    index
                ]

                second = items[
                    other_index
                ]


                first_hash = (
                    first.sha256
                    or ""
                ).lower()


                second_hash = (
                    second.sha256
                    or ""
                ).lower()


                if (
                    first_hash
                    and
                    second_hash
                    and
                    first_hash
                    != second_hash
                ):

                    relations.append(
                        make_relation(

                            first=first,

                            second=second,

                            relation_type=(
                                "SAME_FILENAME_DIFFERENT_HASH"
                            ),

                            reason=(
                                "Both artifacts use the "
                                f"filename '{filename}' but "
                                "their SHA-256 hashes differ."
                            ),
                        )
                    )


    return relations


# =========================================================
# IOC RELATIONSHIPS
# =========================================================


def build_indicator_relations(
    evidence_items: list[Evidence],
    triage_map: dict[
        int,
        ArtifactTriage
    ],
) -> list[dict]:

    evidence_by_id = {

        evidence.id:
            evidence

        for evidence
        in evidence_items
    }


    grouped: dict[
        tuple[str, str],
        set[int]
    ] = defaultdict(
        set
    )


    for evidence in evidence_items:

        triage = (
            triage_map.get(
                evidence.id
            )
        )


        records = (
            extract_indicator_records(
                evidence=evidence,
                triage=triage,
            )
        )


        for record in records:

            grouped[
                (
                    record[
                        "type"
                    ],
                    record[
                        "value"
                    ],
                )
            ].add(
                evidence.id
            )


    relations: list[dict] = []


    for (
        indicator_type,
        indicator_value,
    ), evidence_ids in (
        grouped.items()
    ):

        if len(
            evidence_ids
        ) < 2:

            continue


        sorted_ids = sorted(
            evidence_ids
        )


        relation_type = (
            indicator_relation_type(
                indicator_type
            )
        )


        for index in range(
            len(sorted_ids)
        ):

            for other_index in range(
                index + 1,
                len(sorted_ids),
            ):

                first = (
                    evidence_by_id[
                        sorted_ids[
                            index
                        ]
                    ]
                )


                second = (
                    evidence_by_id[
                        sorted_ids[
                            other_index
                        ]
                    ]
                )


                display_type = (
                    "DOMAIN"
                    if indicator_type
                    == "DERIVED_DOMAIN"
                    else indicator_type
                )


                relations.append(
                    make_relation(

                        first=first,

                        second=second,

                        relation_type=(
                            relation_type
                        ),

                        reason=(
                            "Both evidence items reference "
                            f"the same {display_type}: "
                            f"{indicator_value}"
                        ),

                        indicator_type=(
                            display_type
                        ),

                        indicator_value=(
                            indicator_value
                        ),
                    )
                )


    return relations


# =========================================================
# DEDUPLICATE RELATIONS
# =========================================================


def deduplicate_relations(
    relations: list[dict],
) -> list[dict]:

    seen: set[
        tuple
    ] = set()


    output: list[dict] = []


    for relation in relations:

        pair = pair_key(
            relation[
                "source_evidence_id"
            ],
            relation[
                "target_evidence_id"
            ],
        )


        key = (

            pair[0],

            pair[1],

            relation[
                "relation_type"
            ],

            relation.get(
                "indicator_type"
            ),

            relation.get(
                "indicator_value"
            ),
        )


        if key in seen:

            continue


        seen.add(
            key
        )


        output.append(
            relation
        )


    output.sort(
        key=lambda item: (
            item[
                "strength"
            ],
            item[
                "relation_type"
            ],
        ),
        reverse=True,
    )


    return output


# =========================================================
# CORRELATION CLUSTERS
# =========================================================


def build_clusters(
    evidence_items: list[Evidence],
    relations: list[dict],
) -> list[dict]:

    # Only meaningful medium/strong relationships
    # participate in clusters.

    adjacency: dict[
        int,
        set[int]
    ] = defaultdict(
        set
    )


    edge_lookup: dict[
        tuple[int, int],
        list[dict]
    ] = defaultdict(
        list
    )


    for relation in relations:

        if (
            relation[
                "strength"
            ]
            < MEDIUM_THRESHOLD
        ):

            continue


        first = (
            relation[
                "source_evidence_id"
            ]
        )


        second = (
            relation[
                "target_evidence_id"
            ]
        )


        adjacency[
            first
        ].add(
            second
        )


        adjacency[
            second
        ].add(
            first
        )


        edge_lookup[
            pair_key(
                first,
                second,
            )
        ].append(
            relation
        )


    evidence_by_id = {

        evidence.id:
            evidence

        for evidence
        in evidence_items
    }


    visited: set[int] = set()

    clusters = []


    for evidence_id in (
        adjacency.keys()
    ):

        if evidence_id in visited:

            continue


        queue = deque(
            [
                evidence_id
            ]
        )


        component: list[int] = []


        while queue:

            current = (
                queue.popleft()
            )


            if current in visited:

                continue


            visited.add(
                current
            )


            component.append(
                current
            )


            for neighbor in (
                adjacency[
                    current
                ]
            ):

                if (
                    neighbor
                    not in visited
                ):

                    queue.append(
                        neighbor
                    )


        if len(component) < 2:

            continue


        component_set = set(
            component
        )


        cluster_relations = [

            relation

            for relation
            in relations

            if (
                relation[
                    "source_evidence_id"
                ]
                in component_set
                and
                relation[
                    "target_evidence_id"
                ]
                in component_set
                and
                relation[
                    "strength"
                ]
                >= MEDIUM_THRESHOLD
            )
        ]


        max_strength = max(
            relation[
                "strength"
            ]
            for relation
            in cluster_relations
        )


        average_strength = round(

            sum(
                relation[
                    "strength"
                ]
                for relation
                in cluster_relations
            )
            /
            len(
                cluster_relations
            ),

            2,
        )


        relation_types = sorted(
            {
                relation[
                    "relation_type"
                ]

                for relation
                in cluster_relations
            }
        )


        members = []


        for member_id in sorted(
            component
        ):

            evidence = (
                evidence_by_id[
                    member_id
                ]
            )


            members.append(
                {
                    "evidence_id":
                        evidence.id,

                    "evidence_code":
                        evidence.evidence_code,

                    "filename":
                        evidence.original_filename,
                }
            )


        clusters.append(
            {
                "cluster_id":
                    (
                        f"CLUSTER-"
                        f"{len(clusters) + 1:03d}"
                    ),

                "member_count":
                    len(
                        members
                    ),

                "relationship_count":
                    len(
                        cluster_relations
                    ),

                "maximum_strength":
                    max_strength,

                "average_strength":
                    average_strength,

                "relation_types":
                    relation_types,

                "members":
                    members,
            }
        )


    clusters.sort(
        key=lambda item: (
            item[
                "member_count"
            ],
            item[
                "maximum_strength"
            ],
        ),
        reverse=True,
    )


    return clusters


# =========================================================
# SUMMARY
# =========================================================


def build_summary(
    evidence_items: list[Evidence],
    relations: list[dict],
    clusters: list[dict],
) -> dict:

    type_counts: dict[
        str,
        int
    ] = defaultdict(
        int
    )


    connected_evidence: set[
        int
    ] = set()


    strong = 0
    medium = 0
    weak = 0


    for relation in relations:

        type_counts[
            relation[
                "relation_type"
            ]
        ] += 1


        connected_evidence.add(
            relation[
                "source_evidence_id"
            ]
        )


        connected_evidence.add(
            relation[
                "target_evidence_id"
            ]
        )


        level = (
            relation[
                "level"
            ]
        )


        if level == "STRONG":

            strong += 1

        elif level == "MEDIUM":

            medium += 1

        else:

            weak += 1


    return {

        "total_evidence":
            len(
                evidence_items
            ),

        "correlated_evidence":
            len(
                connected_evidence
            ),

        "uncorrelated_evidence":
            (
                len(
                    evidence_items
                )
                -
                len(
                    connected_evidence
                )
            ),

        "total_relationships":
            len(
                relations
            ),

        "strong_relationships":
            strong,

        "medium_relationships":
            medium,

        "weak_relationships":
            weak,

        "clusters":
            len(
                clusters
            ),

        "relationship_types":
            dict(
                sorted(
                    type_counts.items()
                )
            ),
    }


# =========================================================
# COMPLETE CORRELATION REPORT
# =========================================================


def build_correlation_report(
    session: Session,
    case_id: int,
) -> dict:

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


    file_relations = (
        build_file_relations(
            evidence_items
        )
    )


    indicator_relations = (
        build_indicator_relations(
            evidence_items=(
                evidence_items
            ),
            triage_map=(
                triage_map
            ),
        )
    )


    relations = (
        deduplicate_relations(
            file_relations
            +
            indicator_relations
        )
    )


    clusters = (
        build_clusters(
            evidence_items=(
                evidence_items
            ),
            relations=(
                relations
            ),
        )
    )


    summary = (
        build_summary(
            evidence_items=(
                evidence_items
            ),
            relations=(
                relations
            ),
            clusters=(
                clusters
            ),
        )
    )


    return {

        "case_id":
            case_id,

        "summary":
            summary,

        "relationships":
            relations,

        "clusters":
            clusters,

        "methodology":
            {
                "strong_threshold":
                    STRONG_THRESHOLD,

                "medium_threshold":
                    MEDIUM_THRESHOLD,

                "rules":
                    [
                        (
                            "Exact SHA-256 matches are "
                            "treated as duplicate-content "
                            "relationships."
                        ),
                        (
                            "Shared URLs, IP addresses, "
                            "domains, hashes, emails and "
                            "other extracted indicators "
                            "create deterministic "
                            "cross-evidence relationships."
                        ),
                        (
                            "Different artifacts using the "
                            "same filename but different "
                            "SHA-256 hashes are surfaced "
                            "for investigator review."
                        ),
                        (
                            "URL hostnames are also derived "
                            "as domain indicators so "
                            "different URLs on the same "
                            "host can be correlated."
                        ),
                    ],
            },

        "disclaimer":
            (
                "Correlation means that observable forensic "
                "properties or indicators are shared between "
                "artifacts. A relationship does not by itself "
                "prove common origin, maliciousness, intent, "
                "or causation."
            ),
    }