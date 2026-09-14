from __future__ import annotations

from sqlmodel import (
    Session,
)

from .coverage_engine import (
    build_case_coverage_report,
)


# =========================================================
# BLIND SPOT CLASSIFICATION
# =========================================================


def classify_blind_spot(
    blind_spot_score: float,
    forensic_risk: float,
) -> str:

    if (
        forensic_risk >= 50
        and
        blind_spot_score >= 50
    ):

        return "HIGH"


    if blind_spot_score >= 25:

        return "MEDIUM"


    return "LOW"


# =========================================================
# REASON ENGINE
# =========================================================


def build_blind_spot_reasons(
    item: dict,
) -> list[str]:

    reasons: list[str] = []


    forensic_risk = (
        item.get(
            "forensic_risk"
        )
        or 0.0
    )


    coverage_score = (
        item[
            "coverage_score"
        ]
    )


    attention = (
        item[
            "attention"
        ]
    )


    actions = (
        item[
            "actions"
        ]
    )


    if forensic_risk >= 70:

        reasons.append(
            "Artifact has high forensic risk."
        )

    elif forensic_risk >= 35:

        reasons.append(
            "Artifact contains suspicious forensic indicators."
        )


    if coverage_score < 25:

        reasons.append(
            "Investigation coverage is minimal."
        )

    elif coverage_score < 50:

        reasons.append(
            "Investigation coverage is only partial."
        )


    if (
        attention[
            "focused_seconds"
        ]
        < 10
    ):

        reasons.append(
            "Focused review time is below 10 seconds."
        )


    if (
        attention[
            "view_count"
        ]
        <= 1
    ):

        reasons.append(
            "Evidence has been opened only once."
        )


    if (
        attention[
            "revisit_count"
        ]
        == 0
    ):

        reasons.append(
            "Evidence has not been revisited."
        )


    if not actions[
        "triage_completed"
    ]:

        reasons.append(
            "Forensic triage has not been completed."
        )


    if not actions[
        "integrity_verified"
    ]:

        reasons.append(
            "No investigator-triggered integrity "
            "verification is recorded."
        )


    if coverage_score >= 75:

        reasons.append(
            "Evidence currently has thorough observable coverage."
        )


    return reasons


# =========================================================
# BUILD BLIND SPOT REPORT
# =========================================================


def build_blind_spot_report(
    session: Session,
    case_id: int,
) -> dict:

    coverage_report = (
        build_case_coverage_report(
            session=session,
            case_id=case_id,
        )
    )


    blind_spots = []


    for item in coverage_report[
        "evidence_coverage"
    ]:

        forensic_risk = (
            item[
                "forensic_risk"
            ]
        )


        # Blind Spot analysis requires
        # completed forensic triage.
        if forensic_risk is None:

            continue


        forensic_risk = max(
            0.0,
            min(
                float(
                    forensic_risk
                ),
                100.0,
            ),
        )


        coverage_score = (
            item[
                "coverage_score"
            ]
        )


        # =================================================
        # CORE SYNAPSE EQUATION
        #
        # Blind Spot =
        # Forensic Risk × Missing Coverage
        #
        # Example:
        #
        # Risk = 80
        # Coverage = 20
        #
        # 80 × (1 - 0.20)
        # = 64
        # =================================================

        blind_spot_score = (

            forensic_risk

            *

            (
                1.0
                -
                coverage_score
                /
                100.0
            )
        )


        blind_spot_score = round(

            max(
                0.0,
                min(
                    blind_spot_score,
                    100.0,
                ),
            ),

            2,
        )


        severity = (
            classify_blind_spot(
                blind_spot_score=(
                    blind_spot_score
                ),
                forensic_risk=(
                    forensic_risk
                ),
            )
        )


        reasons = (
            build_blind_spot_reasons(
                item
            )
        )


        blind_spots.append(
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

                "extension":
                    item[
                        "extension"
                    ],

                "forensic_risk":
                    round(
                        forensic_risk,
                        2,
                    ),

                "risk_level":
                    item[
                        "risk_level"
                    ],

                "review_score":
                    coverage_score,

                "coverage_score":
                    coverage_score,

                "coverage_level":
                    item[
                        "coverage_level"
                    ],

                "blind_spot_score":
                    blind_spot_score,

                "severity":
                    severity,

                "view_count":
                    item[
                        "attention"
                    ][
                        "view_count"
                    ],

                "revisit_count":
                    item[
                        "attention"
                    ][
                        "revisit_count"
                    ],

                "dwell_seconds":
                    item[
                        "attention"
                    ][
                        "total_view_seconds"
                    ],

                "focused_seconds":
                    item[
                        "attention"
                    ][
                        "focused_seconds"
                    ],

                "focus_ratio":
                    item[
                        "components"
                    ][
                        "visible_tab_ratio"
                    ],

                "review_components":
                    {

                        "focused_duration":
                            item[
                                "components"
                            ][
                                "focused_duration"
                            ],

                        "views":
                            item[
                                "components"
                            ][
                                "views"
                            ],

                        "revisits":
                            item[
                                "components"
                            ][
                                "revisits"
                            ],

                        "visible_tab_ratio":
                            item[
                                "components"
                            ][
                                "visible_tab_ratio"
                            ],

                        "investigation_actions":
                            item[
                                "components"
                            ][
                                "investigation_actions"
                            ],
                    },

                "actions":
                    item[
                        "actions"
                    ],

                "reasons":
                    reasons,
            }
        )


    blind_spots.sort(
        key=lambda item: (
            item[
                "blind_spot_score"
            ],
            item[
                "forensic_risk"
            ],
        ),
        reverse=True,
    )


    high_count = sum(
        1
        for item
        in blind_spots
        if item[
            "severity"
        ] == "HIGH"
    )


    medium_count = sum(
        1
        for item
        in blind_spots
        if item[
            "severity"
        ] == "MEDIUM"
    )


    low_count = sum(
        1
        for item
        in blind_spots
        if item[
            "severity"
        ] == "LOW"
    )


    reviewed_count = sum(
        1
        for item
        in blind_spots
        if item[
            "coverage_score"
        ] > 0
    )


    return {

        "case_id":
            case_id,

        "formula":
            (
                "blind_spot_score = "
                "forensic_risk × "
                "(1 - coverage_score / 100)"
            ),

        "coverage_formula":
            coverage_report[
                "formula"
            ],

        "summary":
            {

                "analyzed_evidence":
                    len(
                        blind_spots
                    ),

                "high_blind_spots":
                    high_count,

                "medium_blind_spots":
                    medium_count,

                "low_blind_spots":
                    low_count,

                "reviewed_evidence":
                    reviewed_count,

                "unreviewed_evidence":
                    (
                        len(
                            blind_spots
                        )
                        -
                        reviewed_count
                    ),
            },

        "blind_spots":
            blind_spots,

        "disclaimer":
            (
                "Blind Spot Score is a review-priority "
                "signal derived from forensic risk and "
                "observable investigation coverage. It "
                "does not determine guilt, intent, or "
                "conclusive maliciousness."
            ),
    }