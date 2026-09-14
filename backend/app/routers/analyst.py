from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)

from pydantic import (
    BaseModel,
    Field,
)

from sqlmodel import Session

from ..ai_analyst import (
    AIAnalystConfigurationError,
    AIAnalystGenerationError,
    ask_grounded_analyst,
    get_model_name,
)

from ..analyst_engine import (
    build_analyst_context,
)

from ..database import (
    get_session,
)

from ..ledger import (
    create_ledger_entry,
)

from ..models import (
    Case,
)


router = APIRouter(
    prefix="/api/analyst",
    tags=["AI Forensic Analyst"],
)


SessionDep = Annotated[
    Session,
    Depends(get_session),
]


# =========================================================
# REQUEST / RESPONSE
# =========================================================


class AnalystQuestionRequest(
    BaseModel
):

    question: str = Field(
        min_length=3,
        max_length=2000,
    )


class AnalystAnswerResponse(
    BaseModel
):

    case_id: int

    question: str

    answer: str

    evidence_references: list[str]

    recommended_actions: list[str]

    limitations: list[str]

    model_name: str

    grounded: bool


# =========================================================
# FULL GROUNDED CASE CONTEXT
# =========================================================


@router.get(
    "/cases/{case_id}/context",
)
def get_analyst_context(
    case_id: int,
    session: SessionDep,
):

    forensic_case = session.get(
        Case,
        case_id,
    )


    if forensic_case is None:

        raise HTTPException(
            status_code=404,
            detail=(
                "Forensic case not found."
            ),
        )


    try:

        return build_analyst_context(
            session=session,
            case_id=case_id,
        )


    except ValueError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error),
        )


# =========================================================
# DETERMINISTIC CASE BRIEF
# =========================================================


@router.get(
    "/cases/{case_id}/brief",
)
def get_analyst_brief(
    case_id: int,
    session: SessionDep,
):

    forensic_case = session.get(
        Case,
        case_id,
    )


    if forensic_case is None:

        raise HTTPException(
            status_code=404,
            detail=(
                "Forensic case not found."
            ),
        )


    context = (
        build_analyst_context(
            session=session,
            case_id=case_id,
        )
    )


    return {
        "case":
            context[
                "case"
            ],

        "brief":
            context[
                "brief"
            ],

        "priority_queue":
            context[
                "priority_queue"
            ],
    }


# =========================================================
# AI STATUS
# =========================================================


@router.get(
    "/status",
)
def analyst_status():

    return {
        "service":
            "SYNAPSE AI Forensic Analyst",

        "provider":
            "Google Gemini",

        "model":
            get_model_name(),

        "grounding":
            "SYNAPSE case context",

        "status":
            "configured",
    }


# =========================================================
# ASK GROUNDED AI ANALYST
# =========================================================


@router.post(
    "/cases/{case_id}/ask",
    response_model=(
        AnalystAnswerResponse
    ),
)
def ask_analyst(
    case_id: int,
    payload: AnalystQuestionRequest,
    session: SessionDep,
):

    forensic_case = session.get(
        Case,
        case_id,
    )


    if forensic_case is None:

        raise HTTPException(
            status_code=404,
            detail=(
                "Forensic case not found."
            ),
        )


    question = (
        payload.question
        .strip()
    )


    if len(question) < 3:

        raise HTTPException(
            status_code=422,
            detail=(
                "Question is too short."
            ),
        )


    try:

        context = (
            build_analyst_context(
                session=session,
                case_id=case_id,
            )
        )


        result = (
            ask_grounded_analyst(
                question=question,
                context=context,
            )
        )


    except AIAnalystConfigurationError as error:

        raise HTTPException(
            status_code=503,
            detail=str(error),
        )


    except AIAnalystGenerationError as error:

        raise HTTPException(
            status_code=502,
            detail=str(error),
        )


    except ValueError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error),
        )


    # =====================================================
    # AUDIT THE AI INTERACTION
    # =====================================================

    references = (
        result[
            "evidence_references"
        ]
    )


    reference_text = (
        ", ".join(
            references
        )
        if references
        else "None"
    )


    safe_question = (
        question
        .replace(
            "\n",
            " ",
        )[
            :250
        ]
    )


    create_ledger_entry(

        session=session,

        case_id=case_id,

        event_type=(
            "AI_ANALYST_QUERY"
        ),

        event_data=(
            f"Question="
            f"{safe_question} | "
            f"Model="
            f"{result['model_name']} | "
            f"EvidenceRefs="
            f"{reference_text}"
        ),
    )


    return AnalystAnswerResponse(

        case_id=case_id,

        question=question,

        answer=(
            result[
                "answer"
            ]
        ),

        evidence_references=(
            result[
                "evidence_references"
            ]
        ),

        recommended_actions=(
            result[
                "recommended_actions"
            ]
        ),

        limitations=(
            result[
                "limitations"
            ]
        ),

        model_name=(
            result[
                "model_name"
            ]
        ),

        grounded=(
            result[
                "grounded"
            ]
        ),
    )