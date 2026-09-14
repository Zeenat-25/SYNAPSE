from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)

from sqlmodel import (
    Session,
)

from ..database import (
    get_session,
)

from ..graph_engine import (
    build_case_graph,
)

from ..ledger import (
    create_ledger_entry,
)

from ..models import (
    Case,
)


router = APIRouter(
    prefix="/api/graph",
    tags=["Evidence Graph"],
)


SessionDep = Annotated[
    Session,
    Depends(get_session),
]


@router.get(
    "/cases/{case_id}",
)
def get_case_graph(
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


    graph = build_case_graph(
        session=session,
        case_id=case_id,
    )


    if not graph.get(
        "success"
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                graph.get(
                    "message",
                    "Unable to build graph.",
                )
            ),
        )


    return graph


@router.post(
    "/cases/{case_id}/rebuild",
)
def rebuild_case_graph(
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


    graph = build_case_graph(
        session=session,
        case_id=case_id,
    )


    if not graph.get(
        "success"
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                graph.get(
                    "message",
                    "Unable to build graph.",
                )
            ),
        )


    create_ledger_entry(
        session=session,

        case_id=case_id,

        event_type=(
            "EVIDENCE_GRAPH_REBUILT"
        ),

        event_data=(
            f"Nodes="
            f"{graph['summary']['total_nodes']} | "
            f"Edges="
            f"{graph['summary']['total_edges']} | "
            f"HighRisk="
            f"{graph['summary']['high_risk_nodes']}"
        ),
    )


    return graph