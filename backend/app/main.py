from contextlib import asynccontextmanager

from fastapi import FastAPI

from fastapi.middleware.cors import (
    CORSMiddleware,
)

from .database import (
    create_db_and_tables,
)

from .routers.analyst import (
    router as analyst_router,
)

from .routers.artifact_triage import (
    router as artifact_triage_router,
)

from .routers.attention import (
    router as attention_router,
)

from .routers.blind_spots import (
    router as blind_spots_router,
)

from .routers.cases import (
    router as cases_router,
)

from .routers.correlation import (
    router as correlation_router,
)

from .routers.coverage import (
    router as coverage_router,
)

from .routers.dataset import (
    router as dataset_router,
)

from .routers.evidence import (
    router as evidence_router,
)

from .routers.features import (
    router as features_router,
)

from .routers.graph import (
    router as graph_router,
)

from .routers.ml import (
    router as ml_router,
)

from .routers.report import (
    router as report_router,
)

from .routers.timeline import (
    router as timeline_router,
)


@asynccontextmanager
async def lifespan(
    _: FastAPI,
):

    create_db_and_tables()

    yield


app = FastAPI(

    title="SYNAPSE API",

    description=(
        "Human-Aware AI Cyber-Forensic "
        "Investigation System"
    ),

    version="1.5.0",

    lifespan=lifespan,
)


app.add_middleware(

    CORSMiddleware,

    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],

    allow_credentials=True,

    allow_methods=[
        "*"
    ],

    allow_headers=[
        "*"
    ],
)


app.include_router(
    cases_router
)

app.include_router(
    evidence_router
)

app.include_router(
    features_router
)

app.include_router(
    dataset_router
)

app.include_router(
    ml_router
)

app.include_router(
    graph_router
)

app.include_router(
    artifact_triage_router
)

app.include_router(
    attention_router
)

app.include_router(
    coverage_router
)

app.include_router(
    blind_spots_router
)

app.include_router(
    correlation_router
)

app.include_router(
    timeline_router
)

app.include_router(
    report_router
)

app.include_router(
    analyst_router
)


@app.get("/")
def root():

    return {

        "name":
            "SYNAPSE",

        "system":
            (
                "Human-Aware AI "
                "Cyber-Forensic "
                "Investigation System"
            ),

        "version":
            "1.5.0",

        "status":
            "online",
    }


@app.get(
    "/api/health"
)
def health():

    return {

        "status":
            "healthy",

        "database":
            "connected",

        "evidence_ingestion":
            "active",

        "integrity_engine":
            "active",

        "multi_artifact_triage":
            "active",

        "pe_ml_triage":
            "active",

        "explainable_ml":
            "active",

        "evidence_graph":
            "active",

        "advanced_correlation":
            "active",

        "investigator_attention":
            "active",

        "advanced_coverage_engine":
            "active",

        "blind_spot_detector":
            "active",

        "ai_forensic_analyst":
            "active",

        "investigation_timeline":
            "active",

        "investigation_replay":
            "active",

        "forensic_report_engine":
            "active",

        "phase":
            "15A",
    }