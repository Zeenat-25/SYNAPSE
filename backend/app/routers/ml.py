from pathlib import Path
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)

from sqlmodel import (
    Session,
    select,
)

from ..database import (
    get_session,
)

from ..ledger import (
    create_ledger_entry,
)

from ..ml_engine import (
    get_case_model_status,
    train_case_model,
)

from ..ml_explain import (
    explain_pe_prediction,
)

from ..ml_inference import (
    MLModelUnavailableError,
    PEFeatureExtractionError,
    UnsupportedEvidenceError,
    predict_pe_file,
)

from ..models import (
    Case,
    Evidence,
    MLPrediction,
    MLPredictionPublic,
)


router = APIRouter(
    prefix="/api/ml",
    tags=["Machine Learning"],
)


SessionDep = Annotated[
    Session,
    Depends(get_session),
]


# =========================================================
# TRAIN MODEL
# =========================================================


@router.post(
    "/cases/{case_id}/train",
)
def train_model(
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


    result = train_case_model(
        session=session,
        case_id=case_id,
    )


    if not result.get(
        "success"
    ):

        raise HTTPException(
            status_code=400,
            detail=result,
        )


    create_ledger_entry(
        session=session,

        case_id=case_id,

        event_type=(
            "ML_MODEL_TRAINED"
        ),

        event_data=(
            f"Model="
            f"{result['best_model']} | "
            f"Samples="
            f"{result['total_samples']} | "
            f"F1="
            f"{result['metrics']['f1']}"
        ),
    )


    return result


# =========================================================
# MODEL STATUS
# =========================================================


@router.get(
    "/cases/{case_id}/status",
)
def model_status(
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


    return get_case_model_status(
        case_id
    )


# =========================================================
# RUN PE ML TRIAGE
# =========================================================


@router.post(
    "/cases/{case_id}/evidence/{evidence_id}/predict",
    response_model=MLPredictionPublic,
)
def predict_evidence(
    case_id: int,
    evidence_id: int,
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


    evidence = session.get(
        Evidence,
        evidence_id,
    )


    if (
        evidence is None
        or evidence.case_id
        != case_id
    ):

        raise HTTPException(
            status_code=404,
            detail=(
                "Evidence not found."
            ),
        )


    file_path = Path(
        evidence.stored_path
    )


    try:

        result = predict_pe_file(
            file_path=file_path,
            extension=(
                evidence.file_extension
            ),
        )


    except UnsupportedEvidenceError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )


    except MLModelUnavailableError as error:

        raise HTTPException(
            status_code=503,
            detail=str(error),
        )


    except PEFeatureExtractionError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )


    except FileNotFoundError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error),
        )


    prediction = MLPrediction(

        case_id=case_id,

        evidence_id=evidence_id,

        model_name=(
            result[
                "model_name"
            ]
        ),

        predicted_label=(
            result[
                "predicted_label"
            ]
        ),

        predicted_class=(
            result[
                "predicted_class"
            ]
        ),

        benign_probability=(
            result[
                "benign_probability"
            ]
        ),

        malicious_probability=(
            result[
                "malicious_probability"
            ]
        ),

        risk_level=(
            result[
                "risk_level"
            ]
        ),
    )


    session.add(
        prediction
    )

    session.commit()

    session.refresh(
        prediction
    )


    risk_percent = (
        prediction
        .malicious_probability
        * 100
    )


    create_ledger_entry(
        session=session,

        case_id=case_id,

        event_type=(
            "ML_TRIAGE_COMPLETED"
        ),

        event_data=(
            f"{evidence.evidence_code} | "
            f"Model="
            f"{prediction.model_name} | "
            f"Prediction="
            f"{prediction.predicted_class} | "
            f"Risk="
            f"{risk_percent:.2f}% | "
            f"Level="
            f"{prediction.risk_level}"
        ),
    )


    return prediction


# =========================================================
# GET LATEST PREDICTION
# =========================================================


@router.get(
    "/cases/{case_id}/evidence/{evidence_id}/prediction",
    response_model=MLPredictionPublic,
)
def get_latest_prediction(
    case_id: int,
    evidence_id: int,
    session: SessionDep,
):

    evidence = session.get(
        Evidence,
        evidence_id,
    )


    if (
        evidence is None
        or evidence.case_id
        != case_id
    ):

        raise HTTPException(
            status_code=404,
            detail=(
                "Evidence not found."
            ),
        )


    statement = (
        select(MLPrediction)
        .where(
            MLPrediction.case_id
            == case_id
        )
        .where(
            MLPrediction.evidence_id
            == evidence_id
        )
        .order_by(
            MLPrediction.created_at.desc()
        )
    )


    prediction = (
        session.exec(
            statement
        ).first()
    )


    if prediction is None:

        raise HTTPException(
            status_code=404,
            detail=(
                "No ML prediction exists "
                "for this evidence yet."
            ),
        )


    return prediction


# =========================================================
# GET ALL CASE PREDICTIONS
# =========================================================


@router.get(
    "/cases/{case_id}/predictions",
    response_model=list[
        MLPredictionPublic
    ],
)
def get_case_predictions(
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


    results = (
        session.exec(
            statement
        ).all()
    )


    return list(
        results
    )


# =========================================================
# EXPLAIN ML RESULT
# =========================================================


@router.get(
    "/cases/{case_id}/evidence/{evidence_id}/explain",
)
def explain_prediction(
    case_id: int,
    evidence_id: int,
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


    evidence = session.get(
        Evidence,
        evidence_id,
    )


    if (
        evidence is None
        or evidence.case_id
        != case_id
    ):

        raise HTTPException(
            status_code=404,
            detail=(
                "Evidence not found."
            ),
        )


    extension = (
        evidence.file_extension
        .lower()
    )


    if extension not in {
        ".exe",
        ".dll",
    }:

        raise HTTPException(
            status_code=400,
            detail=(
                "Explainable PE analysis "
                "currently supports .exe "
                "and .dll evidence."
            ),
        )


    file_path = Path(
        evidence.stored_path
    )


    if not file_path.exists():

        raise HTTPException(
            status_code=404,
            detail=(
                "Stored evidence file "
                "does not exist."
            ),
        )


    try:

        explanation = (
            explain_pe_prediction(
                file_path
            )
        )


    except Exception as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )


    create_ledger_entry(
        session=session,

        case_id=case_id,

        event_type=(
            "ML_EXPLANATION_GENERATED"
        ),

        event_data=(
            f"{evidence.evidence_code} | "
            f"Model="
            f"{explanation['model_name']} | "
            f"Prediction="
            f"{explanation['predicted_class']}"
        ),
    )


    return explanation