from pathlib import Path

import joblib

from sklearn.ensemble import (
    ExtraTreesClassifier,
    GradientBoostingClassifier,
    RandomForestClassifier,
)

from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from sklearn.model_selection import (
    train_test_split,
)

from sqlmodel import (
    Session,
    select,
)

from .models import (
    EvidenceFeature,
)


BASE_DIR = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)


MODEL_DIR = (
    BASE_DIR
    / "ml"
    / "models"
)


MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


FEATURE_COLUMNS = [
    "file_size_bytes",
    "entropy",
    "filename_length",
    "extension_length",
    "is_executable",
    "is_script",
    "is_archive",
    "is_document",
    "is_image",
    "is_database",
    "is_hidden",
    "has_double_extension",
    "suspicious_extension",
    "suspicious_keyword",
    "high_entropy",
    "mime_is_executable",
    "mime_is_archive",
]


def feature_to_vector(
    feature: EvidenceFeature,
) -> list[float]:

    return [
        float(
            getattr(
                feature,
                column,
            )
        )
        for column in FEATURE_COLUMNS
    ]


def calculate_fpr(
    y_true,
    y_pred,
) -> float:

    matrix = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1],
    )

    tn, fp, fn, tp = (
        matrix.ravel()
    )

    denominator = (
        fp + tn
    )

    if denominator == 0:
        return 0.0

    return (
        fp / denominator
    )


def load_case_dataset(
    session: Session,
    case_id: int,
):

    statement = (
        select(EvidenceFeature)
        .where(
            EvidenceFeature.case_id
            == case_id
        )
        .where(
            EvidenceFeature.label
            != None
        )
        .order_by(
            EvidenceFeature.id.asc()
        )
    )

    rows = list(
        session.exec(
            statement
        ).all()
    )

    x = []
    y = []

    for feature in rows:

        if feature.label is None:
            continue

        x.append(
            feature_to_vector(
                feature
            )
        )

        y.append(
            int(
                feature.label
            )
        )

    return (
        rows,
        x,
        y,
    )


def evaluate_model(
    name: str,
    model,
    x_train,
    x_test,
    y_train,
    y_test,
):

    model.fit(
        x_train,
        y_train,
    )

    predictions = (
        model.predict(
            x_test
        )
    )

    return {

        "name":
            name,

        "accuracy":
            float(
                accuracy_score(
                    y_test,
                    predictions,
                )
            ),

        "precision":
            float(
                precision_score(
                    y_test,
                    predictions,
                    zero_division=0,
                )
            ),

        "recall":
            float(
                recall_score(
                    y_test,
                    predictions,
                    zero_division=0,
                )
            ),

        "f1":
            float(
                f1_score(
                    y_test,
                    predictions,
                    zero_division=0,
                )
            ),

        "false_positive_rate":
            float(
                calculate_fpr(
                    y_test,
                    predictions,
                )
            ),

        "model":
            model,
    }


def train_case_model(
    session: Session,
    case_id: int,
) -> dict:

    (
        rows,
        x,
        y,
    ) = load_case_dataset(
        session=session,
        case_id=case_id,
    )

    total_samples = len(x)

    benign_samples = (
        y.count(0)
    )

    malicious_samples = (
        y.count(1)
    )


    # =====================================================
    # DATASET SAFETY CHECKS
    # =====================================================

    if total_samples < 20:

        return {
            "success": False,

            "message": (
                "Training refused. "
                "At least 20 labeled samples "
                "are required."
            ),

            "total_samples":
                total_samples,

            "benign_samples":
                benign_samples,

            "malicious_samples":
                malicious_samples,
        }


    if (
        benign_samples < 5
        or malicious_samples < 5
    ):

        return {
            "success": False,

            "message": (
                "Training refused. "
                "At least 5 BENIGN and "
                "5 MALICIOUS samples "
                "are required."
            ),

            "total_samples":
                total_samples,

            "benign_samples":
                benign_samples,

            "malicious_samples":
                malicious_samples,
        }


    if len(set(y)) < 2:

        return {
            "success": False,

            "message": (
                "Training refused. "
                "Dataset must contain "
                "both BENIGN and MALICIOUS "
                "classes."
            ),

            "total_samples":
                total_samples,

            "benign_samples":
                benign_samples,

            "malicious_samples":
                malicious_samples,
        }


    # =====================================================
    # TRAIN / TEST SPLIT
    # =====================================================

    x_train, x_test, y_train, y_test = (
        train_test_split(
            x,
            y,
            test_size=0.25,
            random_state=42,
            stratify=y,
        )
    )


    # =====================================================
    # MODELS
    # =====================================================

    models = {

        "Random Forest":
            RandomForestClassifier(
                n_estimators=250,
                random_state=42,
                class_weight="balanced",
            ),

        "Extra Trees":
            ExtraTreesClassifier(
                n_estimators=250,
                random_state=42,
                class_weight="balanced",
            ),

        "Gradient Boosting":
            GradientBoostingClassifier(
                random_state=42,
            ),
    }


    results = []


    for (
        model_name,
        model,
    ) in models.items():

        result = evaluate_model(

            name=model_name,

            model=model,

            x_train=x_train,

            x_test=x_test,

            y_train=y_train,

            y_test=y_test,
        )

        results.append(
            result
        )


    # =====================================================
    # SELECT BEST MODEL BY F1
    # =====================================================

    best_result = max(
        results,
        key=lambda result:
            result["f1"],
    )


    best_model = (
        best_result[
            "model"
        ]
    )


    # =====================================================
    # RETRAIN WINNER ON FULL DATASET
    # =====================================================

    best_model.fit(
        x,
        y,
    )


    # =====================================================
    # SAVE MODEL
    # =====================================================

    model_path = (
        MODEL_DIR
        / f"case_{case_id}_best_model.joblib"
    )


    model_package = {

        "model":
            best_model,

        "model_name":
            best_result[
                "name"
            ],

        "features":
            FEATURE_COLUMNS,

        "metrics": {

            "accuracy":
                best_result[
                    "accuracy"
                ],

            "precision":
                best_result[
                    "precision"
                ],

            "recall":
                best_result[
                    "recall"
                ],

            "f1":
                best_result[
                    "f1"
                ],

            "false_positive_rate":
                best_result[
                    "false_positive_rate"
                ],
        },

        "training_samples":
            total_samples,

        "benign_samples":
            benign_samples,

        "malicious_samples":
            malicious_samples,

        "case_id":
            case_id,
    }


    joblib.dump(
        model_package,
        model_path,
    )


    safe_results = []

    for result in results:

        safe_results.append({

            "name":
                result["name"],

            "accuracy":
                round(
                    result["accuracy"],
                    4,
                ),

            "precision":
                round(
                    result["precision"],
                    4,
                ),

            "recall":
                round(
                    result["recall"],
                    4,
                ),

            "f1":
                round(
                    result["f1"],
                    4,
                ),

            "false_positive_rate":
                round(
                    result[
                        "false_positive_rate"
                    ],
                    4,
                ),
        })


    return {

        "success": True,

        "message":
            "ML training completed successfully.",

        "case_id":
            case_id,

        "total_samples":
            total_samples,

        "benign_samples":
            benign_samples,

        "malicious_samples":
            malicious_samples,

        "best_model":
            best_result[
                "name"
            ],

        "metrics": {
            "accuracy":
                round(
                    best_result[
                        "accuracy"
                    ],
                    4,
                ),

            "precision":
                round(
                    best_result[
                        "precision"
                    ],
                    4,
                ),

            "recall":
                round(
                    best_result[
                        "recall"
                    ],
                    4,
                ),

            "f1":
                round(
                    best_result[
                        "f1"
                    ],
                    4,
                ),

            "false_positive_rate":
                round(
                    best_result[
                        "false_positive_rate"
                    ],
                    4,
                ),
        },

        "model_comparison":
            safe_results,

        "saved_model":
            str(
                model_path.resolve()
            ),
    }


def get_case_model_status(
    case_id: int,
) -> dict:

    model_path = (
        MODEL_DIR
        / f"case_{case_id}_best_model.joblib"
    )


    if not model_path.exists():

        return {
            "trained": False,
            "case_id": case_id,
            "model_name": None,
            "metrics": None,
            "training_samples": 0,
        }


    package = joblib.load(
        model_path
    )


    return {

        "trained": True,

        "case_id":
            case_id,

        "model_name":
            package.get(
                "model_name"
            ),

        "metrics":
            package.get(
                "metrics"
            ),

        "training_samples":
            package.get(
                "training_samples",
                0,
            ),

        "benign_samples":
            package.get(
                "benign_samples",
                0,
            ),

        "malicious_samples":
            package.get(
                "malicious_samples",
                0,
            ),
    }