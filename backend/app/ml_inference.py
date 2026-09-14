from pathlib import Path

import joblib

from .pe_features import (
    extract_pe_features,
)


BASE_DIR = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)


MODEL_PATH = (
    BASE_DIR
    / "ml"
    / "models"
    / "synapse_pe_model.joblib"
)


SUPPORTED_EXTENSIONS = {
    ".exe",
    ".dll",
}


class MLModelUnavailableError(
    Exception
):
    pass


class UnsupportedEvidenceError(
    Exception
):
    pass


class PEFeatureExtractionError(
    Exception
):
    pass


def get_model_package() -> dict:

    if not MODEL_PATH.exists():

        raise MLModelUnavailableError(
            "SYNAPSE PE model has not "
            "been trained yet."
        )


    return joblib.load(
        MODEL_PATH
    )


def classify_risk(
    malicious_probability: float,
) -> str:

    if (
        malicious_probability
        >= 0.70
    ):
        return "HIGH RISK"


    if (
        malicious_probability
        >= 0.35
    ):
        return "SUSPICIOUS"


    return "LOW RISK"


def predict_pe_file(
    file_path: Path,
    extension: str,
) -> dict:

    extension = (
        extension
        .lower()
        .strip()
    )


    if extension not in (
        SUPPORTED_EXTENSIONS
    ):

        raise UnsupportedEvidenceError(
            "PE ML triage currently supports "
            "Windows .exe and .dll evidence."
        )


    if not file_path.exists():

        raise FileNotFoundError(
            "Stored evidence file "
            "does not exist."
        )


    package = (
        get_model_package()
    )


    model = package.get(
        "model"
    )


    model_name = package.get(
        "model_name",
        "Unknown Model",
    )


    feature_columns = package.get(
        "feature_columns",
        [],
    )


    if model is None:

        raise MLModelUnavailableError(
            "Trained model package "
            "does not contain a model."
        )


    if not feature_columns:

        raise MLModelUnavailableError(
            "Trained model package "
            "does not contain "
            "feature metadata."
        )


    try:

        extracted_features = (
            extract_pe_features(
                file_path
            )
        )

    except Exception as error:

        raise PEFeatureExtractionError(
            "The file could not be parsed "
            "as a valid Windows PE file."
        ) from error


    feature_vector = [

        float(
            extracted_features.get(
                column,
                0,
            )
        )

        for column in feature_columns
    ]


    probability = (
        model.predict_proba(
            [
                feature_vector
            ]
        )[0]
    )


    classes = list(
        model.classes_
    )


    probability_map = {

        int(class_label):
            float(
                probability[index]
            )

        for (
            index,
            class_label,
        ) in enumerate(
            classes
        )
    }


    benign_probability = (
        probability_map.get(
            0,
            0.0,
        )
    )


    malicious_probability = (
        probability_map.get(
            1,
            0.0,
        )
    )


    predicted_label = int(
        model.predict(
            [
                feature_vector
            ]
        )[0]
    )


    predicted_class = (
        "MALICIOUS"
        if predicted_label == 1
        else "BENIGN"
    )


    risk_level = (
        classify_risk(
            malicious_probability
        )
    )


    return {

        "model_name":
            model_name,

        "predicted_label":
            predicted_label,

        "predicted_class":
            predicted_class,

        "benign_probability":
            benign_probability,

        "malicious_probability":
            malicious_probability,

        "risk_level":
            risk_level,

        "feature_count":
            len(
                feature_columns
            ),
    }