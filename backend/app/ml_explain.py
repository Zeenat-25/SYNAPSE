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


FEATURE_LABELS = {
    "file_size":
        "File Size",

    "machine":
        "Machine Architecture",

    "number_of_sections":
        "Number of Sections",

    "size_of_optional_header":
        "Optional Header Size",

    "characteristics":
        "PE Characteristics",

    "major_linker_version":
        "Major Linker Version",

    "minor_linker_version":
        "Minor Linker Version",

    "size_of_code":
        "Size of Code",

    "size_of_initialized_data":
        "Initialized Data Size",

    "size_of_uninitialized_data":
        "Uninitialized Data Size",

    "address_of_entry_point":
        "Entry Point",

    "base_of_code":
        "Base of Code",

    "image_base":
        "Image Base",

    "section_alignment":
        "Section Alignment",

    "file_alignment":
        "File Alignment",

    "major_os_version":
        "Major OS Version",

    "minor_os_version":
        "Minor OS Version",

    "major_image_version":
        "Major Image Version",

    "minor_image_version":
        "Minor Image Version",

    "major_subsystem_version":
        "Major Subsystem Version",

    "minor_subsystem_version":
        "Minor Subsystem Version",

    "size_of_image":
        "Image Size",

    "size_of_headers":
        "Header Size",

    "checksum":
        "Checksum",

    "subsystem":
        "Subsystem",

    "dll_characteristics":
        "DLL Characteristics",

    "size_of_stack_reserve":
        "Stack Reserve",

    "size_of_stack_commit":
        "Stack Commit",

    "size_of_heap_reserve":
        "Heap Reserve",

    "size_of_heap_commit":
        "Heap Commit",

    "loader_flags":
        "Loader Flags",

    "number_of_rva_and_sizes":
        "RVA / Directory Count",

    "sections_mean_entropy":
        "Mean Section Entropy",

    "sections_min_entropy":
        "Minimum Section Entropy",

    "sections_max_entropy":
        "Maximum Section Entropy",

    "sections_mean_raw_size":
        "Mean Section Raw Size",

    "sections_min_raw_size":
        "Minimum Section Raw Size",

    "sections_max_raw_size":
        "Maximum Section Raw Size",

    "imports_dll_count":
        "Imported DLL Count",

    "imports_count":
        "Import Count",

    "exports_count":
        "Export Count",
}


def human_value(
    value: float,
) -> str:

    if abs(value) >= 1_000_000:

        return (
            f"{value / 1_000_000:.2f}M"
        )


    if abs(value) >= 1_000:

        return (
            f"{value / 1_000:.2f}K"
        )


    if isinstance(
        value,
        float,
    ):

        return (
            f"{value:.4f}"
        )


    return str(value)


def interpret_feature(
    feature_name: str,
    value: float,
) -> str:

    if feature_name == (
        "sections_max_entropy"
    ):

        if value >= 7.2:
            return (
                "Very high section entropy. "
                "Compressed or packed content "
                "may be present."
            )

        if value >= 6.5:
            return (
                "Moderately high section "
                "entropy."
            )

        return (
            "Section entropy is within "
            "a lower range."
        )


    if feature_name == (
        "sections_mean_entropy"
    ):

        if value >= 7.0:
            return (
                "Average section entropy "
                "is unusually high."
            )

        return (
            "Average section entropy "
            "is not extremely high."
        )


    if feature_name == (
        "imports_count"
    ):

        if value == 0:
            return (
                "No imported functions "
                "were detected."
            )

        if value < 10:
            return (
                "The executable imports "
                "relatively few functions."
            )

        return (
            "The executable contains "
            "multiple imported functions."
        )


    if feature_name == (
        "imports_dll_count"
    ):

        if value == 0:
            return (
                "No imported DLLs were "
                "detected."
            )

        return (
            f"{int(value)} imported DLLs "
            "were detected."
        )


    if feature_name == (
        "number_of_sections"
    ):

        if value <= 1:
            return (
                "The PE contains very few "
                "sections."
            )

        if value > 10:
            return (
                "The PE contains an unusually "
                "large number of sections."
            )

        return (
            "The PE section count is within "
            "a common range."
        )


    if feature_name == (
        "size_of_code"
    ):

        if value == 0:
            return (
                "No executable code size "
                "was reported."
            )

        return (
            "Executable code size contributes "
            "to the model's structural analysis."
        )


    if feature_name == (
        "address_of_entry_point"
    ):

        return (
            "The PE entry-point location "
            "is used as a structural signal."
        )


    if feature_name == (
        "file_alignment"
    ):

        return (
            "File alignment describes how "
            "PE sections are stored on disk."
        )


    if feature_name == (
        "section_alignment"
    ):

        return (
            "Section alignment describes "
            "how PE sections are arranged "
            "in memory."
        )


    if feature_name == (
        "size_of_image"
    ):

        return (
            "Image size is compared with "
            "patterns learned from the "
            "training dataset."
        )


    if feature_name == (
        "checksum"
    ):

        if value == 0:
            return (
                "The PE checksum field is zero."
            )

        return (
            "A PE checksum value is present."
        )


    if feature_name == (
        "exports_count"
    ):

        if value == 0:
            return (
                "The file does not expose "
                "exported functions."
            )

        return (
            f"{int(value)} exported entries "
            "were detected."
        )


    return (
        "This structural PE feature is "
        "used by the trained model."
    )


def explain_pe_prediction(
    file_path: Path,
) -> dict:

    if not MODEL_PATH.exists():

        raise FileNotFoundError(
            "SYNAPSE PE model "
            "is not available."
        )


    package = joblib.load(
        MODEL_PATH
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

        raise ValueError(
            "The model package does "
            "not contain a trained model."
        )


    if not feature_columns:

        raise ValueError(
            "The model package does "
            "not contain feature metadata."
        )


    extracted = (
        extract_pe_features(
            file_path
        )
    )


    vector = [

        float(
            extracted.get(
                column,
                0,
            )
        )

        for column
        in feature_columns
    ]


    probabilities = (
        model.predict_proba(
            [
                vector
            ]
        )[0]
    )


    classes = list(
        model.classes_
    )


    probability_map = {

        int(class_label):
            float(
                probabilities[index]
            )

        for (
            index,
            class_label,
        ) in enumerate(
            classes
        )
    }


    malicious_probability = (
        probability_map.get(
            1,
            0.0,
        )
    )


    benign_probability = (
        probability_map.get(
            0,
            0.0,
        )
    )


    predicted_label = int(
        model.predict(
            [
                vector
            ]
        )[0]
    )


    predicted_class = (
        "MALICIOUS"
        if predicted_label == 1
        else "BENIGN"
    )


    if hasattr(
        model,
        "feature_importances_",
    ):

        importances = list(
            model.feature_importances_
        )

    else:

        importances = [
            0.0
            for _
            in feature_columns
        ]


    feature_rows = []


    for (
        index,
        feature_name,
    ) in enumerate(
        feature_columns
    ):

        value = float(
            extracted.get(
                feature_name,
                0,
            )
        )


        importance = float(
            importances[index]
        )


        feature_rows.append(
            {
                "feature":
                    feature_name,

                "label":
                    FEATURE_LABELS.get(
                        feature_name,
                        feature_name
                        .replace(
                            "_",
                            " ",
                        )
                        .title()
                    ),

                "value":
                    value,

                "display_value":
                    human_value(
                        value
                    ),

                "importance":
                    round(
                        importance,
                        6,
                    ),

                "importance_percent":
                    round(
                        importance
                        * 100,
                        2,
                    ),

                "interpretation":
                    interpret_feature(
                        feature_name,
                        value,
                    ),
            }
        )


    feature_rows.sort(
        key=lambda item:
            item["importance"],
        reverse=True,
    )


    top_features = (
        feature_rows[:6]
    )


    if malicious_probability >= 0.70:

        summary = (
            "The trained PE model found "
            "a strong similarity to structural "
            "patterns associated with malicious "
            "samples in its training dataset."
        )


    elif malicious_probability >= 0.35:

        summary = (
            "The PE contains a mixture of "
            "signals seen across benign and "
            "malicious training samples. "
            "Manual review is recommended."
        )


    else:

        summary = (
            "The PE structure is more similar "
            "to benign samples in the model's "
            "training dataset."
        )


    return {
        "model_name":
            model_name,

        "predicted_class":
            predicted_class,

        "benign_probability":
            benign_probability,

        "malicious_probability":
            malicious_probability,

        "summary":
            summary,

        "top_features":
            top_features,

        "explanation_type":
            (
                "Global model feature importance "
                "with artifact-specific values"
            ),

        "disclaimer":
            (
                "These feature importances show "
                "which PE attributes matter most "
                "to the trained model overall. "
                "They are not proof that a single "
                "feature caused this prediction."
            ),
    }