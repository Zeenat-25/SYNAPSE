import csv
import sys
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


BASE_DIR = (
    Path(__file__)
    .resolve()
    .parent
)


MODEL_DIR = (
    BASE_DIR
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


def load_dataset(
    dataset_path: Path,
):

    x = []
    y = []


    with dataset_path.open(
        "r",
        encoding="utf-8",
    ) as file:

        reader = csv.DictReader(
            file
        )


        for row in reader:

            features = [
                float(row[column])
                for column
                in FEATURE_COLUMNS
            ]

            label = int(
                row["label"]
            )

            x.append(features)
            y.append(label)


    return x, y


def calculate_false_positive_rate(
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


    return fp / denominator


def evaluate_model(
    name,
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


    predictions = model.predict(
        x_test
    )


    result = {

        "name": name,

        "accuracy":
            accuracy_score(
                y_test,
                predictions,
            ),

        "precision":
            precision_score(
                y_test,
                predictions,
                zero_division=0,
            ),

        "recall":
            recall_score(
                y_test,
                predictions,
                zero_division=0,
            ),

        "f1":
            f1_score(
                y_test,
                predictions,
                zero_division=0,
            ),

        "false_positive_rate":
            calculate_false_positive_rate(
                y_test,
                predictions,
            ),

        "model":
            model,
    }


    return result


def main():

    if len(sys.argv) != 2:

        print(
            "Usage:"
        )

        print(
            "python ml/train.py "
            "ml/data/case_2_dataset.csv"
        )

        return


    dataset_path = Path(
        sys.argv[1]
    )


    if not dataset_path.exists():

        print(
            f"Dataset not found: "
            f"{dataset_path}"
        )

        return


    x, y = load_dataset(
        dataset_path
    )


    print(
        f"\nSamples: {len(x)}"
    )


    benign_count = (
        y.count(0)
    )

    malicious_count = (
        y.count(1)
    )


    print(
        f"Benign: {benign_count}"
    )

    print(
        f"Malicious: {malicious_count}"
    )


    if len(x) < 20:

        print(
            "\nTraining stopped."
        )

        print(
            "At least 20 labeled samples "
            "are required for the "
            "development pipeline."
        )

        return


    if (
        benign_count < 5
        or malicious_count < 5
    ):

        print(
            "\nTraining stopped."
        )

        print(
            "Need at least 5 samples "
            "from each class."
        )

        return


    x_train, x_test, y_train, y_test = (
        train_test_split(
            x,
            y,
            test_size=0.25,
            random_state=42,
            stratify=y,
        )
    )


    models = {

        "Random Forest":
            RandomForestClassifier(
                n_estimators=200,
                random_state=42,
                class_weight="balanced",
            ),

        "Extra Trees":
            ExtraTreesClassifier(
                n_estimators=200,
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
        name,
        model,
    ) in models.items():

        result = evaluate_model(
            name,
            model,
            x_train,
            x_test,
            y_train,
            y_test,
        )

        results.append(
            result
        )


    print(
        "\nMODEL COMPARISON"
    )

    print(
        "-" * 72
    )


    for result in results:

        print(
            f"\n{result['name']}"
        )

        print(
            f"Accuracy: "
            f"{result['accuracy']:.4f}"
        )

        print(
            f"Precision: "
            f"{result['precision']:.4f}"
        )

        print(
            f"Recall: "
            f"{result['recall']:.4f}"
        )

        print(
            f"F1: "
            f"{result['f1']:.4f}"
        )

        print(
            "False Positive Rate: "
            f"{result['false_positive_rate']:.4f}"
        )


    best = max(
        results,
        key=lambda result:
            result["f1"],
    )


    output_path = (
        MODEL_DIR
        / "best_model.joblib"
    )


    joblib.dump(
        {
            "model":
                best["model"],

            "features":
                FEATURE_COLUMNS,

            "model_name":
                best["name"],

            "f1":
                best["f1"],

            "precision":
                best["precision"],

            "recall":
                best["recall"],

            "false_positive_rate":
                best[
                    "false_positive_rate"
                ],
        },
        output_path,
    )


    print(
        "\nBEST MODEL"
    )

    print(
        best["name"]
    )

    print(
        f"F1: {best['f1']:.4f}"
    )

    print(
        "\nSaved to:"
    )

    print(
        output_path
    )


if __name__ == "__main__":
    main()