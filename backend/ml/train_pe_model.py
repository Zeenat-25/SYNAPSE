from pathlib import Path
import json
import sys

import joblib
import pandas as pd

from sklearn.ensemble import (
    ExtraTreesClassifier,
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


    return float(
        fp / denominator
    )


def evaluate(
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


    prediction = (
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
                    prediction,
                )
            ),

        "precision":
            float(
                precision_score(
                    y_test,
                    prediction,
                    zero_division=0,
                )
            ),

        "recall":
            float(
                recall_score(
                    y_test,
                    prediction,
                    zero_division=0,
                )
            ),

        "f1":
            float(
                f1_score(
                    y_test,
                    prediction,
                    zero_division=0,
                )
            ),

        "false_positive_rate":
            calculate_fpr(
                y_test,
                prediction,
            ),

        "model":
            model,
    }


def main():

    if len(sys.argv) != 2:

        print(
            "Usage:"
        )

        print(
            "python ml\\train_pe_model.py "
            "ml\\data\\pe_dataset.csv"
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


    dataframe = pd.read_csv(
        dataset_path
    )


    if (
        "label"
        not in dataframe.columns
    ):

        print(
            "Dataset has no label column."
        )

        return


    feature_columns = [
        column
        for column
        in dataframe.columns
        if column != "label"
    ]


    dataframe[
        feature_columns
    ] = (
        dataframe[
            feature_columns
        ]
        .apply(
            pd.to_numeric,
            errors="coerce",
        )
        .fillna(0)
    )


    dataframe = dataframe[
        dataframe[
            "label"
        ].isin(
            [
                0,
                1,
            ]
        )
    ]


    x = dataframe[
        feature_columns
    ]


    y = dataframe[
        "label"
    ].astype(int)


    benign = int(
        (y == 0).sum()
    )


    malicious = int(
        (y == 1).sum()
    )


    print(
        f"Samples: "
        f"{len(dataframe)}"
    )

    print(
        f"Features: "
        f"{len(feature_columns)}"
    )

    print(
        f"Benign: "
        f"{benign}"
    )

    print(
        f"Malicious: "
        f"{malicious}"
    )


    if (
        len(dataframe) < 100
        or benign < 20
        or malicious < 20
    ):

        print(
            "Training refused: "
            "dataset is too small."
        )

        return


    (
        x_train,
        x_test,
        y_train,
        y_test,
    ) = train_test_split(

        x,
        y,

        test_size=0.20,

        random_state=42,

        stratify=y,
    )


    models = {

        "Random Forest":
            RandomForestClassifier(
                n_estimators=250,
                random_state=42,
                class_weight="balanced",
                n_jobs=-1,
            ),

        "Extra Trees":
            ExtraTreesClassifier(
                n_estimators=250,
                random_state=42,
                class_weight="balanced",
                n_jobs=-1,
            ),
    }


    results = []


    for (
        name,
        model,
    ) in models.items():

        result = evaluate(

            name=name,

            model=model,

            x_train=x_train,

            x_test=x_test,

            y_train=y_train,

            y_test=y_test,
        )

        results.append(
            result
        )


        print()
        print(name)

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
        key=lambda item:
            item["f1"],
    )


    final_model = (
        best["model"]
    )


    final_model.fit(
        x,
        y,
    )


    model_path = (
        MODEL_DIR
        / "synapse_pe_model.joblib"
    )


    metadata_path = (
        MODEL_DIR
        / "synapse_pe_model.json"
    )


    package = {

        "model":
            final_model,

        "model_name":
            best["name"],

        "feature_columns":
            feature_columns,

        "metrics": {

            "accuracy":
                best[
                    "accuracy"
                ],

            "precision":
                best[
                    "precision"
                ],

            "recall":
                best[
                    "recall"
                ],

            "f1":
                best[
                    "f1"
                ],

            "false_positive_rate":
                best[
                    "false_positive_rate"
                ],
        },

        "training_samples":
            len(dataframe),

        "benign_samples":
            benign,

        "malicious_samples":
            malicious,
    }


    joblib.dump(
        package,
        model_path,
    )


    metadata = {

        key: value

        for (
            key,
            value,
        ) in package.items()

        if key != "model"
    }


    with metadata_path.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            metadata,
            file,
            indent=2,
        )


    print()
    print(
        "BEST MODEL:"
    )

    print(
        best["name"]
    )

    print(
        f"F1: "
        f"{best['f1']:.4f}"
    )

    print()
    print(
        "Saved:"
    )

    print(
        model_path.resolve()
    )


if __name__ == "__main__":
    main()