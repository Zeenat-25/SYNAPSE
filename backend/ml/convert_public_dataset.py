from pathlib import Path
import sys

import pandas as pd


OUTPUT_COLUMNS = {
    "SizeOfCode":
        "size_of_code",

    "Machine":
        "machine",

    "SizeOfOptionalHeader":
        "size_of_optional_header",

    "Characteristics":
        "characteristics",

    "MajorLinkerVersion":
        "major_linker_version",

    "MinorLinkerVersion":
        "minor_linker_version",

    "SizeOfInitializedData":
        "size_of_initialized_data",

    "SizeOfUninitializedData":
        "size_of_uninitialized_data",

    "AddressOfEntryPoint":
        "address_of_entry_point",

    "BaseOfCode":
        "base_of_code",

    "ImageBase":
        "image_base",

    "SectionAlignment":
        "section_alignment",

    "FileAlignment":
        "file_alignment",

    "MajorOperatingSystemVersion":
        "major_os_version",

    "MinorOperatingSystemVersion":
        "minor_os_version",

    "MajorImageVersion":
        "major_image_version",

    "MinorImageVersion":
        "minor_image_version",

    "MajorSubsystemVersion":
        "major_subsystem_version",

    "MinorSubsystemVersion":
        "minor_subsystem_version",

    "SizeOfImage":
        "size_of_image",

    "SizeOfHeaders":
        "size_of_headers",

    "CheckSum":
        "checksum",

    "Subsystem":
        "subsystem",

    "DllCharacteristics":
        "dll_characteristics",

    "SizeOfStackReserve":
        "size_of_stack_reserve",

    "SizeOfStackCommit":
        "size_of_stack_commit",

    "SizeOfHeapReserve":
        "size_of_heap_reserve",

    "SizeOfHeapCommit":
        "size_of_heap_commit",

    "LoaderFlags":
        "loader_flags",

    "NumberOfRvaAndSizes":
        "number_of_rva_and_sizes",

    "SectionsNb":
        "number_of_sections",

    "SectionsMeanEntropy":
        "sections_mean_entropy",

    "SectionsMinEntropy":
        "sections_min_entropy",

    "SectionsMaxEntropy":
        "sections_max_entropy",

    "SectionsMeanRawsize":
        "sections_mean_raw_size",

    "SectionsMinRawsize":
        "sections_min_raw_size",

    "SectionMaxRawsize":
        "sections_max_raw_size",

    "ImportsNbDLL":
        "imports_dll_count",

    "ImportsNb":
        "imports_count",

    "ExportNb":
        "exports_count",
}


LABEL_CANDIDATES = [
    "legitimate",
    "label",
    "Label",
    "class",
    "Class",
]


def detect_separator(
    file_path: Path,
) -> str:

    with file_path.open(
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as file:

        first_line = file.readline()


    if "|" in first_line:
        return "|"


    if ";" in first_line:
        return ";"


    return ","


def detect_label_column(
    columns: list[str],
) -> str | None:

    for candidate in (
        LABEL_CANDIDATES
    ):

        if candidate in columns:
            return candidate

    return None


def normalize_label(
    value,
    label_column: str,
) -> int | None:

    try:

        numeric = int(
            float(value)
        )

    except (
        TypeError,
        ValueError,
    ):

        return None


    if (
        label_column.lower()
        == "legitimate"
    ):

        if numeric == 1:
            return 0

        if numeric == 0:
            return 1


    if numeric in (
        0,
        1,
    ):
        return numeric


    return None


def main():

    if len(sys.argv) != 3:

        print(
            "Usage:"
        )

        print(
            "python ml\\convert_public_dataset.py "
            "<input.csv> "
            "<output.csv>"
        )

        return


    input_path = Path(
        sys.argv[1]
    )


    output_path = Path(
        sys.argv[2]
    )


    if not input_path.exists():

        print(
            f"Input dataset not found: "
            f"{input_path}"
        )

        return


    separator = detect_separator(
        input_path
    )


    print(
        "Reading public dataset..."
    )

    print(
        f"Detected separator: "
        f"{repr(separator)}"
    )


    dataframe = pd.read_csv(
        input_path,
        sep=separator,
        low_memory=False,
    )


    print(
        f"Rows found: "
        f"{len(dataframe)}"
    )


    print(
        f"Columns found: "
        f"{len(dataframe.columns)}"
    )


    label_column = (
        detect_label_column(
            list(
                dataframe.columns
            )
        )
    )


    if label_column is None:

        print(
            "Could not find a label column."
        )

        print(
            "Columns found:"
        )

        print(
            list(
                dataframe.columns
            )
        )

        return


    print(
        f"Label column: "
        f"{label_column}"
    )


    available_mapping = {

        source:
            destination

        for (
            source,
            destination
        ) in OUTPUT_COLUMNS.items()

        if source
        in dataframe.columns
    }


    print(
        f"Compatible features: "
        f"{len(available_mapping)}"
    )


    if len(
        available_mapping
    ) < 15:

        print(
            "Dataset is not compatible enough "
            "with the SYNAPSE PE model."
        )

        print(
            "Matched columns:"
        )

        print(
            list(
                available_mapping.keys()
            )
        )

        return


    converted = pd.DataFrame()


    for (
        source,
        destination,
    ) in available_mapping.items():

        converted[
            destination
        ] = pd.to_numeric(
            dataframe[
                source
            ],
            errors="coerce",
        ).fillna(0)


    converted[
        "label"
    ] = dataframe[
        label_column
    ].apply(

        lambda value:
            normalize_label(
                value,
                label_column,
            )
    )


    converted = converted[
        converted[
            "label"
        ].isin(
            [
                0,
                1,
            ]
        )
    ]


    converted[
        "label"
    ] = (
        converted[
            "label"
        ]
        .astype(int)
    )


    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )


    converted.to_csv(
        output_path,
        index=False,
    )


    benign = int(
        (
            converted[
                "label"
            ]
            == 0
        ).sum()
    )


    malicious = int(
        (
            converted[
                "label"
            ]
            == 1
        ).sum()
    )


    print()
    print(
        "Conversion complete."
    )

    print(
        f"Output rows: "
        f"{len(converted)}"
    )

    print(
        f"Benign: "
        f"{benign}"
    )

    print(
        f"Malicious: "
        f"{malicious}"
    )

    print(
        f"Features used: "
        f"{len(available_mapping)}"
    )

    print(
        f"Saved to: "
        f"{output_path.resolve()}"
    )


if __name__ == "__main__":
    main()