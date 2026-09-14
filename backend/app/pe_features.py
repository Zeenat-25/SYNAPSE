from pathlib import Path

import pefile


PE_FEATURE_COLUMNS = [
    "file_size",
    "machine",
    "number_of_sections",
    "size_of_optional_header",
    "characteristics",
    "major_linker_version",
    "minor_linker_version",
    "size_of_code",
    "size_of_initialized_data",
    "size_of_uninitialized_data",
    "address_of_entry_point",
    "base_of_code",
    "image_base",
    "section_alignment",
    "file_alignment",
    "major_os_version",
    "minor_os_version",
    "major_image_version",
    "minor_image_version",
    "major_subsystem_version",
    "minor_subsystem_version",
    "size_of_image",
    "size_of_headers",
    "checksum",
    "subsystem",
    "dll_characteristics",
    "size_of_stack_reserve",
    "size_of_stack_commit",
    "size_of_heap_reserve",
    "size_of_heap_commit",
    "loader_flags",
    "number_of_rva_and_sizes",
    "sections_mean_entropy",
    "sections_min_entropy",
    "sections_max_entropy",
    "sections_mean_raw_size",
    "sections_min_raw_size",
    "sections_max_raw_size",
    "imports_dll_count",
    "imports_count",
    "exports_count",
]


def safe_value(
    obj,
    name: str,
    default=0,
):
    return getattr(
        obj,
        name,
        default,
    )


def calculate_average(
    values: list[float],
) -> float:

    if not values:
        return 0.0

    return float(
        sum(values)
        / len(values)
    )


def extract_pe_features(
    file_path: Path,
) -> dict[str, float | int]:

    pe = pefile.PE(
        str(file_path),
        fast_load=False,
    )

    optional_header = (
        pe.OPTIONAL_HEADER
    )

    file_header = (
        pe.FILE_HEADER
    )


    section_entropies = []

    section_raw_sizes = []


    for section in pe.sections:

        try:
            entropy = float(
                section.get_entropy()
            )
        except Exception:
            entropy = 0.0

        section_entropies.append(
            entropy
        )

        section_raw_sizes.append(
            int(
                safe_value(
                    section,
                    "SizeOfRawData",
                    0,
                )
            )
        )


    imports_dll_count = 0

    imports_count = 0


    if hasattr(
        pe,
        "DIRECTORY_ENTRY_IMPORT",
    ):

        imports_dll_count = len(
            pe.DIRECTORY_ENTRY_IMPORT
        )

        imports_count = sum(
            len(entry.imports)
            for entry
            in pe.DIRECTORY_ENTRY_IMPORT
        )


    exports_count = 0


    if hasattr(
        pe,
        "DIRECTORY_ENTRY_EXPORT",
    ):

        symbols = (
            pe.DIRECTORY_ENTRY_EXPORT.symbols
        )

        exports_count = len(
            symbols
        )


    return {

        "file_size":
            int(
                file_path.stat().st_size
            ),

        "machine":
            int(
                safe_value(
                    file_header,
                    "Machine",
                )
            ),

        "number_of_sections":
            int(
                safe_value(
                    file_header,
                    "NumberOfSections",
                )
            ),

        "size_of_optional_header":
            int(
                safe_value(
                    file_header,
                    "SizeOfOptionalHeader",
                )
            ),

        "characteristics":
            int(
                safe_value(
                    file_header,
                    "Characteristics",
                )
            ),

        "major_linker_version":
            int(
                safe_value(
                    optional_header,
                    "MajorLinkerVersion",
                )
            ),

        "minor_linker_version":
            int(
                safe_value(
                    optional_header,
                    "MinorLinkerVersion",
                )
            ),

        "size_of_code":
            int(
                safe_value(
                    optional_header,
                    "SizeOfCode",
                )
            ),

        "size_of_initialized_data":
            int(
                safe_value(
                    optional_header,
                    "SizeOfInitializedData",
                )
            ),

        "size_of_uninitialized_data":
            int(
                safe_value(
                    optional_header,
                    "SizeOfUninitializedData",
                )
            ),

        "address_of_entry_point":
            int(
                safe_value(
                    optional_header,
                    "AddressOfEntryPoint",
                )
            ),

        "base_of_code":
            int(
                safe_value(
                    optional_header,
                    "BaseOfCode",
                )
            ),

        "image_base":
            int(
                safe_value(
                    optional_header,
                    "ImageBase",
                )
            ),

        "section_alignment":
            int(
                safe_value(
                    optional_header,
                    "SectionAlignment",
                )
            ),

        "file_alignment":
            int(
                safe_value(
                    optional_header,
                    "FileAlignment",
                )
            ),

        "major_os_version":
            int(
                safe_value(
                    optional_header,
                    "MajorOperatingSystemVersion",
                )
            ),

        "minor_os_version":
            int(
                safe_value(
                    optional_header,
                    "MinorOperatingSystemVersion",
                )
            ),

        "major_image_version":
            int(
                safe_value(
                    optional_header,
                    "MajorImageVersion",
                )
            ),

        "minor_image_version":
            int(
                safe_value(
                    optional_header,
                    "MinorImageVersion",
                )
            ),

        "major_subsystem_version":
            int(
                safe_value(
                    optional_header,
                    "MajorSubsystemVersion",
                )
            ),

        "minor_subsystem_version":
            int(
                safe_value(
                    optional_header,
                    "MinorSubsystemVersion",
                )
            ),

        "size_of_image":
            int(
                safe_value(
                    optional_header,
                    "SizeOfImage",
                )
            ),

        "size_of_headers":
            int(
                safe_value(
                    optional_header,
                    "SizeOfHeaders",
                )
            ),

        "checksum":
            int(
                safe_value(
                    optional_header,
                    "CheckSum",
                )
            ),

        "subsystem":
            int(
                safe_value(
                    optional_header,
                    "Subsystem",
                )
            ),

        "dll_characteristics":
            int(
                safe_value(
                    optional_header,
                    "DllCharacteristics",
                )
            ),

        "size_of_stack_reserve":
            int(
                safe_value(
                    optional_header,
                    "SizeOfStackReserve",
                )
            ),

        "size_of_stack_commit":
            int(
                safe_value(
                    optional_header,
                    "SizeOfStackCommit",
                )
            ),

        "size_of_heap_reserve":
            int(
                safe_value(
                    optional_header,
                    "SizeOfHeapReserve",
                )
            ),

        "size_of_heap_commit":
            int(
                safe_value(
                    optional_header,
                    "SizeOfHeapCommit",
                )
            ),

        "loader_flags":
            int(
                safe_value(
                    optional_header,
                    "LoaderFlags",
                )
            ),

        "number_of_rva_and_sizes":
            int(
                safe_value(
                    optional_header,
                    "NumberOfRvaAndSizes",
                )
            ),

        "sections_mean_entropy":
            calculate_average(
                section_entropies
            ),

        "sections_min_entropy":
            float(
                min(
                    section_entropies
                )
            )
            if section_entropies
            else 0.0,

        "sections_max_entropy":
            float(
                max(
                    section_entropies
                )
            )
            if section_entropies
            else 0.0,

        "sections_mean_raw_size":
            calculate_average(
                section_raw_sizes
            ),

        "sections_min_raw_size":
            int(
                min(
                    section_raw_sizes
                )
            )
            if section_raw_sizes
            else 0,

        "sections_max_raw_size":
            int(
                max(
                    section_raw_sizes
                )
            )
            if section_raw_sizes
            else 0,

        "imports_dll_count":
            int(
                imports_dll_count
            ),

        "imports_count":
            int(
                imports_count
            ),

        "exports_count":
            int(
                exports_count
            ),
    }