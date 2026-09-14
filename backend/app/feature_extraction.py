from pathlib import Path

from .models import Evidence


EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".com",
    ".scr",
    ".msi",
}


SCRIPT_EXTENSIONS = {
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".jse",
    ".wsf",
    ".py",
    ".sh",
}


ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".bz2",
}


DOCUMENT_EXTENSIONS = {
    ".txt",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".csv",
}


IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".webp",
}


DATABASE_EXTENSIONS = {
    ".db",
    ".sqlite",
    ".sqlite3",
    ".mdb",
}


SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".ps1",
    ".vbs",
    ".bat",
    ".cmd",
    ".js",
    ".jse",
    ".wsf",
}


SUSPICIOUS_KEYWORDS = {
    "password",
    "passwd",
    "credential",
    "dump",
    "payload",
    "malware",
    "shell",
    "backdoor",
    "token",
    "secret",
    "keylogger",
    "wallet",
    "exploit",
    "powershell",
    "ransom",
}


def normalize_extension(
    extension: str,
) -> str:

    extension = (
        extension
        .strip()
        .lower()
    )

    if (
        extension
        and extension != "none"
        and not extension.startswith(".")
    ):
        extension = (
            f".{extension}"
        )

    return extension


def detect_double_extension(
    filename: str,
) -> int:

    suffixes = (
        Path(filename)
        .suffixes
    )

    if len(suffixes) >= 2:
        return 1

    return 0


def detect_hidden_file(
    filename: str,
) -> int:

    if filename.startswith("."):
        return 1

    return 0


def detect_suspicious_keyword(
    filename: str,
) -> int:

    lower_name = (
        filename.lower()
    )

    for keyword in (
        SUSPICIOUS_KEYWORDS
    ):

        if keyword in lower_name:
            return 1

    return 0


def extract_ml_features(
    evidence: Evidence,
) -> dict[str, int | float]:

    extension = normalize_extension(
        evidence.file_extension
    )

    filename = (
        evidence.original_filename
    )

    mime_type = (
        evidence.mime_type
        .lower()
    )


    features = {

        "file_size_bytes":
            evidence.file_size,

        "entropy":
            evidence.entropy,

        "filename_length":
            len(filename),

        "extension_length":
            len(extension),

        "is_executable":
            int(
                extension
                in EXECUTABLE_EXTENSIONS
            ),

        "is_script":
            int(
                extension
                in SCRIPT_EXTENSIONS
            ),

        "is_archive":
            int(
                extension
                in ARCHIVE_EXTENSIONS
            ),

        "is_document":
            int(
                extension
                in DOCUMENT_EXTENSIONS
            ),

        "is_image":
            int(
                extension
                in IMAGE_EXTENSIONS
            ),

        "is_database":
            int(
                extension
                in DATABASE_EXTENSIONS
            ),

        "is_hidden":
            detect_hidden_file(
                filename
            ),

        "has_double_extension":
            detect_double_extension(
                filename
            ),

        "suspicious_extension":
            int(
                extension
                in SUSPICIOUS_EXTENSIONS
            ),

        "suspicious_keyword":
            detect_suspicious_keyword(
                filename
            ),

        "high_entropy":
            int(
                evidence.entropy
                >= 7.2
            ),

        "mime_is_executable":
            int(
                "executable"
                in mime_type
                or
                "x-msdownload"
                in mime_type
            ),

        "mime_is_archive":
            int(
                "zip"
                in mime_type
                or
                "compressed"
                in mime_type
                or
                "archive"
                in mime_type
            ),
    }


    return features