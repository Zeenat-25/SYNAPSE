from __future__ import annotations

import math
import re
import struct
import zipfile

from pathlib import Path
from typing import Any

from .ml_inference import (
    MLModelUnavailableError,
    PEFeatureExtractionError,
    UnsupportedEvidenceError,
    predict_pe_file,
)


TEXT_EXTENSIONS = {
    ".txt",
    ".log",
    ".csv",
    ".json",
    ".xml",
    ".ini",
    ".cfg",
    ".conf",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
}


PDF_EXTENSIONS = {
    ".pdf",
}


IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
}


OFFICE_EXTENSIONS = {
    ".docx",
    ".xlsx",
    ".pptx",
}


ARCHIVE_EXTENSIONS = {
    ".zip",
}


PE_EXTENSIONS = {
    ".exe",
    ".dll",
}


URL_PATTERN = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE,
)


IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


BASE64_PATTERN = re.compile(
    r"(?:[A-Za-z0-9+/]{4}){12,}"
    r"(?:[A-Za-z0-9+/]{2}==|"
    r"[A-Za-z0-9+/]{3}=)?"
)


SUSPICIOUS_TEXT_PATTERNS = {
    "powershell encoded command":
        re.compile(
            r"powershell(?:\.exe)?"
            r".{0,80}"
            r"(?:-enc|-encodedcommand)",
            re.IGNORECASE,
        ),

    "download command":
        re.compile(
            r"\b(?:wget|curl|invoke-webrequest|"
            r"iwr|downloadstring)\b",
            re.IGNORECASE,
        ),

    "process execution":
        re.compile(
            r"\b(?:start-process|cmd\.exe|"
            r"wscript\.exe|cscript\.exe)\b",
            re.IGNORECASE,
        ),

    "credential keyword":
        re.compile(
            r"\b(?:password|passwd|credential|"
            r"token|secret|apikey|api_key)\b",
            re.IGNORECASE,
        ),

    "registry persistence":
        re.compile(
            r"\b(?:currentversion\\run|"
            r"reg\s+add|schtasks)\b",
            re.IGNORECASE,
        ),

    "execution bypass":
        re.compile(
            r"\b(?:bypass|executionpolicy)\b",
            re.IGNORECASE,
        ),
}


PDF_INDICATORS = {
    b"/JavaScript":
        (
            "Embedded JavaScript reference",
            25,
        ),

    b"/JS":
        (
            "JavaScript action reference",
            20,
        ),

    b"/OpenAction":
        (
            "Automatic document action",
            20,
        ),

    b"/Launch":
        (
            "External launch action",
            30,
        ),

    b"/EmbeddedFile":
        (
            "Embedded file detected",
            20,
        ),

    b"/RichMedia":
        (
            "Rich media object detected",
            15,
        ),

    b"/AcroForm":
        (
            "Interactive form detected",
            5,
        ),
}


def calculate_entropy(
    data: bytes,
) -> float:

    if not data:
        return 0.0


    counts = [0] * 256


    for byte in data:
        counts[byte] += 1


    length = len(data)

    entropy = 0.0


    for count in counts:

        if count == 0:
            continue


        probability = (
            count / length
        )


        entropy -= (
            probability
            * math.log2(
                probability
            )
        )


    return round(
        entropy,
        4,
    )


def risk_level_from_score(
    score: float,
) -> str:

    if score >= 70:
        return "HIGH RISK"


    if score >= 35:
        return "SUSPICIOUS"


    return "LOW RISK"


def clamp_score(
    score: float,
) -> float:

    return round(
        max(
            0.0,
            min(
                score,
                100.0,
            ),
        ),
        2,
    )


def read_limited(
    path: Path,
    limit: int = 5_000_000,
) -> bytes:

    with path.open(
        "rb"
    ) as file:

        return file.read(
            limit
        )


def valid_ipv4(
    value: str,
) -> bool:

    try:

        parts = [
            int(part)
            for part
            in value.split(".")
        ]


        return (
            len(parts) == 4
            and
            all(
                0 <= part <= 255
                for part
                in parts
            )
        )

    except ValueError:

        return False


def analyze_text(
    path: Path,
) -> dict[str, Any]:

    raw = read_limited(
        path
    )


    text = raw.decode(
        "utf-8",
        errors="ignore",
    )


    findings = []

    indicators = []

    score = 0.0


    urls = list(
        dict.fromkeys(
            URL_PATTERN.findall(
                text
            )
        )
    )


    ips = [
        ip
        for ip
        in dict.fromkeys(
            IP_PATTERN.findall(
                text
            )
        )
        if valid_ipv4(ip)
    ]


    if urls:

        findings.append(
            {
                "severity":
                    "INFO",

                "title":
                    "URLs detected",

                "detail":
                    (
                        f"{len(urls)} URL(s) "
                        "found in the artifact."
                    ),
            }
        )


        indicators.extend(
            {
                "type":
                    "URL",

                "value":
                    url,
            }
            for url
            in urls[:20]
        )


    if ips:

        findings.append(
            {
                "severity":
                    "INFO",

                "title":
                    "IP addresses detected",

                "detail":
                    (
                        f"{len(ips)} IPv4 "
                        "address(es) found."
                    ),
            }
        )


        indicators.extend(
            {
                "type":
                    "IP",

                "value":
                    ip,
            }
            for ip
            in ips[:20]
        )


    for (
        label,
        pattern,
    ) in (
        SUSPICIOUS_TEXT_PATTERNS
        .items()
    ):

        matches = pattern.findall(
            text
        )


        if not matches:
            continue


        score += 12


        findings.append(
            {
                "severity":
                    "MEDIUM",

                "title":
                    label.title(),

                "detail":
                    (
                        "Potentially security-"
                        "relevant command or "
                        "keyword detected."
                    ),
            }
        )


    base64_matches = (
        BASE64_PATTERN.findall(
            text
        )
    )


    if base64_matches:

        score += 10


        findings.append(
            {
                "severity":
                    "MEDIUM",

                "title":
                    "Long encoded-looking content",

                "detail":
                    (
                        "Long Base64-like strings "
                        "were detected."
                    ),
            }
        )


    entropy = calculate_entropy(
        raw
    )


    if entropy >= 7.2:

        score += 15


        findings.append(
            {
                "severity":
                    "MEDIUM",

                "title":
                    "High byte entropy",

                "detail":
                    (
                        f"Artifact entropy is "
                        f"{entropy}."
                    ),
            }
        )


    score = clamp_score(
        score
    )


    return {
        "analyzer":
            "TEXT_STATIC_ANALYZER",

        "analysis_method":
            (
                "Rule-based IOC and suspicious "
                "content analysis"
            ),

        "risk_score":
            score,

        "risk_level":
            risk_level_from_score(
                score
            ),

        "entropy":
            entropy,

        "findings":
            findings,

        "indicators":
            indicators,

        "limitations":
            (
                "This is static heuristic analysis. "
                "URLs and IPs are not automatically "
                "malicious merely because they exist."
            ),
    }


def analyze_pdf(
    path: Path,
) -> dict[str, Any]:

    raw = read_limited(
        path,
        10_000_000,
    )


    findings = []

    score = 0.0


    if not raw.startswith(
        b"%PDF"
    ):

        findings.append(
            {
                "severity":
                    "HIGH",

                "title":
                    "Invalid PDF signature",

                "detail":
                    (
                        "The file extension is PDF "
                        "but the PDF header was "
                        "not detected."
                    ),
            }
        )

        score += 40


    for (
        token,
        (
            title,
            points,
        ),
    ) in PDF_INDICATORS.items():

        count = raw.count(
            token
        )


        if count == 0:
            continue


        score += points


        severity = (
            "HIGH"
            if points >= 25
            else "MEDIUM"
        )


        findings.append(
            {
                "severity":
                    severity,

                "title":
                    title,

                "detail":
                    (
                        f"{count} occurrence(s) "
                        "detected."
                    ),
            }
        )


    entropy = calculate_entropy(
        raw
    )


    if entropy >= 7.5:

        score += 10


        findings.append(
            {
                "severity":
                    "MEDIUM",

                "title":
                    "High PDF entropy",

                "detail":
                    (
                        "The document contains "
                        "high-entropy byte regions."
                    ),
            }
        )


    score = clamp_score(
        score
    )


    return {
        "analyzer":
            "PDF_STATIC_ANALYZER",

        "analysis_method":
            (
                "PDF structural token and "
                "entropy analysis"
            ),

        "risk_score":
            score,

        "risk_level":
            risk_level_from_score(
                score
            ),

        "entropy":
            entropy,

        "findings":
            findings,

        "indicators":
            [],

        "limitations":
            (
                "This analyzer does not execute "
                "PDF JavaScript or embedded content."
            ),
    }


def png_dimensions(
    raw: bytes,
) -> tuple[int, int] | None:

    if (
        len(raw) < 24
        or
        raw[:8]
        != b"\x89PNG\r\n\x1a\n"
    ):
        return None


    width, height = (
        struct.unpack(
            ">II",
            raw[16:24],
        )
    )


    return (
        width,
        height,
    )


def jpeg_dimensions(
    raw: bytes,
) -> tuple[int, int] | None:

    if (
        len(raw) < 4
        or
        raw[:2] != b"\xff\xd8"
    ):
        return None


    index = 2


    while (
        index + 9
        < len(raw)
    ):

        if raw[index] != 0xFF:

            index += 1
            continue


        marker = raw[
            index + 1
        ]


        index += 2


        if marker in {
            0xD8,
            0xD9,
        }:
            continue


        if (
            index + 2
            > len(raw)
        ):
            break


        segment_length = (
            int.from_bytes(
                raw[
                    index:
                    index + 2
                ],
                "big",
            )
        )


        if marker in {
            0xC0,
            0xC1,
            0xC2,
            0xC3,
            0xC5,
            0xC6,
            0xC7,
            0xC9,
            0xCA,
            0xCB,
            0xCD,
            0xCE,
            0xCF,
        }:

            if (
                index + 7
                <= len(raw)
            ):

                height = (
                    int.from_bytes(
                        raw[
                            index + 3:
                            index + 5
                        ],
                        "big",
                    )
                )

                width = (
                    int.from_bytes(
                        raw[
                            index + 5:
                            index + 7
                        ],
                        "big",
                    )
                )


                return (
                    width,
                    height,
                )


        if segment_length < 2:
            break


        index += (
            segment_length
        )


    return None


def analyze_image(
    path: Path,
) -> dict[str, Any]:

    raw = read_limited(
        path,
        10_000_000,
    )


    extension = (
        path.suffix.lower()
    )


    findings = []

    score = 0.0


    dimensions = None


    if extension == ".png":

        dimensions = (
            png_dimensions(
                raw
            )
        )


        if dimensions is None:

            score += 35


            findings.append(
                {
                    "severity":
                        "HIGH",

                    "title":
                        "Invalid PNG structure",

                    "detail":
                        (
                            "PNG signature or "
                            "dimensions could not "
                            "be parsed."
                        ),
                }
            )


    else:

        dimensions = (
            jpeg_dimensions(
                raw
            )
        )


        if dimensions is None:

            score += 35


            findings.append(
                {
                    "severity":
                        "HIGH",

                    "title":
                        "Invalid JPEG structure",

                    "detail":
                        (
                            "JPEG signature or "
                            "dimensions could not "
                            "be parsed."
                        ),
                }
            )


    entropy = calculate_entropy(
        raw
    )


    if entropy >= 7.85:

        score += 15


        findings.append(
            {
                "severity":
                    "MEDIUM",

                "title":
                    "Very high image entropy",

                "detail":
                    (
                        "High entropy can occur in "
                        "normal compressed images, "
                        "but it is retained as a "
                        "forensic signal."
                    ),
            }
        )


    if dimensions:

        width, height = dimensions


        findings.append(
            {
                "severity":
                    "INFO",

                "title":
                    "Image dimensions",

                "detail":
                    (
                        f"{width} × {height} pixels."
                    ),
            }
        )


    score = clamp_score(
        score
    )


    return {
        "analyzer":
            "IMAGE_STATIC_ANALYZER",

        "analysis_method":
            (
                "Image signature, dimensions "
                "and entropy analysis"
            ),

        "risk_score":
            score,

        "risk_level":
            risk_level_from_score(
                score
            ),

        "entropy":
            entropy,

        "image_dimensions":
            (
                {
                    "width":
                        dimensions[0],

                    "height":
                        dimensions[1],
                }
                if dimensions
                else None
            ),

        "findings":
            findings,

        "indicators":
            [],

        "limitations":
            (
                "High entropy alone does not "
                "prove steganography or malicious "
                "content."
            ),
    }


def inspect_zip_members(
    path: Path,
) -> dict[str, Any]:

    findings = []

    indicators = []

    score = 0.0


    with zipfile.ZipFile(
        path,
        "r",
    ) as archive:

        members = (
            archive.namelist()
        )


        for member in members:

            lower = (
                member.lower()
            )


            if (
                lower.endswith(
                    "vbaproject.bin"
                )
            ):

                score += 40


                findings.append(
                    {
                        "severity":
                            "HIGH",

                        "title":
                            "Office VBA macro detected",

                        "detail":
                            member,
                    }
                )


            if (
                "embeddings/"
                in lower
            ):

                score += 20


                findings.append(
                    {
                        "severity":
                            "MEDIUM",

                        "title":
                            "Embedded object detected",

                        "detail":
                            member,
                    }
                )


            if (
                "externallinks/"
                in lower
            ):

                score += 15


                findings.append(
                    {
                        "severity":
                            "MEDIUM",

                        "title":
                            "External document link",

                        "detail":
                            member,
                    }
                )


            member_extension = (
                Path(member)
                .suffix
                .lower()
            )


            if member_extension in {
                ".exe",
                ".dll",
                ".ps1",
                ".bat",
                ".cmd",
                ".vbs",
                ".js",
            }:

                score += 25


                indicators.append(
                    {
                        "type":
                            "EMBEDDED_FILE",

                        "value":
                            member,
                    }
                )


                findings.append(
                    {
                        "severity":
                            "HIGH",

                        "title":
                            "Executable or script "
                            "inside package",

                        "detail":
                            member,
                    }
                )


        return {
            "members":
                members,

            "score":
                score,

            "findings":
                findings,

            "indicators":
                indicators,
        }


def analyze_office(
    path: Path,
) -> dict[str, Any]:

    findings = []

    indicators = []

    score = 0.0


    if not zipfile.is_zipfile(
        path
    ):

        return {
            "analyzer":
                "OFFICE_STATIC_ANALYZER",

            "analysis_method":
                "OOXML package analysis",

            "risk_score":
                45.0,

            "risk_level":
                "SUSPICIOUS",

            "findings":
                [
                    {
                        "severity":
                            "HIGH",

                        "title":
                            "Invalid OOXML package",

                        "detail":
                            (
                                "Office extension "
                                "was detected but the "
                                "file is not a valid "
                                "ZIP-based OOXML "
                                "document."
                            ),
                    }
                ],

            "indicators":
                [],

            "limitations":
                (
                    "Document content is never "
                    "executed."
                ),
        }


    result = (
        inspect_zip_members(
            path
        )
    )


    score += (
        result["score"]
    )


    findings.extend(
        result["findings"]
    )


    indicators.extend(
        result["indicators"]
    )


    score = clamp_score(
        score
    )


    return {
        "analyzer":
            "OFFICE_STATIC_ANALYZER",

        "analysis_method":
            (
                "OOXML internal package and "
                "embedded-content analysis"
            ),

        "risk_score":
            score,

        "risk_level":
            risk_level_from_score(
                score
            ),

        "findings":
            findings,

        "indicators":
            indicators,

        "limitations":
            (
                "Macros and embedded objects "
                "are detected statically and "
                "are never executed."
            ),
    }


def analyze_archive(
    path: Path,
) -> dict[str, Any]:

    if not zipfile.is_zipfile(
        path
    ):

        return {
            "analyzer":
                "ARCHIVE_STATIC_ANALYZER",

            "analysis_method":
                "ZIP package inspection",

            "risk_score":
                40.0,

            "risk_level":
                "SUSPICIOUS",

            "findings":
                [
                    {
                        "severity":
                            "HIGH",

                        "title":
                            "Invalid ZIP structure",

                        "detail":
                            (
                                "ZIP extension was "
                                "detected but the "
                                "archive could not "
                                "be parsed."
                            ),
                    }
                ],

            "indicators":
                [],

            "limitations":
                (
                    "Archive contents are listed "
                    "but never executed."
                ),
        }


    result = (
        inspect_zip_members(
            path
        )
    )


    score = clamp_score(
        result["score"]
    )


    return {
        "analyzer":
            "ARCHIVE_STATIC_ANALYZER",

        "analysis_method":
            "ZIP member inspection",

        "risk_score":
            score,

        "risk_level":
            risk_level_from_score(
                score
            ),

        "findings":
            result["findings"],

        "indicators":
            result["indicators"],

        "limitations":
            (
                "Archive members are inspected "
                "statically. No contained file "
                "is executed."
            ),
    }


def analyze_pe(
    path: Path,
    extension: str,
) -> dict[str, Any]:

    result = predict_pe_file(
        file_path=path,
        extension=extension,
    )


    score = (
        result[
            "malicious_probability"
        ]
        * 100
    )


    findings = [
        {
            "severity":
                (
                    "HIGH"
                    if score >= 70
                    else
                    "MEDIUM"
                    if score >= 35
                    else
                    "INFO"
                ),

            "title":
                (
                    "PE machine-learning "
                    "classification"
                ),

            "detail":
                (
                    f"{result['predicted_class']} "
                    f"with {score:.2f}% "
                    f"malicious probability."
                ),
        }
    ]


    return {
        "analyzer":
            "PE_ML_MODEL",

        "analysis_method":
            (
                "Trained Random Forest "
                "static PE classification"
            ),

        "risk_score":
            round(
                score,
                2,
            ),

        "risk_level":
            result[
                "risk_level"
            ],

        "predicted_class":
            result[
                "predicted_class"
            ],

        "model_name":
            result[
                "model_name"
            ],

        "benign_probability":
            result[
                "benign_probability"
            ],

        "malicious_probability":
            result[
                "malicious_probability"
            ],

        "findings":
            findings,

        "indicators":
            [],

        "limitations":
            (
                "The PE model performs static "
                "classification only. The file "
                "is never executed."
            ),
    }


def triage_artifact(
    path: Path,
    extension: str,
) -> dict[str, Any]:

    extension = (
        extension.lower()
        .strip()
    )


    if not path.exists():

        raise FileNotFoundError(
            "Stored evidence file "
            "does not exist."
        )


    if extension in PE_EXTENSIONS:

        try:

            return analyze_pe(
                path,
                extension,
            )

        except (
            MLModelUnavailableError,
            PEFeatureExtractionError,
            UnsupportedEvidenceError,
        ):
            raise


    if extension in TEXT_EXTENSIONS:

        return analyze_text(
            path
        )


    if extension in PDF_EXTENSIONS:

        return analyze_pdf(
            path
        )


    if extension in IMAGE_EXTENSIONS:

        return analyze_image(
            path
        )


    if extension in OFFICE_EXTENSIONS:

        return analyze_office(
            path
        )


    if extension in ARCHIVE_EXTENSIONS:

        return analyze_archive(
            path
        )


    return {
        "analyzer":
            "GENERIC_METADATA_ANALYZER",

        "analysis_method":
            "Generic static metadata analysis",

        "risk_score":
            0.0,

        "risk_level":
            "UNASSESSED",

        "findings":
            [
                {
                    "severity":
                        "INFO",

                    "title":
                        "No specialist analyzer",

                    "detail":
                        (
                            f"SYNAPSE does not yet "
                            f"have a specialist "
                            f"analyzer for "
                            f"{extension or 'this file type'}."
                        ),
                }
            ],

        "indicators":
            [],

        "limitations":
            (
                "No security risk conclusion "
                "is produced for unsupported "
                "file types."
            ),
    }