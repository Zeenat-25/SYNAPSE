from __future__ import annotations

from io import BytesIO
from html import escape
from typing import Any
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import (
    TA_CENTER,
    TA_LEFT,
)
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    HRFlowable,
    LongTable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


# =========================================================
# PALETTE
# =========================================================


NAVY = colors.HexColor(
    "#09131E"
)

NAVY_2 = colors.HexColor(
    "#101E2C"
)

BLUE = colors.HexColor(
    "#4CA8E8"
)

ICE_BLUE = colors.HexColor(
    "#9DD4FF"
)

GREEN = colors.HexColor(
    "#2DAE83"
)

AMBER = colors.HexColor(
    "#D79131"
)

RED = colors.HexColor(
    "#CC5252"
)

PURPLE = colors.HexColor(
    "#8366C7"
)

TEXT = colors.HexColor(
    "#1C2732"
)

MUTED = colors.HexColor(
    "#657381"
)

LIGHT_BORDER = colors.HexColor(
    "#DDE4EA"
)

LIGHT_PANEL = colors.HexColor(
    "#F5F8FA"
)

LIGHT_BLUE = colors.HexColor(
    "#EDF6FC"
)

WHITE = colors.white


# Exact brand artwork selected for SYNAPSE.
# Place the supplied logo PNG at:
#   F:\\ZEENAT\\SYNAPSE\\backend\\app\\assets\\synapse-logo.png
BRAND_ASSET_PATH = (
    Path(__file__)
    .resolve()
    .parent
    / "assets"
    / "synapse-logo.png"
)


# =========================================================
# BASIC HELPERS
# =========================================================


def safe_text(
    value: Any,
    fallback: str = "-",
) -> str:

    if value is None:
        return fallback


    text = str(
        value
    ).strip()


    return (
        text
        if text
        else fallback
    )


def fmt_number(
    value: Any,
    digits: int = 1,
) -> str:

    if value is None:
        return "-"


    try:

        numeric = float(
            value
        )


        if numeric.is_integer():

            return str(
                int(
                    numeric
                )
            )


        return f"{numeric:.{digits}f}"


    except (
        TypeError,
        ValueError,
    ):

        return safe_text(
            value
        )


def fmt_percent(
    value: Any,
) -> str:

    if value is None:
        return "-"


    return (
        f"{fmt_number(value, 1)}%"
    )


def fmt_bytes(
    value: Any,
) -> str:

    try:

        size = float(
            value
        )

    except (
        TypeError,
        ValueError,
    ):

        return "-"


    units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB",
    ]


    index = 0


    while (
        size >= 1024
        and
        index
        <
        len(units) - 1
    ):

        size /= 1024

        index += 1


    if index == 0:

        return (
            f"{int(size)} "
            f"{units[index]}"
        )


    return (
        f"{size:.2f} "
        f"{units[index]}"
    )


def fmt_datetime(
    value: Any,
) -> str:

    if value is None:
        return "-"


    text = str(
        value
    )


    if "T" in text:

        text = text.replace(
            "T",
            " ",
            1,
        )


    if "+" in text:

        text = text.split(
            "+",
            1,
        )[0]


    if text.endswith(
        "Z"
    ):

        text = text[
            :-1
        ]


    return text


def break_token(
    value: Any,
    chunk: int = 28,
) -> str:

    text = safe_text(
        value
    )


    if text == "-":

        return text


    pieces = [

        text[
            index:
            index + chunk
        ]

        for index
        in range(
            0,
            len(text),
            chunk,
        )
    ]


    return "<br/>".join(
        escape(
            piece
        )
        for piece
        in pieces
    )


def paragraph_text(
    value: Any,
) -> str:

    return escape(
        safe_text(
            value
        )
    ).replace(
        "\n",
        "<br/>",
    )


def humanize_indicator_type(
    value: Any,
) -> str:

    normalized = (
        safe_text(
            value,
            "",
        )
        .strip()
        .upper()
    )

    labels = {
        "AMOUNT_INR": "Transaction Amounts",
        "BANK_ACCOUNT_LAST4": "Bank Accounts Referenced",
        "INVOICE_ID": "Invoices Found",
        "EMAIL": "Email Addresses",
        "EMAIL_ADDRESS": "Email Addresses",
        "IP": "IP Addresses",
        "IP_ADDRESS": "IP Addresses",
        "DOMAIN": "Domains",
        "URL": "URLs",
        "FILE": "Files Referenced",
        "FILENAME": "Files Referenced",
        "USER": "Users Referenced",
        "USERNAME": "Users Referenced",
        "PHONE": "Phone Numbers",
        "PHONE_NUMBER": "Phone Numbers",
        "DATE": "Dates",
        "TIMESTAMP": "Timestamps",
        "SHA256": "SHA-256 Hashes",
        "SHA1": "SHA-1 Hashes",
        "MD5": "MD5 Hashes",
    }

    if normalized in labels:

        return labels[
            normalized
        ]

    if not normalized:

        return "Other Extracted Evidence"

    return " ".join(
        part.capitalize()
        for part in normalized.split(
            "_"
        )
        if part
    )


def format_indian_number(
    value: float,
) -> str:

    negative = value < 0

    absolute = abs(
        value
    )

    rounded = round(
        absolute,
        2,
    )

    whole = int(
        rounded
    )

    decimal = (
        f"{rounded:.2f}"
        .split(
            ".",
            1,
        )[1]
        .rstrip(
            "0"
        )
    )

    digits = str(
        whole
    )

    if len(
        digits
    ) <= 3:

        grouped = digits

    else:

        last_three = digits[
            -3:
        ]

        remaining = digits[
            :-3
        ]

        pairs = []

        while remaining:

            pairs.insert(
                0,
                remaining[
                    -2:
                ],
            )

            remaining = remaining[
                :-2
            ]

        grouped = (
            ",".join(
                pairs
            )
            +
            ","
            +
            last_three
        )

    if decimal:

        grouped += (
            "."
            +
            decimal
        )

    if negative:

        grouped = (
            "-"
            +
            grouped
        )

    return grouped


def format_indicator_value(
    indicator: dict,
) -> str:

    indicator_type = (
        safe_text(
            indicator.get(
                "type"
            ),
            "",
        )
        .strip()
        .upper()
    )

    value = safe_text(
        indicator.get(
            "value"
        )
    )

    if indicator_type == "AMOUNT_INR":

        try:

            numeric = float(
                value.replace(
                    ",",
                    "",
                )
            )

            return (
                "INR "
                +
                format_indian_number(
                    numeric
                )
            )

        except (
            TypeError,
            ValueError,
        ):

            return value

    if indicator_type == "BANK_ACCOUNT_LAST4":

        last_four = value[
            -4:
        ]

        return (
            "**** "
            +
            last_four
        )

    return value


def group_indicators(
    indicators: list,
) -> list[dict[str, Any]]:

    groups: dict[
        str,
        dict[str, Any],
    ] = {}

    order = []

    for indicator in indicators:

        indicator_type = (
            safe_text(
                indicator.get(
                    "type"
                ),
                "UNKNOWN",
            )
            .strip()
            .upper()
        )

        formatted_value = (
            format_indicator_value(
                indicator
            )
        )

        if indicator_type not in groups:

            groups[
                indicator_type
            ] = {
                "type": indicator_type,
                "label": humanize_indicator_type(
                    indicator_type
                ),
                "values": [],
            }

            order.append(
                indicator_type
            )

        values = groups[
            indicator_type
        ][
            "values"
        ]

        if formatted_value not in values:

            values.append(
                formatted_value
            )

    return [
        groups[
            indicator_type
        ]
        for indicator_type
        in order
    ]


def risk_color(
    level: Any,
):

    value = (
        safe_text(
            level,
            "",
        )
        .upper()
    )


    if value == "HIGH RISK":

        return RED


    if value == "SUSPICIOUS":

        return AMBER


    if value == "LOW RISK":

        return GREEN


    return MUTED


def severity_color(
    level: Any,
):

    value = (
        safe_text(
            level,
            "",
        )
        .upper()
    )


    if value == "HIGH":

        return RED


    if value == "MEDIUM":

        return AMBER


    if value == "LOW":

        return GREEN


    return BLUE


# =========================================================
# STYLES
# =========================================================


def build_styles():

    base = (
        getSampleStyleSheet()
    )


    return {

        "cover_brand":
            ParagraphStyle(
                "CoverBrand",
                parent=base[
                    "Normal"
                ],
                fontName="Helvetica-Bold",
                fontSize=25,
                leading=29,
                textColor=WHITE,
                alignment=TA_CENTER,
                spaceAfter=6,
            ),

        "cover_sub":
            ParagraphStyle(
                "CoverSub",
                parent=base[
                    "Normal"
                ],
                fontName="Helvetica",
                fontSize=8,
                leading=11,
                textColor=ICE_BLUE,
                alignment=TA_CENTER,
                spaceAfter=32,
            ),

        "cover_title":
            ParagraphStyle(
                "CoverTitle",
                parent=base[
                    "Normal"
                ],
                fontName="Helvetica-Bold",
                fontSize=20,
                leading=25,
                textColor=WHITE,
                alignment=TA_CENTER,
                spaceAfter=18,
            ),

        "cover_case":
            ParagraphStyle(
                "CoverCase",
                parent=base[
                    "Normal"
                ],
                fontName="Helvetica-Bold",
                fontSize=13,
                leading=17,
                textColor=WHITE,
                alignment=TA_CENTER,
                spaceAfter=5,
            ),

        "cover_detail":
            ParagraphStyle(
                "CoverDetail",
                parent=base[
                    "Normal"
                ],
                fontName="Helvetica",
                fontSize=9,
                leading=14,
                textColor=colors.HexColor(
                    "#C8D6E2"
                ),
                alignment=TA_CENTER,
            ),

        "h1":
            ParagraphStyle(
                "ReportH1",
                parent=base[
                    "Heading1"
                ],
                fontName="Helvetica-Bold",
                fontSize=17,
                leading=21,
                textColor=NAVY,
                spaceBefore=4,
                spaceAfter=10,
            ),

        "h2":
            ParagraphStyle(
                "ReportH2",
                parent=base[
                    "Heading2"
                ],
                fontName="Helvetica-Bold",
                fontSize=12,
                leading=15,
                textColor=NAVY_2,
                spaceBefore=10,
                spaceAfter=7,
            ),

        "artifact":
            ParagraphStyle(
                "ArtifactTitle",
                parent=base[
                    "Heading2"
                ],
                fontName="Helvetica-Bold",
                fontSize=11,
                leading=14,
                textColor=NAVY,
                spaceBefore=12,
                spaceAfter=3,
            ),

        "artifact_code":
            ParagraphStyle(
                "ArtifactCode",
                parent=base[
                    "Normal"
                ],
                fontName="Helvetica-Bold",
                fontSize=7.5,
                leading=10,
                textColor=BLUE,
                spaceAfter=7,
            ),

        "body":
            ParagraphStyle(
                "ReportBody",
                parent=base[
                    "BodyText"
                ],
                fontName="Helvetica",
                fontSize=8.5,
                leading=12.5,
                textColor=TEXT,
                spaceAfter=5,
            ),

        "small":
            ParagraphStyle(
                "ReportSmall",
                parent=base[
                    "BodyText"
                ],
                fontName="Helvetica",
                fontSize=7,
                leading=9.5,
                textColor=MUTED,
            ),

        "table":
            ParagraphStyle(
                "TableText",
                parent=base[
                    "BodyText"
                ],
                fontName="Helvetica",
                fontSize=6.8,
                leading=8.6,
                textColor=TEXT,
            ),

        "table_bold":
            ParagraphStyle(
                "TableBold",
                parent=base[
                    "BodyText"
                ],
                fontName="Helvetica-Bold",
                fontSize=6.8,
                leading=8.6,
                textColor=TEXT,
            ),

        "code":
            ParagraphStyle(
                "CodeText",
                parent=base[
                    "BodyText"
                ],
                fontName="Courier",
                fontSize=6,
                leading=8,
                textColor=TEXT,
            ),

        "note":
            ParagraphStyle(
                "ReportNote",
                parent=base[
                    "BodyText"
                ],
                fontName="Helvetica",
                fontSize=7.5,
                leading=10.5,
                textColor=MUTED,
                backColor=LIGHT_PANEL,
                borderColor=LIGHT_BORDER,
                borderWidth=0.5,
                borderPadding=7,
                spaceBefore=5,
                spaceAfter=7,
            ),
    }


# =========================================================
# FLOWABLE HELPERS
# =========================================================


def p(
    value: Any,
    style,
) -> Paragraph:

    return Paragraph(
        paragraph_text(
            value
        ),
        style,
    )


def code_p(
    value: Any,
    style,
) -> Paragraph:

    return Paragraph(
        break_token(
            value
        ),
        style,
    )


def section_title(
    title: str,
    styles: dict,
):

    return [
        Spacer(
            1,
            3 * mm,
        ),
        Paragraph(
            escape(
                title
            ),
            styles[
                "h1"
            ],
        ),
        HRFlowable(
            width="100%",
            thickness=0.7,
            color=BLUE,
            spaceBefore=0,
            spaceAfter=4 * mm,
        ),
    ]


def subsection_title(
    title: str,
    styles: dict,
):

    return Paragraph(
        escape(
            title
        ),
        styles[
            "h2"
        ],
    )



def white_header_row(
    rows: list,
) -> list:

    if not rows:
        return rows

    header_row = []

    for cell in rows[0]:

        if isinstance(
            cell,
            Paragraph,
        ):

            header_style = ParagraphStyle(
                f"{cell.style.name}WhiteHeader",
                parent=cell.style,
                textColor=WHITE,
            )

            header_row.append(
                Paragraph(
                    cell.text,
                    header_style,
                )
            )

        else:

            header_row.append(
                cell
            )

    return [
        header_row,
        *rows[1:],
    ]


def simple_table(
    rows: list,
    widths: list,
    header: bool = False,
):

    if header:

        rows = white_header_row(
            rows
        )

    table = Table(
        rows,
        colWidths=widths,
        repeatRows=(
            1
            if header
            else 0
        ),
        hAlign="LEFT",
    )


    commands = [
        (
            "VALIGN",
            (
                0,
                0,
            ),
            (
                -1,
                -1,
            ),
            "TOP",
        ),
        (
            "GRID",
            (
                0,
                0,
            ),
            (
                -1,
                -1,
            ),
            0.35,
            LIGHT_BORDER,
        ),
        (
            "LEFTPADDING",
            (
                0,
                0,
            ),
            (
                -1,
                -1,
            ),
            5,
        ),
        (
            "RIGHTPADDING",
            (
                0,
                0,
            ),
            (
                -1,
                -1,
            ),
            5,
        ),
        (
            "TOPPADDING",
            (
                0,
                0,
            ),
            (
                -1,
                -1,
            ),
            5,
        ),
        (
            "BOTTOMPADDING",
            (
                0,
                0,
            ),
            (
                -1,
                -1,
            ),
            5,
        ),
    ]


    if header:

        commands.extend(
            [
                (
                    "BACKGROUND",
                    (
                        0,
                        0,
                    ),
                    (
                        -1,
                        0,
                    ),
                    NAVY,
                ),
                (
                    "TEXTCOLOR",
                    (
                        0,
                        0,
                    ),
                    (
                        -1,
                        0,
                    ),
                    WHITE,
                ),
            ]
        )


    for index in range(
        1 if header else 0,
        len(rows),
    ):

        if index % 2 == 0:

            commands.append(
                (
                    "BACKGROUND",
                    (
                        0,
                        index,
                    ),
                    (
                        -1,
                        index,
                    ),
                    LIGHT_PANEL,
                )
            )


    table.setStyle(
        TableStyle(
            commands
        )
    )


    return table



# =========================================================
# SYNAPSE BRAND
# =========================================================
#
# The PDF logo is drawn as vector artwork directly on the
# ReportLab canvas. No generated image or external font is
# required, so the exported report remains portable.
# =========================================================


def draw_synapse_mark(
    canvas,
    x: float,
    y: float,
    size: float,
    color=BLUE,
) -> None:

    canvas.saveState()

    canvas.setStrokeColor(
        color
    )

    canvas.setLineWidth(
        max(
            1.4,
            size * 0.105,
        )
    )

    canvas.setLineCap(
        1
    )

    canvas.setLineJoin(
        1
    )

    # Stylised triangular "A" mark.
    canvas.line(
        x + size * 0.10,
        y + size * 0.08,
        x + size * 0.50,
        y + size * 0.92,
    )

    canvas.line(
        x + size * 0.50,
        y + size * 0.92,
        x + size * 0.90,
        y + size * 0.08,
    )

    canvas.line(
        x + size * 0.23,
        y + size * 0.08,
        x + size * 0.77,
        y + size * 0.08,
    )

    # Crossbar / inner cut detail.
    canvas.setLineWidth(
        max(
            1.1,
            size * 0.075,
        )
    )

    canvas.line(
        x + size * 0.31,
        y + size * 0.34,
        x + size * 0.69,
        y + size * 0.34,
    )

    # Small accent edge for the split-blue look.
    canvas.setStrokeColor(
        ICE_BLUE
    )

    canvas.setLineWidth(
        max(
            0.7,
            size * 0.035,
        )
    )

    canvas.line(
        x + size * 0.51,
        y + size * 0.86,
        x + size * 0.84,
        y + size * 0.16,
    )

    canvas.restoreState()


def draw_synapse_brand(
    canvas,
    x: float,
    y: float,
    scale: float = 1.0,
    light_text: bool = True,
    show_subtitle: bool = True,
) -> None:

    # Preferred path: use the exact approved SYNAPSE artwork.
    if BRAND_ASSET_PATH.exists():

        logo_width = (
            67
            *
            mm
            *
            scale
        )

        logo_height = (
            logo_width
            *
            724
            /
            2172
        )

        canvas.drawImage(
            ImageReader(
                str(
                    BRAND_ASSET_PATH
                )
            ),
            x,
            y,
            width=logo_width,
            height=logo_height,
            preserveAspectRatio=True,
            mask="auto",
        )

        return


    # Fallback only if the artwork file was not copied yet.
    # This keeps PDF export working instead of crashing.
    mark_size = (
        13.5
        *
        mm
        *
        scale
    )

    draw_synapse_mark(
        canvas=canvas,
        x=x,
        y=y,
        size=mark_size,
        color=BLUE,
    )

    text_x = (
        x
        +
        mark_size
        +
        4.0
        *
        mm
        *
        scale
    )

    primary = (
        WHITE
        if light_text
        else NAVY
    )

    secondary = (
        ICE_BLUE
        if light_text
        else MUTED
    )

    canvas.setFillColor(
        primary
    )

    canvas.setFont(
        "Helvetica-Bold",
        15.5
        *
        scale,
    )

    canvas.drawString(
        text_x,
        y + mark_size * 0.53,
        "S Y N A P S E",
    )

    if show_subtitle:

        canvas.setFillColor(
            secondary
        )

        canvas.setFont(
            "Helvetica",
            6.8
            *
            scale,
        )

        canvas.drawString(
            text_x,
            y + mark_size * 0.24,
            "Human-Aware Forensics",
        )



# =========================================================
# PAGE DRAWING
# =========================================================


def draw_cover(
    canvas,
    doc,
):

    canvas.saveState()


    width, height = A4


    canvas.setFillColor(
        NAVY
    )


    canvas.rect(
        0,
        0,
        width,
        height,
        fill=1,
        stroke=0,
    )


    # Subtle top accent.
    canvas.setFillColor(
        BLUE
    )


    canvas.rect(
        0,
        height - 4 * mm,
        width,
        4 * mm,
        fill=1,
        stroke=0,
    )


    # Selected SYNAPSE identity: triangle mark + wordmark.
    draw_synapse_brand(
        canvas=canvas,
        x=16 * mm,
        y=height - 34 * mm,
        scale=1.00,
        light_text=True,
        show_subtitle=True,
    )


    canvas.setStrokeColor(
        colors.HexColor(
            "#24465F"
        )
    )

    canvas.setLineWidth(
        0.6
    )

    canvas.line(
        16 * mm,
        height - 39 * mm,
        width - 16 * mm,
        height - 39 * mm,
    )


    canvas.setFillColor(
        colors.HexColor(
            "#B7C8D6"
        )
    )

    canvas.setFont(
        "Helvetica-Bold",
        6.8,
    )

    canvas.drawRightString(
        width - 16 * mm,
        height - 25 * mm,
        "DIGITAL FORENSIC INVESTIGATION REPORT",
    )


    canvas.setFillColor(
        colors.HexColor(
            "#7FA7C2"
        )
    )

    canvas.setFont(
        "Helvetica",
        5.8,
    )

    canvas.drawRightString(
        width - 16 * mm,
        height - 30 * mm,
        "CONFIDENTIAL - INVESTIGATION WORK PRODUCT",
    )


    canvas.setFillColor(
        colors.HexColor(
            "#142536"
        )
    )


    canvas.rect(
        0,
        0,
        width,
        11 * mm,
        fill=1,
        stroke=0,
    )


    canvas.setFillColor(
        ICE_BLUE
    )


    canvas.setFont(
        "Helvetica",
        6.5,
    )


    canvas.drawString(
        16 * mm,
        5 * mm,
        "SYNAPSE | Human-Aware Forensics",
    )


    canvas.drawRightString(
        width - 16 * mm,
        5 * mm,
        "CONFIDENTIAL - INVESTIGATOR USE",
    )


    canvas.restoreState()


def body_page_callback(
    report: dict,
):

    case_code = safe_text(
        report.get(
            "case",
            {},
        ).get(
            "case_code"
        )
    )


    def draw_body_page(
        canvas,
        doc,
    ):

        canvas.saveState()


        width, height = A4


        # Professional fixed header.
        canvas.setFillColor(
            NAVY
        )


        canvas.rect(
            0,
            height - 16 * mm,
            width,
            16 * mm,
            fill=1,
            stroke=0,
        )


        draw_synapse_brand(
            canvas=canvas,
            x=12 * mm,
            y=height - 14.2 * mm,
            scale=0.48,
            light_text=True,
            show_subtitle=True,
        )


        canvas.setFillColor(
            colors.HexColor(
                "#C7D7E3"
            )
        )


        canvas.setFont(
            "Helvetica-Bold",
            6.6,
        )


        canvas.drawRightString(
            width - 15 * mm,
            height - 7.3 * mm,
            "DIGITAL FORENSIC INVESTIGATION REPORT",
        )


        canvas.setFillColor(
            ICE_BLUE
        )


        canvas.setFont(
            "Helvetica",
            6.3,
        )


        canvas.drawRightString(
            width - 15 * mm,
            height - 11.6 * mm,
            case_code,
        )


        canvas.setStrokeColor(
            LIGHT_BORDER
        )


        canvas.line(
            15 * mm,
            13 * mm,
            width - 15 * mm,
            13 * mm,
        )


        canvas.setFillColor(
            MUTED
        )


        canvas.setFont(
            "Helvetica",
            6.5,
        )


        canvas.drawString(
            15 * mm,
            8 * mm,
            "SYNAPSE | Human-Aware Forensics",
        )


        canvas.drawRightString(
            width - 15 * mm,
            8 * mm,
            f"Page {doc.page}",
        )


        canvas.restoreState()


    return draw_body_page



# =========================================================
# COVER
# =========================================================


def add_cover(
    story: list,
    report: dict,
    styles: dict,
):

    case = report.get(
        "case",
        {},
    )


    # Branding is painted by draw_cover(). Keep the story
    # focused on the actual report title and case metadata.
    story.extend(
        [
            Spacer(
                1,
                62 * mm,
            ),

            Paragraph(
                (
                    "Digital Forensic "
                    "Investigation Report"
                ),
                styles[
                    "cover_title"
                ],
            ),

            Spacer(
                1,
                8 * mm,
            ),

            Paragraph(
                paragraph_text(
                    case.get(
                        "name"
                    )
                ),
                styles[
                    "cover_case"
                ],
            ),

            Paragraph(
                (
                    "Case Code: "
                    +
                    paragraph_text(
                        case.get(
                            "case_code"
                        )
                    )
                ),
                styles[
                    "cover_detail"
                ],
            ),

            Spacer(
                1,
                18 * mm,
            ),

            Paragraph(
                (
                    "<b>Investigator</b><br/>"
                    +
                    paragraph_text(
                        case.get(
                            "investigator"
                        )
                    )
                ),
                styles[
                    "cover_detail"
                ],
            ),

            Spacer(
                1,
                6 * mm,
            ),

            Paragraph(
                (
                    "<b>Case Status</b><br/>"
                    +
                    paragraph_text(
                        case.get(
                            "status"
                        )
                    )
                ),
                styles[
                    "cover_detail"
                ],
            ),

            Spacer(
                1,
                6 * mm,
            ),

            Paragraph(
                (
                    "<b>Report Generated</b><br/>"
                    +
                    paragraph_text(
                        fmt_datetime(
                            report.get(
                                "generated_at"
                            )
                        )
                    )
                ),
                styles[
                    "cover_detail"
                ],
            ),

            Spacer(
                1,
                28 * mm,
            ),

            Paragraph(
                (
                    "Forensic decision-support information "
                    "derived from evidence and observable "
                    "investigation activity recorded within "
                    "SYNAPSE."
                ),
                styles[
                    "cover_detail"
                ],
            ),

            PageBreak(),
        ]
    )



# =========================================================
# EXECUTIVE SUMMARY
# =========================================================


def add_executive_summary(
    story: list,
    report: dict,
    styles: dict,
):

    story.extend(
        section_title(
            "1. Executive Summary",
            styles,
        )
    )


    case = report.get(
        "case",
        {},
    )


    summary = report.get(
        "executive_summary",
        {},
    )


    story.append(
        p(
            case.get(
                "description"
            )
            or
            "No case description was supplied.",
            styles[
                "body"
            ],
        )
    )


    metric_rows = [

        [
            p(
                "Total Evidence",
                styles[
                    "table_bold"
                ],
            ),
            p(
                safe_text(
                    summary.get(
                        "total_evidence"
                    )
                ),
                styles[
                    "table"
                ],
            ),
            p(
                "Analyzed",
                styles[
                    "table_bold"
                ],
            ),
            p(
                safe_text(
                    summary.get(
                        "analyzed_evidence"
                    )
                ),
                styles[
                    "table"
                ],
            ),
        ],

        [
            p(
                "High Risk",
                styles[
                    "table_bold"
                ],
            ),
            p(
                safe_text(
                    summary.get(
                        "high_risk_evidence"
                    )
                ),
                styles[
                    "table"
                ],
            ),
            p(
                "Suspicious",
                styles[
                    "table_bold"
                ],
            ),
            p(
                safe_text(
                    summary.get(
                        "suspicious_evidence"
                    )
                ),
                styles[
                    "table"
                ],
            ),
        ],

        [
            p(
                "Average Coverage",
                styles[
                    "table_bold"
                ],
            ),
            p(
                fmt_percent(
                    summary.get(
                        "average_coverage"
                    )
                ),
                styles[
                    "table"
                ],
            ),
            p(
                "High Blind Spots",
                styles[
                    "table_bold"
                ],
            ),
            p(
                safe_text(
                    summary.get(
                        "high_blind_spots"
                    )
                ),
                styles[
                    "table"
                ],
            ),
        ],

        [
            p(
                "Correlations",
                styles[
                    "table_bold"
                ],
            ),
            p(
                safe_text(
                    summary.get(
                        "correlation_relationships"
                    )
                ),
                styles[
                    "table"
                ],
            ),
            p(
                "Correlation Clusters",
                styles[
                    "table_bold"
                ],
            ),
            p(
                safe_text(
                    summary.get(
                        "correlation_clusters"
                    )
                ),
                styles[
                    "table"
                ],
            ),
        ],

        [
            p(
                "Timeline Events",
                styles[
                    "table_bold"
                ],
            ),
            p(
                safe_text(
                    summary.get(
                        "timeline_events"
                    )
                ),
                styles[
                    "table"
                ],
            ),
            p(
                "Chain-of-Custody Entries",
                styles[
                    "table_bold"
                ],
            ),
            p(
                safe_text(
                    summary.get(
                        "chain_of_custody_entries"
                    )
                ),
                styles[
                    "table"
                ],
            ),
        ],
    ]


    metric_table = (
        simple_table(
            metric_rows,
            [
                43 * mm,
                42 * mm,
                48 * mm,
                42 * mm,
            ],
        )
    )


    story.append(
        metric_table
    )


    story.append(
        Spacer(
            1,
            5 * mm,
        )
    )


    top_risk = summary.get(
        "top_risk_evidence",
        [],
    )


    if top_risk:

        story.append(
            subsection_title(
                "Highest Forensic Risk",
                styles,
            )
        )


        rows = [
            [
                p(
                    "Evidence",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Filename",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Risk",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Level",
                    styles[
                        "table_bold"
                    ],
                ),
            ]
        ]


        for item in top_risk:

            rows.append(
                [
                    p(
                        item.get(
                            "evidence_code"
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        item.get(
                            "filename"
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        fmt_percent(
                            item.get(
                                "risk_score"
                            )
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        item.get(
                            "risk_level"
                        ),
                        styles[
                            "table"
                        ],
                    ),
                ]
            )


        story.append(
            simple_table(
                rows,
                [
                    35 * mm,
                    80 * mm,
                    25 * mm,
                    35 * mm,
                ],
                header=True,
            )
        )


    story.append(
        PageBreak()
    )


# =========================================================
# EVIDENCE INVENTORY
# =========================================================


def add_evidence_inventory(
    story: list,
    report: dict,
    styles: dict,
):

    story.extend(
        section_title(
            "2. Evidence Inventory",
            styles,
        )
    )


    rows = [
        [
            p(
                "Evidence",
                styles[
                    "table_bold"
                ],
            ),
            p(
                "Filename",
                styles[
                    "table_bold"
                ],
            ),
            p(
                "Type",
                styles[
                    "table_bold"
                ],
            ),
            p(
                "Size",
                styles[
                    "table_bold"
                ],
            ),
            p(
                "Integrity",
                styles[
                    "table_bold"
                ],
            ),
            p(
                "Risk",
                styles[
                    "table_bold"
                ],
            ),
            p(
                "Coverage",
                styles[
                    "table_bold"
                ],
            ),
            p(
                "Blind Spot",
                styles[
                    "table_bold"
                ],
            ),
        ]
    ]


    for item in report.get(
        "evidence",
        [],
    ):

        triage = (
            item.get(
                "triage"
            )
            or
            {}
        )


        coverage = (
            item.get(
                "coverage"
            )
            or
            {}
        )


        blind_spot = (
            item.get(
                "blind_spot"
            )
            or
            {}
        )


        rows.append(
            [
                p(
                    item.get(
                        "evidence_code"
                    ),
                    styles[
                        "table"
                    ],
                ),
                p(
                    item.get(
                        "filename"
                    ),
                    styles[
                        "table"
                    ],
                ),
                p(
                    item.get(
                        "file_extension"
                    ),
                    styles[
                        "table"
                    ],
                ),
                p(
                    fmt_bytes(
                        item.get(
                            "file_size"
                        )
                    ),
                    styles[
                        "table"
                    ],
                ),
                p(
                    item.get(
                        "integrity",
                        {},
                    ).get(
                        "status"
                    ),
                    styles[
                        "table"
                    ],
                ),
                p(
                    (
                        fmt_percent(
                            triage.get(
                                "risk_score"
                            )
                        )
                        if triage
                        else "Not triaged"
                    ),
                    styles[
                        "table"
                    ],
                ),
                p(
                    (
                        fmt_percent(
                            coverage.get(
                                "coverage_score"
                            )
                        )
                        if coverage
                        else "-"
                    ),
                    styles[
                        "table"
                    ],
                ),
                p(
                    (
                        fmt_percent(
                            blind_spot.get(
                                "blind_spot_score"
                            )
                        )
                        if blind_spot
                        else "-"
                    ),
                    styles[
                        "table"
                    ],
                ),
            ]
        )


    rows = white_header_row(
        rows
    )


    table = LongTable(
        rows,
        colWidths=[
            25 * mm,
            48 * mm,
            15 * mm,
            18 * mm,
            19 * mm,
            18 * mm,
            19 * mm,
            18 * mm,
        ],
        repeatRows=1,
        hAlign="LEFT",
    )


    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (
                        0,
                        0,
                    ),
                    (
                        -1,
                        0,
                    ),
                    NAVY,
                ),
                (
                    "TEXTCOLOR",
                    (
                        0,
                        0,
                    ),
                    (
                        -1,
                        0,
                    ),
                    WHITE,
                ),
                (
                    "GRID",
                    (
                        0,
                        0,
                    ),
                    (
                        -1,
                        -1,
                    ),
                    0.35,
                    LIGHT_BORDER,
                ),
                (
                    "VALIGN",
                    (
                        0,
                        0,
                    ),
                    (
                        -1,
                        -1,
                    ),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (
                        0,
                        0,
                    ),
                    (
                        -1,
                        -1,
                    ),
                    4,
                ),
                (
                    "RIGHTPADDING",
                    (
                        0,
                        0,
                    ),
                    (
                        -1,
                        -1,
                    ),
                    4,
                ),
                (
                    "TOPPADDING",
                    (
                        0,
                        0,
                    ),
                    (
                        -1,
                        -1,
                    ),
                    4,
                ),
                (
                    "BOTTOMPADDING",
                    (
                        0,
                        0,
                    ),
                    (
                        -1,
                        -1,
                    ),
                    4,
                ),
            ]
        )
    )


    story.append(
        table
    )


    story.append(
        PageBreak()
    )


# =========================================================
# DETAILED EVIDENCE
# =========================================================


def add_detailed_evidence(
    story: list,
    report: dict,
    styles: dict,
):

    story.extend(
        section_title(
            "3. Detailed Evidence Analysis",
            styles,
        )
    )


    evidence_items = report.get(
        "evidence",
        [],
    )


    for index, item in enumerate(
        evidence_items,
        start=1,
    ):

        story.append(
            Paragraph(
                (
                    f"3.{index} "
                    +
                    paragraph_text(
                        item.get(
                            "filename"
                        )
                    )
                ),
                styles[
                    "artifact"
                ],
            )
        )


        story.append(
            Paragraph(
                paragraph_text(
                    item.get(
                        "evidence_code"
                    )
                ),
                styles[
                    "artifact_code"
                ],
            )
        )


        triage = (
            item.get(
                "triage"
            )
            or
            {}
        )


        coverage = (
            item.get(
                "coverage"
            )
            or
            {}
        )


        blind_spot = (
            item.get(
                "blind_spot"
            )
            or
            {}
        )


        metadata_rows = [
            [
                p(
                    "File Type",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    item.get(
                        "file_extension"
                    ),
                    styles[
                        "table"
                    ],
                ),
                p(
                    "MIME Type",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    item.get(
                        "mime_type"
                    ),
                    styles[
                        "table"
                    ],
                ),
            ],
            [
                p(
                    "File Size",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    fmt_bytes(
                        item.get(
                            "file_size"
                        )
                    ),
                    styles[
                        "table"
                    ],
                ),
                p(
                    "Entropy",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    fmt_number(
                        item.get(
                            "entropy"
                        ),
                        4,
                    ),
                    styles[
                        "table"
                    ],
                ),
            ],
            [
                p(
                    "Integrity",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    item.get(
                        "integrity",
                        {},
                    ).get(
                        "status"
                    ),
                    styles[
                        "table"
                    ],
                ),
                p(
                    "Uploaded",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    fmt_datetime(
                        item.get(
                            "uploaded_at"
                        )
                    ),
                    styles[
                        "table"
                    ],
                ),
            ],
        ]


        story.append(
            simple_table(
                metadata_rows,
                [
                    31 * mm,
                    56 * mm,
                    31 * mm,
                    57 * mm,
                ],
            )
        )


        story.append(
            Spacer(
                1,
                3 * mm,
            )
        )


        story.append(
            subsection_title(
                "Integrity Hashes",
                styles,
            )
        )


        hash_rows = [
            [
                p(
                    "SHA-256",
                    styles[
                        "table_bold"
                    ],
                ),
                code_p(
                    item.get(
                        "integrity",
                        {},
                    ).get(
                        "sha256"
                    ),
                    styles[
                        "code"
                    ],
                ),
            ],
            [
                p(
                    "SHA-1",
                    styles[
                        "table_bold"
                    ],
                ),
                code_p(
                    item.get(
                        "integrity",
                        {},
                    ).get(
                        "sha1"
                    ),
                    styles[
                        "code"
                    ],
                ),
            ],
            [
                p(
                    "MD5",
                    styles[
                        "table_bold"
                    ],
                ),
                code_p(
                    item.get(
                        "integrity",
                        {},
                    ).get(
                        "md5"
                    ),
                    styles[
                        "code"
                    ],
                ),
            ],
        ]


        story.append(
            simple_table(
                hash_rows,
                [
                    28 * mm,
                    147 * mm,
                ],
            )
        )


        story.append(
            Spacer(
                1,
                3 * mm,
            )
        )


        if triage:

            story.append(
                subsection_title(
                    "Forensic Triage",
                    styles,
                )
            )


            triage_rows = [
                [
                    p(
                        "Analyzer",
                        styles[
                            "table_bold"
                        ],
                    ),
                    p(
                        triage.get(
                            "analyzer"
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        "Risk",
                        styles[
                            "table_bold"
                        ],
                    ),
                    Paragraph(
                        (
                            "<b>"
                            +
                            escape(
                                fmt_percent(
                                    triage.get(
                                        "risk_score"
                                    )
                                )
                            )
                            +
                            "</b><br/>"
                            +
                            escape(
                                safe_text(
                                    triage.get(
                                        "risk_level"
                                    )
                                )
                            )
                        ),
                        ParagraphStyle(
                            "RiskCell",
                            parent=styles[
                                "table"
                            ],
                            textColor=risk_color(
                                triage.get(
                                    "risk_level"
                                )
                            ),
                        ),
                    ),
                ],
                [
                    p(
                        "Method",
                        styles[
                            "table_bold"
                        ],
                    ),
                    p(
                        triage.get(
                            "analysis_method"
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        "Model/Class",
                        styles[
                            "table_bold"
                        ],
                    ),
                    p(
                        (
                            safe_text(
                                triage.get(
                                    "model_name"
                                )
                            )
                            +
                            " / "
                            +
                            safe_text(
                                triage.get(
                                    "predicted_class"
                                )
                            )
                        ),
                        styles[
                            "table"
                        ],
                    ),
                ],
            ]


            story.append(
                simple_table(
                    triage_rows,
                    [
                        28 * mm,
                        64 * mm,
                        27 * mm,
                        56 * mm,
                    ],
                )
            )


            findings = triage.get(
                "findings",
                [],
            )


            if findings:

                story.append(
                    subsection_title(
                        "Findings",
                        styles,
                    )
                )


                rows = [
                    [
                        p(
                            "Severity",
                            styles[
                                "table_bold"
                            ],
                        ),
                        p(
                            "Finding",
                            styles[
                                "table_bold"
                            ],
                        ),
                        p(
                            "Detail",
                            styles[
                                "table_bold"
                            ],
                        ),
                    ]
                ]


                for finding in findings:

                    rows.append(
                        [
                            Paragraph(
                                escape(
                                    safe_text(
                                        finding.get(
                                            "severity"
                                        )
                                    )
                                ),
                                ParagraphStyle(
                                    "FindingSeverity",
                                    parent=styles[
                                        "table_bold"
                                    ],
                                    textColor=severity_color(
                                        finding.get(
                                            "severity"
                                        )
                                    ),
                                ),
                            ),
                            p(
                                finding.get(
                                    "title"
                                ),
                                styles[
                                    "table"
                                ],
                            ),
                            p(
                                finding.get(
                                    "detail"
                                ),
                                styles[
                                    "table"
                                ],
                            ),
                        ]
                    )


                story.append(
                    simple_table(
                        rows,
                        [
                            25 * mm,
                            48 * mm,
                            102 * mm,
                        ],
                        header=True,
                    )
                )


            indicators = triage.get(
                "indicators",
                [],
            )


            if indicators:

                story.append(
                    subsection_title(
                        "Extracted Evidence",
                        styles,
                    )
                )


                story.append(
                    p(
                        (
                            "Machine-extracted indicators are grouped "
                            "below into investigator-friendly evidence "
                            "categories. The original raw values are "
                            "retained immediately afterward for "
                            "forensic traceability."
                        ),
                        styles[
                            "small"
                        ],
                    )
                )


                friendly_rows = [
                    [
                        p(
                            "Evidence Category",
                            styles[
                                "table_bold"
                            ],
                        ),
                        p(
                            "Extracted Values",
                            styles[
                                "table_bold"
                            ],
                        ),
                        p(
                            "Count",
                            styles[
                                "table_bold"
                            ],
                        ),
                    ]
                ]


                for group in group_indicators(
                    indicators
                ):

                    friendly_rows.append(
                        [
                            p(
                                group.get(
                                    "label"
                                ),
                                styles[
                                    "table_bold"
                                ],
                            ),
                            p(
                                "\n".join(
                                    group.get(
                                        "values",
                                        [],
                                    )
                                ),
                                styles[
                                    "table"
                                ],
                            ),
                            p(
                                len(
                                    group.get(
                                        "values",
                                        [],
                                    )
                                ),
                                styles[
                                    "table"
                                ],
                            ),
                        ]
                    )


                story.append(
                    simple_table(
                        friendly_rows,
                        [
                            48 * mm,
                            112 * mm,
                            15 * mm,
                        ],
                        header=True,
                    )
                )


                story.append(
                    Spacer(
                        1,
                        3 * mm,
                    )
                )


                story.append(
                    subsection_title(
                        "Raw Forensic Indicators",
                        styles,
                    )
                )


                raw_rows = [
                    [
                        p(
                            "Type",
                            styles[
                                "table_bold"
                            ],
                        ),
                        p(
                            "Raw Value",
                            styles[
                                "table_bold"
                            ],
                        ),
                    ]
                ]


                for indicator in indicators:

                    raw_rows.append(
                        [
                            p(
                                indicator.get(
                                    "type"
                                ),
                                styles[
                                    "table"
                                ],
                            ),
                            code_p(
                                indicator.get(
                                    "value"
                                ),
                                styles[
                                    "code"
                                ],
                            ),
                        ]
                    )


                story.append(
                    simple_table(
                        raw_rows,
                        [
                            38 * mm,
                            137 * mm,
                        ],
                        header=True,
                    )
                )


            if triage.get(
                "limitations"
            ):

                story.append(
                    Paragraph(
                        (
                            "<b>Analyzer limitation:</b><br/>"
                            +
                            paragraph_text(
                                triage.get(
                                    "limitations"
                                )
                            )
                        ),
                        styles[
                            "note"
                        ],
                    )
                )


        else:

            story.append(
                Paragraph(
                    (
                        "<b>Forensic triage:</b> "
                        "This artifact has not yet "
                        "completed forensic triage."
                    ),
                    styles[
                        "note"
                    ],
                )
            )


        story.append(
            subsection_title(
                "Human-Aware Review",
                styles,
            )
        )


        review_rows = [
            [
                p(
                    "Coverage",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    (
                        fmt_percent(
                            coverage.get(
                                "coverage_score"
                            )
                        )
                        if coverage
                        else "-"
                    ),
                    styles[
                        "table"
                    ],
                ),
                p(
                    "Coverage Level",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    (
                        coverage.get(
                            "coverage_level"
                        )
                        if coverage
                        else "-"
                    ),
                    styles[
                        "table"
                    ],
                ),
            ],
            [
                p(
                    "Blind Spot",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    (
                        fmt_percent(
                            blind_spot.get(
                                "blind_spot_score"
                            )
                        )
                        if blind_spot
                        else "-"
                    ),
                    styles[
                        "table"
                    ],
                ),
                p(
                    "Severity",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    (
                        blind_spot.get(
                            "severity"
                        )
                        if blind_spot
                        else "-"
                    ),
                    styles[
                        "table"
                    ],
                ),
            ],
        ]


        story.append(
            simple_table(
                review_rows,
                [
                    31 * mm,
                    56 * mm,
                    31 * mm,
                    57 * mm,
                ],
            )
        )


        relationships = item.get(
            "relationships",
            [],
        )


        if relationships:

            story.append(
                subsection_title(
                    "Cross-Evidence Relationships",
                    styles,
                )
            )


            rows = [
                [
                    p(
                        "Related Evidence",
                        styles[
                            "table_bold"
                        ],
                    ),
                    p(
                        "Relationship",
                        styles[
                            "table_bold"
                        ],
                    ),
                    p(
                        "Strength",
                        styles[
                            "table_bold"
                        ],
                    ),
                    p(
                        "Reason",
                        styles[
                            "table_bold"
                        ],
                    ),
                ]
            ]


            for relation in relationships[
                :10
            ]:

                rows.append(
                    [
                        p(
                            (
                                safe_text(
                                    relation.get(
                                        "related_evidence_code"
                                    )
                                )
                                +
                                "<br/>"
                                +
                                paragraph_text(
                                    relation.get(
                                        "related_filename"
                                    )
                                )
                            ),
                            styles[
                                "table"
                            ],
                        ),
                        p(
                            relation.get(
                                "relation_type"
                            ),
                            styles[
                                "table"
                            ],
                        ),
                        p(
                            fmt_percent(
                                relation.get(
                                    "strength"
                                )
                            ),
                            styles[
                                "table"
                            ],
                        ),
                        p(
                            relation.get(
                                "reason"
                            ),
                            styles[
                                "table"
                            ],
                        ),
                    ]
                )


            story.append(
                simple_table(
                    rows,
                    [
                        46 * mm,
                        42 * mm,
                        22 * mm,
                        65 * mm,
                    ],
                    header=True,
                )
            )


        story.append(
            Spacer(
                1,
                6 * mm,
            )
        )


        story.append(
            HRFlowable(
                width="100%",
                thickness=0.4,
                color=LIGHT_BORDER,
                spaceBefore=2,
                spaceAfter=3,
            )
        )


    story.append(
        PageBreak()
    )


# =========================================================
# CORRELATIONS
# =========================================================


def add_correlations(
    story: list,
    report: dict,
    styles: dict,
):

    story.extend(
        section_title(
            "4. Evidence Correlation",
            styles,
        )
    )


    section = report.get(
        "correlations",
        {},
    )


    summary = section.get(
        "summary",
        {},
    )


    story.append(
        p(
            (
                "Deterministic relationships are generated "
                "from observable evidence properties and "
                "extracted indicators."
            ),
            styles[
                "body"
            ],
        )
    )


    summary_rows = [
        [
            p(
                "Relationships",
                styles[
                    "table_bold"
                ],
            ),
            p(
                safe_text(
                    summary.get(
                        "correlation_links"
                    )
                ),
                styles[
                    "table"
                ],
            ),
            p(
                "Strong",
                styles[
                    "table_bold"
                ],
            ),
            p(
                safe_text(
                    summary.get(
                        "strong_correlations"
                    )
                ),
                styles[
                    "table"
                ],
            ),
        ],
        [
            p(
                "Correlated Evidence",
                styles[
                    "table_bold"
                ],
            ),
            p(
                safe_text(
                    summary.get(
                        "correlated_evidence"
                    )
                ),
                styles[
                    "table"
                ],
            ),
            p(
                "Clusters",
                styles[
                    "table_bold"
                ],
            ),
            p(
                safe_text(
                    summary.get(
                        "clusters"
                    )
                ),
                styles[
                    "table"
                ],
            ),
        ],
    ]


    story.append(
        simple_table(
            summary_rows,
            [
                44 * mm,
                42 * mm,
                44 * mm,
                45 * mm,
            ],
        )
    )


    relationships = section.get(
        "relationships",
        [],
    )


    if relationships:

        story.append(
            subsection_title(
                "Deterministic Relationships",
                styles,
            )
        )


        rows = [
            [
                p(
                    "Source",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Relationship",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Target",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Strength",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Shared Indicator / Reason",
                    styles[
                        "table_bold"
                    ],
                ),
            ]
        ]


        for relation in relationships:

            indicator = safe_text(
                relation.get(
                    "indicator_value"
                ),
                "",
            )


            reason = safe_text(
                relation.get(
                    "reason"
                )
            )


            detail = (
                (
                    indicator
                    +
                    "\n"
                    +
                    reason
                )
                if indicator
                else reason
            )


            rows.append(
                [
                    p(
                        (
                            safe_text(
                                relation.get(
                                    "source_evidence_code"
                                )
                            )
                            +
                            "<br/>"
                            +
                            paragraph_text(
                                relation.get(
                                    "source_filename"
                                )
                            )
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        relation.get(
                            "relation_type"
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        (
                            safe_text(
                                relation.get(
                                    "target_evidence_code"
                                )
                            )
                            +
                            "<br/>"
                            +
                            paragraph_text(
                                relation.get(
                                    "target_filename"
                                )
                            )
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        fmt_percent(
                            relation.get(
                                "strength"
                            )
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        detail,
                        styles[
                            "table"
                        ],
                    ),
                ]
            )


        rows = white_header_row(
            rows
        )


        table = LongTable(
            rows,
            colWidths=[
                35 * mm,
                35 * mm,
                35 * mm,
                20 * mm,
                50 * mm,
            ],
            repeatRows=1,
            hAlign="LEFT",
        )


        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            0,
                        ),
                        NAVY,
                    ),
                    (
                        "TEXTCOLOR",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            0,
                        ),
                        WHITE,
                    ),
                    (
                        "GRID",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        0.35,
                        LIGHT_BORDER,
                    ),
                    (
                        "VALIGN",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        4,
                    ),
                    (
                        "RIGHTPADDING",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        4,
                    ),
                    (
                        "TOPPADDING",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        4,
                    ),
                    (
                        "BOTTOMPADDING",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        4,
                    ),
                ]
            )
        )


        story.append(
            table
        )


    clusters = section.get(
        "clusters",
        [],
    )


    if clusters:

        story.append(
            subsection_title(
                "Correlation Clusters",
                styles,
            )
        )


        for cluster in clusters:

            member_codes = ", ".join(
                safe_text(
                    member.get(
                        "evidence_code"
                    )
                )

                for member
                in cluster.get(
                    "members",
                    [],
                )
            )


            story.append(
                Paragraph(
                    (
                        "<b>"
                        +
                        paragraph_text(
                            cluster.get(
                                "cluster_id"
                            )
                        )
                        +
                        "</b><br/>"
                        +
                        "Members: "
                        +
                        escape(
                            member_codes
                        )
                        +
                        "<br/>"
                        +
                        "Relationships: "
                        +
                        escape(
                            safe_text(
                                cluster.get(
                                    "relationship_count"
                                )
                            )
                        )
                        +
                        " | Average strength: "
                        +
                        escape(
                            fmt_percent(
                                cluster.get(
                                    "average_strength"
                                )
                            )
                        )
                    ),
                    styles[
                        "note"
                    ],
                )
            )


    if section.get(
        "disclaimer"
    ):

        story.append(
            Paragraph(
                (
                    "<b>Correlation limitation:</b><br/>"
                    +
                    paragraph_text(
                        section.get(
                            "disclaimer"
                        )
                    )
                ),
                styles[
                    "note"
                ],
            )
        )


    story.append(
        PageBreak()
    )


# =========================================================
# COVERAGE + BLIND SPOTS
# =========================================================


def add_human_aware_review(
    story: list,
    report: dict,
    styles: dict,
):

    story.extend(
        section_title(
            "5. Human-Aware Investigation Coverage",
            styles,
        )
    )


    coverage = report.get(
        "coverage",
        {},
    )


    blind_spots = report.get(
        "blind_spots",
        {},
    )


    coverage_summary = coverage.get(
        "summary",
        {},
    )


    blind_summary = blind_spots.get(
        "summary",
        {},
    )


    summary_rows = [
        [
            p(
                "Average Coverage",
                styles[
                    "table_bold"
                ],
            ),
            p(
                fmt_percent(
                    coverage_summary.get(
                        "average_coverage"
                    )
                ),
                styles[
                    "table"
                ],
            ),
            p(
                "Reviewed Evidence",
                styles[
                    "table_bold"
                ],
            ),
            p(
                safe_text(
                    coverage_summary.get(
                        "reviewed_evidence"
                    )
                ),
                styles[
                    "table"
                ],
            ),
        ],
        [
            p(
                "Thoroughly Covered",
                styles[
                    "table_bold"
                ],
            ),
            p(
                safe_text(
                    coverage_summary.get(
                        "thoroughly_covered"
                    )
                ),
                styles[
                    "table"
                ],
            ),
            p(
                "High Blind Spots",
                styles[
                    "table_bold"
                ],
            ),
            p(
                safe_text(
                    blind_summary.get(
                        "high_blind_spots"
                    )
                ),
                styles[
                    "table"
                ],
            ),
        ],
    ]


    story.append(
        simple_table(
            summary_rows,
            [
                44 * mm,
                42 * mm,
                44 * mm,
                45 * mm,
            ],
        )
    )


    items = blind_spots.get(
        "items",
        [],
    )


    if items:

        story.append(
            subsection_title(
                "Blind Spot Priorities",
                styles,
            )
        )


        rows = [
            [
                p(
                    "Evidence",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Risk",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Coverage",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Blind Spot",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Severity",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Reason",
                    styles[
                        "table_bold"
                    ],
                ),
            ]
        ]


        for item in sorted(
            items,
            key=lambda value:
                float(
                    value.get(
                        "blind_spot_score"
                    )
                    or 0
                ),
            reverse=True,
        ):

            reasons = "; ".join(
                safe_text(
                    reason
                )

                for reason
                in item.get(
                    "reasons",
                    [],
                )
            )


            rows.append(
                [
                    p(
                        (
                            safe_text(
                                item.get(
                                    "evidence_code"
                                )
                            )
                            +
                            "<br/>"
                            +
                            paragraph_text(
                                item.get(
                                    "filename"
                                )
                            )
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        fmt_percent(
                            item.get(
                                "forensic_risk"
                            )
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        fmt_percent(
                            item.get(
                                "coverage_score"
                            )
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        fmt_percent(
                            item.get(
                                "blind_spot_score"
                            )
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        item.get(
                            "severity"
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        reasons,
                        styles[
                            "table"
                        ],
                    ),
                ]
            )


        story.append(
            simple_table(
                rows,
                [
                    45 * mm,
                    20 * mm,
                    20 * mm,
                    22 * mm,
                    20 * mm,
                    48 * mm,
                ],
                header=True,
            )
        )


    story.append(
        Paragraph(
            (
                "<b>Coverage methodology:</b><br/>"
                +
                paragraph_text(
                    coverage.get(
                        "formula"
                    )
                )
            ),
            styles[
                "note"
            ],
        )
    )


    story.append(
        Paragraph(
            (
                "<b>Blind Spot methodology:</b><br/>"
                +
                paragraph_text(
                    blind_spots.get(
                        "formula"
                    )
                )
            ),
            styles[
                "note"
            ],
        )
    )


    story.append(
        PageBreak()
    )


# =========================================================
# TIMELINE
# =========================================================


def add_timeline(
    story: list,
    report: dict,
    styles: dict,
):

    story.extend(
        section_title(
            "6. Investigation Timeline",
            styles,
        )
    )


    timeline = report.get(
        "timeline",
        {},
    )


    summary = timeline.get(
        "summary",
        {},
    )


    story.append(
        p(
            (
                "The following section summarizes the "
                "most recent recorded investigation events "
                "within SYNAPSE."
            ),
            styles[
                "body"
            ],
        )
    )


    story.append(
        Paragraph(
            (
                "<b>Total timeline events:</b> "
                +
                escape(
                    safe_text(
                        summary.get(
                            "total_events"
                        )
                    )
                )
                +
                "<br/>"
                +
                "<b>Evidence touched:</b> "
                +
                escape(
                    safe_text(
                        summary.get(
                            "evidence_touched"
                        )
                    )
                )
            ),
            styles[
                "note"
            ],
        )
    )


    events = timeline.get(
        "recent_events",
        [],
    )


    if events:

        rows = [
            [
                p(
                    "Timestamp",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Category",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Event",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Description",
                    styles[
                        "table_bold"
                    ],
                ),
            ]
        ]


        for event in events:

            rows.append(
                [
                    p(
                        fmt_datetime(
                            event.get(
                                "timestamp"
                            )
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        event.get(
                            "category"
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        event.get(
                            "title"
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        event.get(
                            "description"
                        ),
                        styles[
                            "table"
                        ],
                    ),
                ]
            )


        rows = white_header_row(
            rows
        )


        table = LongTable(
            rows,
            colWidths=[
                35 * mm,
                25 * mm,
                42 * mm,
                73 * mm,
            ],
            repeatRows=1,
            hAlign="LEFT",
        )


        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            0,
                        ),
                        NAVY,
                    ),
                    (
                        "TEXTCOLOR",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            0,
                        ),
                        WHITE,
                    ),
                    (
                        "GRID",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        0.35,
                        LIGHT_BORDER,
                    ),
                    (
                        "VALIGN",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        4,
                    ),
                    (
                        "RIGHTPADDING",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        4,
                    ),
                    (
                        "TOPPADDING",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        4,
                    ),
                    (
                        "BOTTOMPADDING",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        4,
                    ),
                ]
            )
        )


        story.append(
            table
        )


    if timeline.get(
        "disclaimer"
    ):

        story.append(
            Paragraph(
                (
                    "<b>Timeline limitation:</b><br/>"
                    +
                    paragraph_text(
                        timeline.get(
                            "disclaimer"
                        )
                    )
                ),
                styles[
                    "note"
                ],
            )
        )


    story.append(
        PageBreak()
    )


# =========================================================
# CHAIN OF CUSTODY
# =========================================================


def add_chain_of_custody(
    story: list,
    report: dict,
    styles: dict,
):

    story.extend(
        section_title(
            "7. Chain of Custody",
            styles,
        )
    )


    ledger = report.get(
        "chain_of_custody",
        {},
    )


    story.append(
        Paragraph(
            (
                "<b>Total ledger entries:</b> "
                +
                escape(
                    safe_text(
                        ledger.get(
                            "total_entries"
                        )
                    )
                )
            ),
            styles[
                "body"
            ],
        )
    )


    entries = ledger.get(
        "recent_entries",
        [],
    )


    if entries:

        rows = [
            [
                p(
                    "Timestamp",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Event",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Details",
                    styles[
                        "table_bold"
                    ],
                ),
                p(
                    "Current Hash",
                    styles[
                        "table_bold"
                    ],
                ),
            ]
        ]


        for entry in entries:

            rows.append(
                [
                    p(
                        fmt_datetime(
                            entry.get(
                                "timestamp"
                            )
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        entry.get(
                            "event_type"
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    p(
                        entry.get(
                            "event_data"
                        ),
                        styles[
                            "table"
                        ],
                    ),
                    code_p(
                        entry.get(
                            "current_hash"
                        ),
                        styles[
                            "code"
                        ],
                    ),
                ]
            )


        rows = white_header_row(
            rows
        )


        table = LongTable(
            rows,
            colWidths=[
                31 * mm,
                37 * mm,
                67 * mm,
                40 * mm,
            ],
            repeatRows=1,
            hAlign="LEFT",
        )


        table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            0,
                        ),
                        NAVY,
                    ),
                    (
                        "TEXTCOLOR",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            0,
                        ),
                        WHITE,
                    ),
                    (
                        "GRID",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        0.35,
                        LIGHT_BORDER,
                    ),
                    (
                        "VALIGN",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        "TOP",
                    ),
                    (
                        "LEFTPADDING",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        4,
                    ),
                    (
                        "RIGHTPADDING",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        4,
                    ),
                    (
                        "TOPPADDING",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        4,
                    ),
                    (
                        "BOTTOMPADDING",
                        (
                            0,
                            0,
                        ),
                        (
                            -1,
                            -1,
                        ),
                        4,
                    ),
                ]
            )
        )


        story.append(
            table
        )


    if ledger.get(
        "note"
    ):

        story.append(
            Paragraph(
                paragraph_text(
                    ledger.get(
                        "note"
                    )
                ),
                styles[
                    "note"
                ],
            )
        )


    story.append(
        PageBreak()
    )


# =========================================================
# METHODOLOGY + LIMITATIONS
# =========================================================


def add_methodology(
    story: list,
    report: dict,
    styles: dict,
):

    story.extend(
        section_title(
            "8. Methodology and Limitations",
            styles,
        )
    )


    story.append(
        subsection_title(
            "Methodology",
            styles,
        )
    )


    for index, item in enumerate(
        report.get(
            "methodology",
            [],
        ),
        start=1,
    ):

        story.append(
            Paragraph(
                (
                    f"<b>{index}.</b> "
                    +
                    paragraph_text(
                        item
                    )
                ),
                styles[
                    "body"
                ],
            )
        )


    story.append(
        Spacer(
            1,
            3 * mm,
        )
    )


    story.append(
        subsection_title(
            "Limitations",
            styles,
        )
    )


    for index, item in enumerate(
        report.get(
            "limitations",
            [],
        ),
        start=1,
    ):

        story.append(
            Paragraph(
                (
                    f"<b>{index}.</b> "
                    +
                    paragraph_text(
                        item
                    )
                ),
                styles[
                    "body"
                ],
            )
        )


    story.append(
        Spacer(
            1,
            7 * mm,
        )
    )


    story.append(
        Paragraph(
            (
                "<b>Final note:</b><br/>"
                "This report is a technical investigation "
                "support document. SYNAPSE does not determine "
                "criminal responsibility, guilt, intent or "
                "legal conclusions."
            ),
            styles[
                "note"
            ],
        )
    )


# =========================================================
# PDF BUILDER
# =========================================================


def build_forensic_pdf(
    report: dict,
) -> bytes:

    buffer = BytesIO()


    document = SimpleDocTemplate(

        buffer,

        pagesize=A4,

        rightMargin=15 * mm,

        leftMargin=15 * mm,

        topMargin=22 * mm,

        bottomMargin=18 * mm,

        title=(
            "SYNAPSE Digital Forensic "
            "Investigation Report"
        ),

        author="SYNAPSE",

        subject=(
            safe_text(
                report.get(
                    "case",
                    {},
                ).get(
                    "case_code"
                )
            )
        ),
    )


    styles = (
        build_styles()
    )


    story = []


    add_cover(
        story=story,
        report=report,
        styles=styles,
    )


    add_executive_summary(
        story=story,
        report=report,
        styles=styles,
    )


    add_evidence_inventory(
        story=story,
        report=report,
        styles=styles,
    )


    add_detailed_evidence(
        story=story,
        report=report,
        styles=styles,
    )


    add_correlations(
        story=story,
        report=report,
        styles=styles,
    )


    add_human_aware_review(
        story=story,
        report=report,
        styles=styles,
    )


    add_timeline(
        story=story,
        report=report,
        styles=styles,
    )


    add_chain_of_custody(
        story=story,
        report=report,
        styles=styles,
    )


    add_methodology(
        story=story,
        report=report,
        styles=styles,
    )


    document.build(

        story,

        onFirstPage=(
            draw_cover
        ),

        onLaterPages=(
            body_page_callback(
                report
            )
        ),
    )


    pdf_bytes = (
        buffer.getvalue()
    )


    buffer.close()


    return pdf_bytes
