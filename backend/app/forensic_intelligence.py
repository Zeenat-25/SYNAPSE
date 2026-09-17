from __future__ import annotations

import os
import re
from collections import defaultdict
from datetime import datetime
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

try:
    from pypdf import PdfReader
except Exception:  # optional dependency
    PdfReader = None  # type: ignore[assignment]

try:
    from PIL import Image
except Exception:  # optional dependency
    Image = None  # type: ignore[assignment]

try:
    import pytesseract
except Exception:  # optional dependency
    pytesseract = None  # type: ignore[assignment]


PROFILE_KIND = "FORENSIC_PROFILE"

TEXT_EXTENSIONS = {
    ".txt", ".log", ".csv", ".json", ".xml", ".ini", ".cfg",
    ".conf", ".ps1", ".bat", ".cmd", ".vbs", ".js",
}

URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_PATTERN = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE,
)
DATE_PATTERN = re.compile(
    r"\b20\d{2}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?\b"
)

# Currency/amount extraction is context-based. A bare number is not treated as money.
MONEY_PATTERNS = [
    re.compile(
        r"(?:₹|INR|RS\.?|AMOUNT(?:\(INR\))?|TOTAL(?:\s+PAID)?|GRAND\s+TOTAL|SUBTOTAL)"
        r"\s*[:=]?\s*([0-9][0-9,]*(?:\.\d{1,2})?)",
        re.IGNORECASE,
    ),
    re.compile(r"\bamount\s*=\s*([0-9][0-9,]*(?:\.\d{1,2})?)", re.IGNORECASE),
]

ACCOUNT_PATTERNS = [
    re.compile(
        r"(?:account(?:\s+(?:no\.?|number|ending))?|acct_ending_|a/c(?:\s+no\.?)?|bank_account)"
        r"[^\n\r]{0,45}?(?:\*{2,}|x{2,}[\s\-x]*)?(\d{4})\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:old|new)\s*=\s*(?:\*{2,}|x{2,})?(\d{4})\b", re.IGNORECASE),
]

INVOICE_PATTERN = re.compile(
    r"\b(?:invoice(?:\s+(?:no\.?|number|id))?\s*[:=#-]?\s*)?"
    r"([A-Z]{2,12}[A-Z0-9]*[-/]\d{2,12})\b",
    re.IGNORECASE,
)
PAYMENT_PATTERN = re.compile(
    r"\b(?:payment|voucher|transaction)(?:\s+(?:id|no\.?|number))?\s*[:=#-]?\s*"
    r"([A-Z0-9][A-Z0-9-]{3,30})\b",
    re.IGNORECASE,
)
PO_PATTERN = re.compile(
    r"\b(?:PO|PURCHASE\s+ORDER)(?:\s+(?:REF(?:ERENCE)?|NO\.?|NUMBER))?\s*[:=#-]?\s*"
    r"([A-Z0-9][A-Z0-9-]{3,30})\b",
    re.IGNORECASE,
)
USER_PATTERN = re.compile(r"\buser=([A-Z0-9._-]+)", re.IGNORECASE)
ACTION_PATTERN = re.compile(r"\baction=([A-Z0-9_:-]+)", re.IGNORECASE)

THRESHOLD_PATTERNS = [
    re.compile(
        r"payments?\s*(?:>=|>|over|above|at\s+least)\s*(?:inr|₹|rs\.?)?\s*([\d,]+)"
        r"[^\n]{0,100}?(?:approval|co-approval|cfo|manager)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:approval|co-approval|cfo|manager)[^\n]{0,100}?threshold"
        r"[^\d]{0,20}(?:inr|₹|rs\.?)?\s*([\d,]+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:threshold|approval\s+limit)\s*[:=]?\s*(?:inr|₹|rs\.?)?\s*([\d,]+)",
        re.IGNORECASE,
    ),
]

CYBER_PATTERNS: dict[str, re.Pattern[str]] = {
    "POWERSHELL_ENCODED_COMMAND": re.compile(
        r"powershell(?:\.exe)?.{0,80}(?:-enc|-encodedcommand)", re.IGNORECASE
    ),
    "DOWNLOAD_COMMAND": re.compile(
        r"\b(?:wget|curl|invoke-webrequest|iwr|downloadstring)\b", re.IGNORECASE
    ),
    "PROCESS_EXECUTION": re.compile(
        r"\b(?:start-process|cmd\.exe|wscript\.exe|cscript\.exe)\b", re.IGNORECASE
    ),
    "REGISTRY_PERSISTENCE": re.compile(
        r"\b(?:currentversion\\run|reg\s+add|schtasks)\b", re.IGNORECASE
    ),
}

FINANCIAL_TERMS = {
    "invoice", "vendor", "beneficiary", "payment", "ledger", "approval",
    "bank", "gst", "utr", "settlement account", "accounts payable",
}

COMPANY_STOPWORDS = {
    "pvt", "private", "ltd", "limited", "llp", "inc", "incorporated",
    "corp", "corporation", "company", "co", "the", "supplies", "services",
    "consulting", "solutions", "enterprises", "enterprise", "trading",
}


def _dedupe(values: list[Any]) -> list[Any]:
    seen: set[str] = set()
    output: list[Any] = []
    for value in values:
        if value is None:
            continue
        normalized = str(value).strip()
        if not normalized:
            continue
        key = normalized.casefold()
        if key in seen:
            continue
        seen.add(key)
        output.append(value)
    return output


def _valid_ipv4(value: str) -> bool:
    try:
        parts = [int(part) for part in value.split(".")]
        return len(parts) == 4 and all(0 <= part <= 255 for part in parts)
    except ValueError:
        return False


def _parse_amount(value: str | int | float | None) -> int | None:
    if value is None:
        return None
    try:
        number = float(str(value).replace(",", "").strip())
    except (TypeError, ValueError):
        return None
    if number < 0:
        return None
    return int(round(number))


def _format_inr(value: int | float) -> str:
    number = int(round(float(value)))
    sign = "-" if number < 0 else ""
    digits = str(abs(number))
    if len(digits) <= 3:
        return f"₹{sign}{digits}"
    tail = digits[-3:]
    rest = digits[:-3]
    groups: list[str] = []
    while rest:
        groups.append(rest[-2:])
        rest = rest[:-2]
    return f"₹{sign}{','.join(reversed(groups))},{tail}"


def _normalize_company(value: str) -> set[str]:
    tokens = re.findall(r"[a-z0-9]+", value.casefold())
    return {token for token in tokens if token not in COMPANY_STOPWORDS and len(token) > 1}


def _company_similarity(left: str, right: str) -> float:
    left_tokens = _normalize_company(left)
    right_tokens = _normalize_company(right)
    if left_tokens and right_tokens:
        overlap = len(left_tokens & right_tokens) / max(len(left_tokens), len(right_tokens))
        if overlap > 0:
            return overlap
    left_norm = " ".join(sorted(left_tokens)) or left.casefold().strip()
    right_norm = " ".join(sorted(right_tokens)) or right.casefold().strip()
    return SequenceMatcher(None, left_norm, right_norm).ratio()


def extract_text(path: Path, extension: str) -> tuple[str, str, list[str]]:
    """Read evidence without executing it."""
    extension = extension.lower().strip()
    limitations: list[str] = []

    if extension in TEXT_EXTENSIONS:
        raw = path.read_bytes()[:8_000_000]
        return raw.decode("utf-8", errors="ignore"), "TEXT_DECODE", limitations

    if extension == ".pdf":
        if PdfReader is None:
            limitations.append("PDF text extraction unavailable because pypdf is not installed.")
            return "", "PDF_STRUCTURE_ONLY", limitations
        try:
            reader = PdfReader(str(path))
            pages = [(page.extract_text() or "") for page in reader.pages[:60]]
            text = "\n".join(pages).strip()
            if not text:
                limitations.append("No embedded PDF text was extractable; scanned PDFs need OCR.")
            return text, "PDF_TEXT_EXTRACTION", limitations
        except Exception as exc:
            limitations.append(f"PDF text extraction failed: {exc}")
            return "", "PDF_STRUCTURE_ONLY", limitations

    if extension in {".png", ".jpg", ".jpeg"}:
        if Image is None or pytesseract is None:
            limitations.append("Image OCR unavailable because Pillow/pytesseract is not installed.")
            return "", "IMAGE_STRUCTURE_ONLY", limitations
        if os.getenv("SYNAPSE_DISABLE_LOCAL_OCR", "0").strip() == "1":
            limitations.append("Local image OCR is disabled by SYNAPSE_DISABLE_LOCAL_OCR.")
            return "", "IMAGE_STRUCTURE_ONLY", limitations
        try:
            with Image.open(path) as image:
                image = image.convert("RGB")
                text = pytesseract.image_to_string(image, config="--psm 6").strip()
            if not text:
                limitations.append("OCR returned no readable text from the image.")
            return text, "LOCAL_IMAGE_OCR", limitations
        except Exception as exc:
            limitations.append(
                "Local OCR failed or the Tesseract executable is unavailable: " + str(exc)
            )
            return "", "IMAGE_STRUCTURE_ONLY", limitations

    return "", "UNSUPPORTED_TEXT_EXTRACTION", limitations


def classify_artifact(text: str, extension: str, filename: str = "") -> tuple[str, str, float]:
    lowered = text.casefold()
    name = filename.casefold()

    if "action=" in lowered and "user=" in lowered and "result=" in lowered:
        return "financial", "audit_log", 0.97

    if lowered.count("from:") >= 1 and lowered.count("subject:") >= 1:
        domain = "financial" if any(term in lowered for term in FINANCIAL_TERMS) else "communication"
        return domain, "email", 0.95

    if (
        "general ledger" in lowered
        or ("voucher" in lowered and "vendor" in lowered and "amount" in lowered and "approver" in lowered)
        or ("ledger" in name and "amount" in lowered)
    ):
        return "financial", "ledger", 0.98

    if "tax invoice" in lowered or (
        "invoice" in lowered and "payment instructions" in lowered and "total" in lowered
    ):
        return "financial", "invoice", 0.97

    if (
        "payment confirmation" in lowered
        or "transaction successful" in lowered
        or ("beneficiary" in lowered and ("utr" in lowered or "transaction id" in lowered))
        or ("payment" in name and any(term in lowered for term in {"amount", "beneficiary", "account", "utr"}))
    ):
        return "financial", "payment_confirmation", 0.90

    # Common chat/transcript exports. This is intentionally conservative:
    # require at least three timestamped/speaker-style message lines.
    chat_lines = re.findall(
        r"(?m)^\s*(?:\[?20\d{2}-\d{2}-\d{2}[^\]\n]{0,24}\]?\s+)?"
        r"[A-Za-z][A-Za-z0-9 ._@+-]{1,60}\s*:\s*\S.+$",
        text,
    )
    if len(chat_lines) >= 3 and "subject:" not in lowered:
        domain = "financial" if any(term in lowered for term in FINANCIAL_TERMS) else "communication"
        return domain, "chat_transcript", 0.78

    # Common web/server/security log shape: repeated IP + request/status lines.
    log_event_lines = re.findall(
        r"(?m)^\s*(?:20\d{2}-\d{2}-\d{2}[ T][0-9:]+\s+)?"
        r"(?:\d{1,3}\.){3}\d{1,3}\s+.*(?:GET|POST|PUT|DELETE|PATCH|"
        r"status=\d{3}|result=|action=).*$",
        text,
        re.IGNORECASE,
    )
    if len(log_event_lines) >= 3:
        return "cyber", "network_or_server_log", 0.82

    if any(pattern.search(text) for pattern in CYBER_PATTERNS.values()):
        return "cyber", "script_or_log", 0.93

    if URL_PATTERN.search(text) or IP_PATTERN.search(text):
        return "cyber", "text_artifact", 0.73

    if any(term in lowered for term in FINANCIAL_TERMS):
        return "financial", "financial_document", 0.68

    if extension == ".pdf":
        return "document", "pdf_document", 0.60
    if extension in {".png", ".jpg", ".jpeg"}:
        return "document", "image_document", 0.55
    return "text", "text_artifact", 0.52


def extract_threshold(text: str) -> int | None:
    for pattern in THRESHOLD_PATTERNS:
        match = pattern.search(text)
        if match:
            value = _parse_amount(match.group(1))
            if value and value > 0:
                return value
    return None


def extract_ledger_transactions(text: str) -> list[dict[str, Any]]:
    """
    Parse common exported ledger rows without assuming any vendor, account,
    voucher prefix, or invoice prefix.
    """
    transactions: list[dict[str, Any]] = []
    row_pattern = re.compile(
        r"^(?P<date>20\d{2}-\d{2}-\d{2})\s+"
        r"(?P<payment>[A-Z0-9][A-Z0-9-]{2,30})\s+"
        r"(?P<vendor>.+?)\s+"
        r"(?P<invoice>[A-Z][A-Z0-9-]{2,30})\s+"
        r"(?P<amount>[\d,]+(?:\.\d{1,2})?)\s+"
        r"(?:\*{2,}|x{2,})?(?P<account>\d{4})\s+"
        r"(?P<approver>\S+)\s+"
        r"(?P<status>[A-Z_]+)\s*$",
        re.MULTILINE | re.IGNORECASE,
    )

    for match in row_pattern.finditer(text):
        amount = _parse_amount(match.group("amount"))
        if amount is None:
            continue
        transactions.append(
            {
                "date": match.group("date"),
                "payment_id": match.group("payment").upper(),
                "vendor": re.sub(r"\s+", " ", match.group("vendor")).strip(),
                "invoice_id": match.group("invoice").upper(),
                "amount": amount,
                "account": match.group("account"),
                "approver": match.group("approver"),
                "status": match.group("status").upper(),
            }
        )
    return transactions


def _extract_invoice_vendor(text: str) -> str | None:
    lines = [re.sub(r"\s+", " ", line).strip() for line in text.splitlines() if line.strip()]
    stop_markers = {
        "tax invoice", "invoice", "bill to", "invoice details", "date", "due date",
        "payment instructions", "description", "subtotal", "total",
    }
    for line in lines[:12]:
        lower = line.casefold().strip(":")
        if any(lower == marker or lower.startswith(marker + ":") for marker in stop_markers):
            continue
        if re.search(r"[A-Za-z]", line) and not re.search(r"\bpage\s+\d+\b", line, re.IGNORECASE):
            if len(line) <= 120:
                return line
    return None


def _extract_beneficiaries(text: str) -> list[str]:
    values: list[str] = []
    patterns = [
        re.compile(r"A/C\s+Name\s*:\s*([^\n\r]+)", re.IGNORECASE),
        re.compile(r"beneficiary(?:\s+name)?\s*[:=]\s*\"([^\"]+)\"", re.IGNORECASE),
        re.compile(r"beneficiary(?:\s+name)?\s*[:=]\s*([^\n\r,;]+)", re.IGNORECASE),
        re.compile(r"beneficiary\s+\"([^\"]+)\"", re.IGNORECASE),
    ]
    for pattern in patterns:
        for match in pattern.finditer(text):
            value = re.sub(r"\s+", " ", match.group(1)).strip(" .\t\"")
            if value and not value.isdigit() and len(value) <= 120:
                values.append(value)

    # Audit logs commonly store old/new quoted beneficiary values.
    for line in text.splitlines():
        if re.search(r"field=BENEFICIARY", line, re.IGNORECASE):
            values.extend(re.findall(r"(?:old|new)=\"([^\"]+)\"", line, re.IGNORECASE))
    return [str(v) for v in _dedupe(values)]


def _extract_account_last4(text: str) -> list[str]:
    values: list[str] = []
    for pattern in ACCOUNT_PATTERNS:
        values.extend(pattern.findall(text))
    # Also capture masked values in explicit bank-account audit changes.
    for line in text.splitlines():
        if re.search(r"field=BANK_ACCOUNT", line, re.IGNORECASE):
            values.extend(re.findall(r"(?:old|new)=\**(\d{4})\b", line, re.IGNORECASE))
    return [str(v) for v in _dedupe(values)]


def _extract_amounts(text: str) -> list[int]:
    values: list[int] = []
    for pattern in MONEY_PATTERNS:
        for raw in pattern.findall(text):
            parsed = _parse_amount(raw)
            if parsed is not None and parsed > 0:
                values.append(parsed)
    return sorted(set(values))


def _extract_audit_vendors(text: str) -> list[str]:
    values: list[str] = []
    for line in text.splitlines():
        action_match = re.search(r"\baction=([A-Z0-9_:-]+)", line, re.IGNORECASE)
        object_match = re.search(r"\bobject=([A-Z0-9_.:-]+)", line, re.IGNORECASE)
        if not action_match or not object_match:
            continue
        action = action_match.group(1).upper()
        if "VENDOR" not in action:
            continue
        raw = object_match.group(1).replace("_", " ").replace("-", " ")
        value = re.sub(r"\s+", " ", raw).strip().title()
        if value:
            values.append(value)
    return [str(v) for v in _dedupe(values)]


def extract_entities(text: str, artifact_type: str) -> dict[str, list[Any]]:
    urls = [str(v) for v in _dedupe(URL_PATTERN.findall(text))]
    ips = [str(v) for v in _dedupe([ip for ip in IP_PATTERN.findall(text) if _valid_ipv4(ip)])]
    emails = [str(v) for v in _dedupe(EMAIL_PATTERN.findall(text))]
    timestamps = [str(v) for v in _dedupe(DATE_PATTERN.findall(text))]
    accounts = _extract_account_last4(text)
    amounts = _extract_amounts(text)

    invoice_ids: list[str] = []
    for match in INVOICE_PATTERN.finditer(text):
        value = match.group(1).upper()
        # Avoid treating common date-like fragments as invoice ids.
        if not re.fullmatch(r"20\d{2}-\d{2}", value):
            invoice_ids.append(value)

    payment_ids: list[str] = []
    for match in PAYMENT_PATTERN.finditer(text):
        candidate = match.group(1).upper()
        if candidate not in {"SUCCESS", "COMPLETED", "FAILED"}:
            payment_ids.append(candidate)

    po_ids = [match.group(1).upper() for match in PO_PATTERN.finditer(text)]
    users = USER_PATTERN.findall(text)
    users.extend(email.split("@", 1)[0] for email in emails)
    actions = [value.upper() for value in ACTION_PATTERN.findall(text)]

    transactions = extract_ledger_transactions(text)
    vendors: list[str] = []
    for tx in transactions:
        amounts.append(tx["amount"])
        accounts.append(tx["account"])
        invoice_ids.append(tx["invoice_id"])
        payment_ids.append(tx["payment_id"])
        vendors.append(tx["vendor"])

    if artifact_type == "invoice":
        vendor = _extract_invoice_vendor(text)
        if vendor:
            vendors.append(vendor)

    vendors.extend(_extract_audit_vendors(text))
    beneficiaries = _extract_beneficiaries(text)
    threshold = extract_threshold(text)

    return {
        "amounts": sorted(set(int(v) for v in amounts if _parse_amount(v) is not None)),
        "accounts": [str(v) for v in _dedupe(accounts)],
        "invoice_ids": [str(v) for v in _dedupe(invoice_ids)],
        "payment_ids": [str(v) for v in _dedupe(payment_ids)],
        "po_ids": [str(v) for v in _dedupe(po_ids)],
        "vendors": [str(v) for v in _dedupe(vendors)],
        "beneficiaries": [str(v) for v in _dedupe(beneficiaries)],
        "organizations": [str(v) for v in _dedupe(vendors + beneficiaries)],
        "users": [str(v) for v in _dedupe(users)],
        "actions": [str(v) for v in _dedupe(actions)],
        "emails": emails,
        "urls": urls,
        "ips": ips,
        "timestamps": timestamps,
        "approval_thresholds": [threshold] if threshold else [],
    }


# =========================================================
# ARTIFACT-AWARE STRUCTURED EXTRACTION
# =========================================================
#
# Generic entity extraction remains useful across investigations, but it is
# not enough to describe the shape of the evidence. This layer preserves the
# structure of the artifact itself (email messages, ledger rows, audit events,
# etc.) without tying SYNAPSE to any specific case, vendor, person, or story.


def _clean_scalar(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _split_address_values(value: str) -> list[str]:
    emails = [str(v) for v in _dedupe(EMAIL_PATTERN.findall(value))]
    if emails:
        return emails
    parts = [
        part.strip()
        for part in re.split(r"[;,]", value)
        if part.strip()
    ]
    return [str(v) for v in _dedupe(parts)]


def _normalise_subject(value: str) -> str:
    subject = _clean_scalar(value)
    while True:
        stripped = re.sub(r"^(?:re|fw|fwd)\s*:\s*", "", subject, flags=re.IGNORECASE)
        if stripped == subject:
            break
        subject = stripped
    return subject


def extract_email_messages(text: str) -> list[dict[str, Any]]:
    """
    Parse exported email content without assuming a specific sender, vendor,
    subject, or case. Supports both single-message text emails and simple
    exported threads that contain MESSAGE/EMAIL separators.
    """
    separator = re.compile(
        r"(?m)^\s*-{2,}\s*(?:MESSAGE|EMAIL)\s*(\d+)?\s*-{2,}\s*$",
        re.IGNORECASE,
    )
    matches = list(separator.finditer(text))

    blocks: list[tuple[int, str]] = []
    if matches:
        for index, match in enumerate(matches):
            start = match.end()
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            number = int(match.group(1)) if match.group(1) else index + 1
            blocks.append((number, text[start:end].strip()))
    else:
        blocks.append((1, text.strip()))

    messages: list[dict[str, Any]] = []
    header_pattern = re.compile(
        r"(?mi)^(From|To|Cc|Bcc|Date|Sent|Subject)\s*:\s*(.+?)\s*$"
    )

    for sequence, block in blocks:
        headers: dict[str, str] = {}
        header_matches = list(header_pattern.finditer(block))
        for match in header_matches:
            key = match.group(1).casefold()
            if key == "sent":
                key = "date"
            headers.setdefault(key, _clean_scalar(match.group(2)))

        if not any(headers.get(key) for key in ("from", "to", "subject", "date")):
            continue

        body_start = max((match.end() for match in header_matches), default=0)
        body = block[body_start:].strip()
        body = re.sub(r"(?m)^\s*-{2,}\s*$", "", body).strip()

        messages.append(
            {
                "message_number": sequence,
                "from": headers.get("from", ""),
                "to": _split_address_values(headers.get("to", "")),
                "cc": _split_address_values(headers.get("cc", "")),
                "bcc": _split_address_values(headers.get("bcc", "")),
                "date": headers.get("date", ""),
                "subject": headers.get("subject", ""),
                "body_excerpt": body[:2000],
            }
        )

    return messages[:100]


def extract_chat_messages(text: str) -> list[dict[str, Any]]:
    """
    Parse common plain-text chat/transcript lines. Unknown formats simply
    return no records and fall back to generic entity extraction.
    """
    patterns = [
        re.compile(
            r"^\s*\[(?P<timestamp>[^\]]+)\]\s*"
            r"(?P<speaker>[A-Za-z][A-Za-z0-9 ._@+-]{1,60})\s*:\s*"
            r"(?P<message>.+?)\s*$"
        ),
        re.compile(
            r"^\s*(?P<timestamp>20\d{2}-\d{2}-\d{2}"
            r"(?:[ T]\d{2}:\d{2}(?::\d{2})?)?)\s+"
            r"(?P<speaker>[A-Za-z][A-Za-z0-9 ._@+-]{1,60})\s*:\s*"
            r"(?P<message>.+?)\s*$"
        ),
        re.compile(
            r"^\s*(?P<speaker>[A-Za-z][A-Za-z0-9 ._@+-]{1,60})\s*:\s*"
            r"(?P<message>.+?)\s*$"
        ),
    ]

    records: list[dict[str, Any]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        for pattern in patterns:
            match = pattern.match(line)
            if not match:
                continue
            groups = match.groupdict()
            records.append(
                {
                    "message_number": len(records) + 1,
                    "timestamp": _clean_scalar(groups.get("timestamp", "")),
                    "speaker": _clean_scalar(groups.get("speaker", "")),
                    "message": _clean_scalar(groups.get("message", ""))[:2000],
                }
            )
            break

    return records[:300]


def _parse_key_value_tokens(line: str) -> dict[str, str]:
    """
    Parse key=value log tokens while preserving quoted values containing
    spaces, e.g. old="Vendor A" new="Vendor B".
    """
    result: dict[str, str] = {}
    token_pattern = re.compile(
        r"\b([A-Za-z][A-Za-z0-9_.:-]*)="
        r"(\"[^\"]*\"|'[^']*'|[^\s]+)"
    )
    for match in token_pattern.finditer(line):
        key = match.group(1).strip().casefold()
        value = match.group(2).strip().strip("\"'")
        result[key] = value
    return result


def extract_audit_events(text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    timestamp_pattern = re.compile(
        r"^\s*(20\d{2}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+"
    )

    for raw_line in text.splitlines():
        timestamp_match = timestamp_pattern.match(raw_line)
        if not timestamp_match:
            continue

        tokens = _parse_key_value_tokens(raw_line[timestamp_match.end():])
        if not tokens:
            continue

        events.append(
            {
                "timestamp": timestamp_match.group(1),
                "user": tokens.get("user", ""),
                "source": tokens.get("src", tokens.get("source", "")),
                "action": tokens.get("action", ""),
                "object": tokens.get("object", ""),
                "field": tokens.get("field", ""),
                "old_value": tokens.get("old", ""),
                "new_value": tokens.get("new", ""),
                "value": tokens.get("value", ""),
                "amount": tokens.get("amount", ""),
                "result": tokens.get("result", ""),
                "mfa": tokens.get("mfa", ""),
                "device": tokens.get("device", ""),
                "file": tokens.get("file", ""),
            }
        )

    return events[:500]


def extract_network_log_events(text: str) -> list[dict[str, Any]]:
    """
    Conservative parser for common access/server log lines. Only directly
    observable fields are returned.
    """
    events: list[dict[str, Any]] = []
    common_log = re.compile(
        r'^\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+'
        r'.*?"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+'
        r'(?P<path>\S+)(?:\s+HTTP/[0-9.]+)?"\s+'
        r'(?P<status>\d{3})\b',
        re.IGNORECASE,
    )

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        match = common_log.match(line)
        if match and _valid_ipv4(match.group("ip")):
            events.append(
                {
                    "source_ip": match.group("ip"),
                    "method": match.group("method").upper(),
                    "path": match.group("path"),
                    "status": match.group("status"),
                    "raw_excerpt": line[:500],
                }
            )
            continue

        tokens = _parse_key_value_tokens(line)
        source_ip = tokens.get("src", tokens.get("source", tokens.get("ip", "")))
        if source_ip and _valid_ipv4(source_ip) and (
            tokens.get("status") or tokens.get("action") or tokens.get("result")
        ):
            events.append(
                {
                    "source_ip": source_ip,
                    "method": tokens.get("method", ""),
                    "path": tokens.get("path", tokens.get("url", "")),
                    "status": tokens.get("status", tokens.get("result", "")),
                    "action": tokens.get("action", ""),
                    "user": tokens.get("user", ""),
                    "raw_excerpt": line[:500],
                }
            )

    return events[:500]


def _entity_groups(
    entities: dict[str, list[Any]],
    *,
    include_empty: bool = False,
) -> list[dict[str, Any]]:
    labels = [
        ("emails", "Email Addresses"),
        ("users", "Users / Identities"),
        ("urls", "URLs"),
        ("ips", "IP Addresses"),
        ("timestamps", "Timestamps"),
        ("vendors", "Vendors"),
        ("beneficiaries", "Beneficiaries"),
        ("organizations", "Organizations"),
        ("invoice_ids", "Invoice IDs"),
        ("payment_ids", "Payment / Transaction IDs"),
        ("po_ids", "Purchase Order IDs"),
        ("amounts", "Amounts (INR)"),
        ("accounts", "Bank Account Endings"),
        ("actions", "Actions"),
        ("approval_thresholds", "Approval Thresholds (INR)"),
    ]

    groups: list[dict[str, Any]] = []
    for key, label in labels:
        values = entities.get(key, [])
        if values or include_empty:
            groups.append(
                {
                    "key": key,
                    "label": label,
                    "values": list(values)[:100],
                }
            )
    return groups


def _records_section(
    key: str,
    label: str,
    columns: list[tuple[str, str]],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "kind": "records",
        "columns": [
            {"key": column_key, "label": column_label}
            for column_key, column_label in columns
        ],
        "records": records,
    }


def _groups_section(
    key: str,
    label: str,
    groups: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "kind": "groups",
        "groups": groups,
    }


def _key_value_section(
    key: str,
    label: str,
    items: list[tuple[str, Any]],
) -> dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "kind": "key_value",
        "items": [
            {"label": item_label, "value": value}
            for item_label, value in items
            if value not in (None, "", [], {})
        ],
    }


def build_structured_evidence(
    text: str,
    artifact_type: str,
    domain: str,
    entities: dict[str, list[Any]],
) -> dict[str, Any]:
    """
    Return a stable renderer-friendly structure.

    UI/PDF consumers only need to understand three generic section kinds:
    key_value, records, and groups. New artifact parsers can be added later
    without redesigning the frontend or PDF template.
    """
    display_names = {
        "email": "Email Communication",
        "chat_transcript": "Chat / Message Transcript",
        "ledger": "Financial Ledger",
        "audit_log": "Audit Log",
        "invoice": "Invoice / Billing Document",
        "payment_confirmation": "Payment Confirmation",
        "network_or_server_log": "Network / Server Log",
        "script_or_log": "Cyber Artifact",
        "text_artifact": "Text Artifact",
        "financial_document": "Financial Document",
        "pdf_document": "PDF Document",
        "image_document": "Image Document",
    }

    sections: list[dict[str, Any]] = []

    if artifact_type == "email":
        messages = extract_email_messages(text)
        participants: list[str] = []
        subjects: list[str] = []

        for message in messages:
            participants.extend(_split_address_values(str(message.get("from", ""))))
            participants.extend([str(v) for v in message.get("to", [])])
            participants.extend([str(v) for v in message.get("cc", [])])
            participants.extend([str(v) for v in message.get("bcc", [])])
            subject = _normalise_subject(str(message.get("subject", "")))
            if subject:
                subjects.append(subject)

        sections.append(
            _key_value_section(
                "email_overview",
                "Email Thread Overview" if len(messages) > 1 else "Email Overview",
                [
                    ("Messages", len(messages)),
                    ("Participants", len(_dedupe(participants))),
                    ("Thread Subject", _dedupe(subjects)[0] if subjects else ""),
                ],
            )
        )
        if messages:
            sections.append(
                _records_section(
                    "email_messages",
                    "Email Messages",
                    [
                        ("message_number", "Message"),
                        ("from", "From"),
                        ("to", "To"),
                        ("date", "Date"),
                        ("subject", "Subject"),
                        ("body_excerpt", "Body"),
                    ],
                    messages,
                )
            )
        sections.append(
            _groups_section(
                "referenced_entities",
                "Referenced Entities",
                _entity_groups(entities),
            )
        )

    elif artifact_type == "chat_transcript":
        messages = extract_chat_messages(text)
        participants = [record.get("speaker", "") for record in messages]
        sections.append(
            _key_value_section(
                "chat_overview",
                "Conversation Overview",
                [
                    ("Messages", len(messages)),
                    ("Participants", len(_dedupe(participants))),
                ],
            )
        )
        if messages:
            sections.append(
                _records_section(
                    "chat_messages",
                    "Messages",
                    [
                        ("message_number", "Message"),
                        ("timestamp", "Timestamp"),
                        ("speaker", "Speaker"),
                        ("message", "Content"),
                    ],
                    messages,
                )
            )
        sections.append(
            _groups_section(
                "referenced_entities",
                "Referenced Entities",
                _entity_groups(entities),
            )
        )

    elif artifact_type == "ledger":
        transactions = extract_ledger_transactions(text)
        threshold = extract_threshold(text)
        sections.append(
            _key_value_section(
                "ledger_overview",
                "Ledger Overview",
                [
                    ("Transactions", len(transactions)),
                    ("Approval Threshold (INR)", threshold),
                    ("Vendors", len(_dedupe([tx.get("vendor", "") for tx in transactions]))),
                ],
            )
        )
        if transactions:
            sections.append(
                _records_section(
                    "ledger_transactions",
                    "Transactions",
                    [
                        ("date", "Date"),
                        ("payment_id", "Payment"),
                        ("vendor", "Vendor"),
                        ("invoice_id", "Invoice"),
                        ("amount", "Amount (INR)"),
                        ("account", "Account"),
                        ("approver", "Approver"),
                        ("status", "Status"),
                    ],
                    transactions[:300],
                )
            )
        sections.append(
            _groups_section(
                "referenced_entities",
                "Referenced Entities",
                _entity_groups(entities),
            )
        )

    elif artifact_type == "audit_log":
        events = extract_audit_events(text)
        sections.append(
            _key_value_section(
                "audit_overview",
                "Audit Log Overview",
                [
                    ("Events", len(events)),
                    ("Users", len(_dedupe([event.get("user", "") for event in events]))),
                    ("Actions", len(_dedupe([event.get("action", "") for event in events]))),
                    ("Source IPs", len(_dedupe([event.get("source", "") for event in events]))),
                ],
            )
        )
        if events:
            sections.append(
                _records_section(
                    "audit_events",
                    "Audit Events",
                    [
                        ("timestamp", "Timestamp"),
                        ("user", "User"),
                        ("source", "Source"),
                        ("action", "Action"),
                        ("object", "Object"),
                        ("field", "Field"),
                        ("old_value", "Old"),
                        ("new_value", "New"),
                        ("result", "Result"),
                    ],
                    events,
                )
            )
        sections.append(
            _groups_section(
                "referenced_entities",
                "Referenced Entities",
                _entity_groups(entities),
            )
        )

    elif artifact_type == "invoice":
        sections.append(
            _key_value_section(
                "invoice_overview",
                "Invoice Details",
                [
                    ("Vendor", (entities.get("vendors") or [""])[0]),
                    ("Invoice ID", (entities.get("invoice_ids") or [""])[0]),
                    ("Purchase Order", (entities.get("po_ids") or [""])[0]),
                    ("Beneficiary", (entities.get("beneficiaries") or [""])[0]),
                    ("Payment Account", (entities.get("accounts") or [""])[0]),
                    ("Amount (INR)", (entities.get("amounts") or [""])[-1]),
                ],
            )
        )
        sections.append(
            _groups_section(
                "invoice_entities",
                "Invoice Entities",
                _entity_groups(entities),
            )
        )

    elif artifact_type == "payment_confirmation":
        sections.append(
            _key_value_section(
                "payment_overview",
                "Payment Details",
                [
                    ("Payment / Transaction ID", (entities.get("payment_ids") or [""])[0]),
                    ("Amount (INR)", (entities.get("amounts") or [""])[-1]),
                    ("Beneficiary", (entities.get("beneficiaries") or [""])[0]),
                    ("Destination Account", (entities.get("accounts") or [""])[0]),
                    ("Timestamp", (entities.get("timestamps") or [""])[0]),
                ],
            )
        )
        sections.append(
            _groups_section(
                "payment_entities",
                "Payment Entities",
                _entity_groups(entities),
            )
        )

    elif artifact_type == "network_or_server_log":
        events = extract_network_log_events(text)
        sections.append(
            _key_value_section(
                "network_log_overview",
                "Network / Server Log Overview",
                [
                    ("Events", len(events)),
                    ("Source IPs", len(_dedupe([event.get("source_ip", "") for event in events]))),
                ],
            )
        )
        if events:
            sections.append(
                _records_section(
                    "network_events",
                    "Network / Server Events",
                    [
                        ("source_ip", "Source IP"),
                        ("method", "Method"),
                        ("path", "Path / URL"),
                        ("status", "Status"),
                        ("action", "Action"),
                        ("user", "User"),
                    ],
                    events,
                )
            )
        sections.append(
            _groups_section(
                "referenced_entities",
                "Referenced Entities",
                _entity_groups(entities),
            )
        )

    else:
        # Safe fallback: unknown evidence is never forced into a known schema.
        sections.append(
            _groups_section(
                "extracted_entities",
                "Extracted Entities",
                _entity_groups(entities),
            )
        )

    return {
        "schema_version": 1,
        "artifact_type": artifact_type,
        "domain": domain,
        "display_name": display_names.get(
            artifact_type,
            artifact_type.replace("_", " ").title() or "Evidence Artifact",
        ),
        "sections": [
            section
            for section in sections
            if (
                section.get("items")
                or section.get("records")
                or section.get("groups")
            )
        ],
    }


def structured_evidence_to_indicators(
    structured: dict[str, Any],
) -> list[dict[str, str]]:
    """
    Add concise artifact-specific indicators for the current UI/PDF. The full
    structured payload is preserved separately in the forensic-profile finding.
    """
    artifact_type = str(structured.get("artifact_type", ""))
    sections = structured.get("sections", [])
    indicators: list[dict[str, str]] = []

    section_map = {
        str(section.get("key", "")): section
        for section in sections
        if isinstance(section, dict)
    }

    if artifact_type == "email":
        messages = section_map.get("email_messages", {}).get("records", [])
        indicators.append(
            {"type": "EMAIL_MESSAGE_COUNT", "value": str(len(messages))}
        )
        participants: list[str] = []
        for message in messages[:100]:
            sender = _clean_scalar(message.get("from", ""))
            if sender:
                indicators.append({"type": "EMAIL_FROM", "value": sender})
                participants.extend(_split_address_values(sender))
            for recipient in message.get("to", [])[:20]:
                value = _clean_scalar(recipient)
                if value:
                    indicators.append({"type": "EMAIL_TO", "value": value})
                    participants.append(value)
            date = _clean_scalar(message.get("date", ""))
            if date:
                indicators.append({"type": "EMAIL_MESSAGE_DATE", "value": date})
            subject = _clean_scalar(message.get("subject", ""))
            if subject:
                indicators.append({"type": "EMAIL_SUBJECT", "value": subject})
        for participant in _dedupe(participants)[:60]:
            indicators.append({"type": "EMAIL_PARTICIPANT", "value": str(participant)})

    elif artifact_type == "chat_transcript":
        records = section_map.get("chat_messages", {}).get("records", [])
        indicators.append({"type": "CHAT_MESSAGE_COUNT", "value": str(len(records))})
        for speaker in _dedupe([record.get("speaker", "") for record in records])[:60]:
            if speaker:
                indicators.append({"type": "CHAT_PARTICIPANT", "value": str(speaker)})

    elif artifact_type == "ledger":
        records = section_map.get("ledger_transactions", {}).get("records", [])
        indicators.append({"type": "TRANSACTION_COUNT", "value": str(len(records))})
        for approver in _dedupe([record.get("approver", "") for record in records])[:60]:
            if approver:
                indicators.append({"type": "APPROVER", "value": str(approver)})

    elif artifact_type == "audit_log":
        records = section_map.get("audit_events", {}).get("records", [])
        indicators.append({"type": "AUDIT_EVENT_COUNT", "value": str(len(records))})
        for event in records[:200]:
            if event.get("user"):
                indicators.append({"type": "AUDIT_USER", "value": str(event["user"])})
            if event.get("source"):
                indicators.append({"type": "SOURCE_IP", "value": str(event["source"])})
            if event.get("action"):
                indicators.append({"type": "AUDIT_ACTION", "value": str(event["action"])})
            if event.get("field"):
                indicators.append({"type": "CHANGED_FIELD", "value": str(event["field"])})

    elif artifact_type == "network_or_server_log":
        records = section_map.get("network_events", {}).get("records", [])
        indicators.append({"type": "LOG_EVENT_COUNT", "value": str(len(records))})
        for event in records[:200]:
            if event.get("source_ip"):
                indicators.append({"type": "SOURCE_IP", "value": str(event["source_ip"])})
            if event.get("path"):
                indicators.append({"type": "REQUEST_PATH", "value": str(event["path"])})
            if event.get("status"):
                indicators.append({"type": "STATUS", "value": str(event["status"])})

    return indicators



def entities_to_indicators(entities: dict[str, list[Any]]) -> list[dict[str, str]]:
    mapping = {
        "amounts": "AMOUNT_INR",
        "accounts": "BANK_ACCOUNT_LAST4",
        "invoice_ids": "INVOICE_ID",
        "payment_ids": "PAYMENT_ID",
        "po_ids": "PO_ID",
        "vendors": "VENDOR",
        "beneficiaries": "BENEFICIARY",
        "organizations": "ORGANIZATION",
        "users": "USER",
        "actions": "ACTION",
        "emails": "EMAIL",
        "urls": "URL",
        "ips": "IP",
        "timestamps": "TIMESTAMP",
        "approval_thresholds": "APPROVAL_THRESHOLD_INR",
    }
    indicators: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for key, indicator_type in mapping.items():
        for value in entities.get(key, [])[:60]:
            item = (indicator_type, str(value).strip())
            norm = (item[0], item[1].casefold())
            if not item[1] or norm in seen:
                continue
            seen.add(norm)
            indicators.append({"type": item[0], "value": item[1]})
    return indicators


def _finding(
    severity: str,
    title: str,
    detail: str,
    signal_code: str | None = None,
    points: float | None = None,
    **extra: Any,
) -> dict[str, Any]:
    item: dict[str, Any] = {"severity": severity, "title": title, "detail": detail}
    if signal_code:
        item["signal_code"] = signal_code
    if points is not None:
        item["points"] = round(float(points), 2)
    item.update(extra)
    return item


def _profile_finding(domain: str, artifact_type: str, confidence: float, extractor: str) -> dict[str, Any]:
    return _finding(
        "INFO",
        "Evidence classification",
        f"Classified as {artifact_type.replace('_', ' ')} in the {domain} domain.",
        signal_code="EVIDENCE_CLASSIFICATION",
        kind=PROFILE_KIND,
        domain=domain,
        artifact_type=artifact_type,
        confidence=round(confidence, 3),
        extractor=extractor,
    )


def _timestamps_within_minutes(text: str, minutes: int = 30) -> bool:
    values = re.findall(r"\b(20\d{2}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})\b", text)
    parsed: list[datetime] = []
    for date_part, time_part in values:
        try:
            parsed.append(datetime.strptime(f"{date_part} {time_part}", "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            pass
    parsed.sort()
    if len(parsed) < 3:
        return False
    for index in range(len(parsed) - 2):
        if (parsed[index + 2] - parsed[index]).total_seconds() <= minutes * 60:
            return True
    return False


def _ledger_analysis(text: str, entities: dict[str, list[Any]]) -> tuple[float, list[dict[str, Any]]]:
    score = 0.0
    findings: list[dict[str, Any]] = []
    transactions = extract_ledger_transactions(text)
    threshold = extract_threshold(text)

    if threshold and transactions:
        near_threshold = [
            tx for tx in transactions
            if threshold * 0.90 <= tx["amount"] < threshold
        ]
        groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for tx in near_threshold:
            groups[(tx["vendor"].casefold(), tx["account"])].append(tx)

        suspicious_groups = [group for group in groups.values() if len(group) >= 2]
        if suspicious_groups:
            group = max(suspicious_groups, key=len)
            subtotal = sum(tx["amount"] for tx in group)
            split_points = 45.0 if len(group) >= 3 else 30.0
            score += split_points
            findings.append(
                _finding(
                    "HIGH" if len(group) >= 3 else "MEDIUM",
                    "Possible transaction splitting below approval threshold",
                    (
                        f"{len(group)} payments to {group[0]['vendor']} total {_format_inr(subtotal)}; "
                        f"each falls immediately below the {_format_inr(threshold)} approval threshold."
                    ),
                    signal_code="TRANSACTION_SPLITTING",
                    points=split_points,
                    related_amount=subtotal,
                    threshold=threshold,
                    transaction_count=len(group),
                )
            )
            if subtotal >= threshold * 1.5:
                score += 12
                findings.append(
                    _finding(
                        "HIGH",
                        "Cumulative value exceeds approval threshold",
                        f"The clustered transactions total {_format_inr(subtotal)}.",
                        signal_code="CUMULATIVE_THRESHOLD_EXCEEDANCE",
                        points=12,
                        related_amount=subtotal,
                    )
                )
                entities.setdefault("amounts", []).append(subtotal)

    rapid_note = re.search(r"(?:within|in)\s+(\d+)\s+minutes", text, re.IGNORECASE)
    if (rapid_note and int(rapid_note.group(1)) <= 60) or _timestamps_within_minutes(text, 30):
        score += 10
        findings.append(
            _finding(
                "MEDIUM",
                "Rapid release of related payments",
                "Multiple related payment events occurred within a short time window.",
                signal_code="RAPID_PAYMENT_RELEASE",
                points=10,
            )
        )

    if re.search(
        r"(?:new|recent(?:ly)?)\s+(?:vendor|supplier)|"
        r"(?:vendor|supplier).{0,80}(?:added|created)|"
        r"(?:added|created).{0,80}(?:vendor|supplier)",
        text,
        re.IGNORECASE,
    ):
        score += 8
        findings.append(
            _finding(
                "MEDIUM",
                "Recently created vendor or supplier",
                "The evidence indicates that the vendor/supplier was created shortly before the payment activity.",
                signal_code="RECENT_VENDOR_CREATION",
                points=8,
            )
        )

    return min(score, 95.0), findings


def _email_analysis(text: str, entities: dict[str, list[Any]]) -> tuple[float, list[dict[str, Any]]]:
    score = 0.0
    findings: list[dict[str, Any]] = []

    bypass = bool(re.search(
        r"(?:avoid|bypass|skip|circumvent).{0,50}(?:approval|cfo|manager|authorization)|"
        r"(?:do\s+not|don't).{0,35}(?:cfo|approval|queue)|"
        r"(?:without|outside).{0,25}(?:approval|authorization)|"
        r"(?:within|below|under).{0,25}(?:approval|authorization).{0,20}(?:band|limit|threshold)",
        text,
        re.IGNORECASE,
    ))
    splitting = bool(re.search(
        r"(?:split|divide).{0,30}(?:payment|invoice|amount)|"
        r"(?:separate|multiple).{0,20}invoices?|"
        r"process.{0,20}(?:individually|separately)|"
        r"each\s+payment.{0,40}(?:below|under|within)",
        text,
        re.IGNORECASE,
    ))

    if bypass:
        score += 38
        findings.append(
            _finding(
                "HIGH",
                "Approval-bypass instruction detected",
                "The communication contains language directing a transaction away from the normal approval path.",
                signal_code="APPROVAL_BYPASS",
                points=38,
            )
        )

    if splitting:
        score += 28
        findings.append(
            _finding(
                "HIGH",
                "Invoice/payment splitting instruction detected",
                "The communication describes splitting or separately processing related payments/invoices.",
                signal_code="TRANSACTION_SPLITTING_INTENT",
                points=28,
            )
        )

    accounts = [str(v) for v in entities.get("accounts", [])]
    if len(set(accounts)) >= 2 and re.search(
        r"(?:new|old|change|changed|updated|replacement|settlement|outdated).{0,50}(?:account|bank)|"
        r"(?:account|bank).{0,50}(?:new|old|change|changed|updated|outdated)",
        text,
        re.IGNORECASE,
    ):
        score += 12
        findings.append(
            _finding(
                "HIGH",
                "Conflicting or changed bank-account details",
                f"The communication references multiple account endings ({', '.join(sorted(set(accounts)))}) in a change context.",
                signal_code="BANK_ACCOUNT_CHANGE",
                points=12,
            )
        )

    beneficiaries = [str(v) for v in entities.get("beneficiaries", [])]
    if len(beneficiaries) >= 2:
        lowest_similarity = min(
            _company_similarity(left, right)
            for i, left in enumerate(beneficiaries)
            for right in beneficiaries[i + 1:]
        )
        if lowest_similarity < 0.35:
            score += 10
            findings.append(
                _finding(
                    "HIGH",
                    "Conflicting beneficiary identities",
                    "The communication contains materially different beneficiary identities requiring verification.",
                    signal_code="VENDOR_BENEFICIARY_MISMATCH",
                    points=10,
                )
            )

    if re.search(
        r"(?:cannot|can't|unable\s+to)\s+(?:locate|find|verify).{0,60}(?:signed|callback|verification|amendment)|"
        r"(?:missing|no).{0,30}(?:signed|callback|verification|amendment)|"
        r"do\s+we\s+have.{0,60}(?:signed|callback|verification)",
        text,
        re.IGNORECASE,
    ):
        score += 8
        findings.append(
            _finding(
                "HIGH",
                "Independent verification missing or questioned",
                "The communication questions or cannot locate supporting bank/change verification.",
                signal_code="MISSING_VERIFICATION",
                points=8,
            )
        )

    if re.search(
        r"mark.{0,25}verification.{0,20}(?:complete|completed|done)|"
        r"(?:verification|confirmation).{0,35}(?:later|afterwards)|"
        r"(?:skip|bypass).{0,20}(?:verification|callback)",
        text,
        re.IGNORECASE,
    ):
        score += 8
        findings.append(
            _finding(
                "HIGH",
                "Verification override or premature completion",
                "The communication indicates verification may be marked complete without contemporaneous supporting evidence.",
                signal_code="VERIFICATION_OVERRIDE",
                points=8,
            )
        )

    return min(score, 95.0), findings


def _audit_analysis(text: str, entities: dict[str, list[Any]]) -> tuple[float, list[dict[str, Any]]]:
    score = 0.0
    findings: list[dict[str, Any]] = []
    lines = text.splitlines()

    bank_changes: list[tuple[str, str]] = []
    beneficiary_changes: list[tuple[str, str]] = []
    verification_events = 0
    delete_events: list[str] = []
    approve_amounts: list[int] = []
    approve_times: list[datetime] = []

    for line in lines:
        action_match = re.search(r"\baction=([A-Z0-9_:-]+)", line, re.IGNORECASE)
        action = action_match.group(1).upper() if action_match else ""

        if "BANK" in line.upper() and re.search(r"\bold=", line, re.IGNORECASE) and re.search(r"\bnew=", line, re.IGNORECASE):
            old_match = re.search(r"\bold=\**(\d{4})\b", line, re.IGNORECASE)
            new_match = re.search(r"\bnew=\**(\d{4})\b", line, re.IGNORECASE)
            if old_match and new_match and old_match.group(1) != new_match.group(1):
                bank_changes.append((old_match.group(1), new_match.group(1)))

        if re.search(r"field=BENEFICIARY", line, re.IGNORECASE):
            old_match = re.search(r"\bold=\"?([^\"\n]+?)\"?(?=\s+new=)", line, re.IGNORECASE)
            new_match = re.search(r"\bnew=\"?([^\"\n]+?)\"?(?=\s+result=|\s*$)", line, re.IGNORECASE)
            if old_match and new_match:
                old_value = old_match.group(1).strip()
                new_value = new_match.group(1).strip()
                if _company_similarity(old_value, new_value) < 0.5:
                    beneficiary_changes.append((old_value, new_value))

        if "VERIFICATION" in action or re.search(r"field=VERIFICATION", line, re.IGNORECASE):
            if re.search(r"(?:complete|completed|verified|success)", line, re.IGNORECASE):
                verification_events += 1

        if "DELETE" in action:
            delete_events.append(line)

        if "APPROVE" in action and "PAYMENT" in action:
            amount_match = re.search(r"\bamount=([\d,]+(?:\.\d{1,2})?)", line, re.IGNORECASE)
            if amount_match:
                parsed = _parse_amount(amount_match.group(1))
                if parsed is not None:
                    approve_amounts.append(parsed)
            time_match = re.match(r"\s*(20\d{2}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line)
            if time_match:
                try:
                    approve_times.append(datetime.strptime(time_match.group(1), "%Y-%m-%d %H:%M:%S"))
                except ValueError:
                    pass

    if bank_changes:
        score += 24
        details = ", ".join(f"{old} → {new}" for old, new in bank_changes[:3])
        findings.append(
            _finding(
                "HIGH",
                "Vendor bank account changed",
                f"Audit records show bank-account changes ({details}).",
                signal_code="BANK_ACCOUNT_CHANGE",
                points=24,
            )
        )

    if beneficiary_changes:
        score += 18
        findings.append(
            _finding(
                "HIGH",
                "Beneficiary identity changed",
                "Audit records show a material beneficiary-name change.",
                signal_code="BENEFICIARY_CHANGE",
                points=18,
            )
        )

    if verification_events and (bank_changes or beneficiary_changes):
        score += 14
        findings.append(
            _finding(
                "HIGH",
                "Verification completed around sensitive vendor changes",
                "The audit log records verification completion close to bank/beneficiary changes.",
                signal_code="VERIFICATION_OVERRIDE",
                points=14,
            )
        )

    weak_mfa_event = bool(re.search(r"\bmfa=(?:PASSWORD_ONLY|NONE|DISABLED)\b", text, re.IGNORECASE))
    stronger_policy = bool(re.search(
        r"(?:normal|required|policy).{0,60}mfa.{0,80}(?:authenticator|totp|two[- ]factor|2fa|multi[- ]factor)",
        text,
        re.IGNORECASE,
    ))
    if weak_mfa_event and stronger_policy:
        score += 12
        findings.append(
            _finding(
                "HIGH",
                "Authentication event deviates from stated MFA policy",
                "The evidence records weaker authentication than the policy described in the same artifact.",
                signal_code="MFA_POLICY_DEVIATION",
                points=12,
            )
        )

    if len(approve_amounts) >= 3:
        average = sum(approve_amounts) / len(approve_amounts)
        spread = max(approve_amounts) - min(approve_amounts)
        close_in_value = average > 0 and spread <= average * 0.05
        rapid = False
        if len(approve_times) >= 3:
            approve_times.sort()
            rapid = (approve_times[-1] - approve_times[0]).total_seconds() <= 45 * 60
        if close_in_value:
            score += 10
            detail = f"{len(approve_amounts)} approved payments are tightly clustered around {_format_inr(average)}."
            if rapid:
                detail += " The approvals also occurred within a short time window."
            findings.append(
                _finding(
                    "MEDIUM",
                    "Cluster of similarly sized payment approvals",
                    detail,
                    signal_code="PAYMENT_CLUSTER",
                    points=10,
                    related_amount=sum(approve_amounts),
                )
            )

    sensitive_deletions = [
        line for line in delete_events
        if re.search(r"bank|verification|invoice|payment|audit|attachment|evidence", line, re.IGNORECASE)
    ]
    if sensitive_deletions:
        score += 20
        findings.append(
            _finding(
                "HIGH",
                "Potentially relevant evidence deleted",
                "The audit log records deletion of a file/record related to financial or verification activity.",
                signal_code="EVIDENCE_DELETION",
                points=20,
            )
        )

    if re.search(r"action=.*EXPORT.*(?:AUDIT|LOG|VENDOR|FINANCE)", text, re.IGNORECASE):
        score += 5
        findings.append(
            _finding(
                "MEDIUM",
                "Sensitive audit/finance data exported",
                "The audit trail records an export of potentially relevant administrative or financial data.",
                signal_code="AUDIT_LOG_EXPORT",
                points=5,
            )
        )

    return min(score, 95.0), findings


def _invoice_analysis(text: str, entities: dict[str, list[Any]]) -> tuple[float, list[dict[str, Any]]]:
    score = 0.0
    findings: list[dict[str, Any]] = []
    vendors = [str(v) for v in entities.get("vendors", [])]
    beneficiaries = [str(v) for v in entities.get("beneficiaries", [])]

    if vendors and beneficiaries:
        vendor = vendors[0]
        beneficiary = beneficiaries[0]
        similarity = _company_similarity(vendor, beneficiary)
        if similarity < 0.35:
            score += 68
            findings.append(
                _finding(
                    "HIGH",
                    "Invoice vendor and payment beneficiary mismatch",
                    f"Invoice issuer '{vendor}' differs materially from payment beneficiary '{beneficiary}'.",
                    signal_code="VENDOR_BENEFICIARY_MISMATCH",
                    points=68,
                )
            )

    if entities.get("accounts"):
        findings.append(
            _finding(
                "INFO",
                "Payment account extracted",
                f"Payment instructions reference account ending {entities['accounts'][0]}.",
                signal_code="PAYMENT_ACCOUNT_PRESENT",
                points=0,
            )
        )

    return min(score, 95.0), findings


def _payment_analysis(text: str, entities: dict[str, list[Any]]) -> tuple[float, list[dict[str, Any]]]:
    score = 0.0
    findings: list[dict[str, Any]] = []

    if entities.get("amounts") and entities.get("accounts"):
        score += 18
        findings.append(
            _finding(
                "INFO",
                "Payment transaction details extracted",
                "The document contains both transaction amount and destination-account details.",
                signal_code="PAYMENT_DETAILS_PRESENT",
                points=18,
            )
        )

    vendors = [str(v) for v in entities.get("vendors", [])]
    beneficiaries = [str(v) for v in entities.get("beneficiaries", [])]
    if vendors and beneficiaries and _company_similarity(vendors[0], beneficiaries[0]) < 0.35:
        score += 35
        findings.append(
            _finding(
                "HIGH",
                "Payment beneficiary differs from referenced vendor",
                "The payment record contains materially different vendor and beneficiary identities.",
                signal_code="VENDOR_BENEFICIARY_MISMATCH",
                points=35,
            )
        )

    return min(score, 80.0), findings


def _cyber_analysis(text: str) -> tuple[float, list[dict[str, Any]]]:
    score = 0.0
    findings: list[dict[str, Any]] = []
    for code, pattern in CYBER_PATTERNS.items():
        if pattern.search(text):
            score += 18
            findings.append(
                _finding(
                    "MEDIUM",
                    code.replace("_", " ").title(),
                    "A security-relevant command or execution pattern was detected in the artifact.",
                    signal_code=code,
                    points=18,
                )
            )
    return min(score, 90.0), findings


def _generic_financial_analysis(text: str, entities: dict[str, list[Any]]) -> tuple[float, list[dict[str, Any]]]:
    """Conservative fallback. Entity presence alone does not create high risk."""
    score = 0.0
    findings: list[dict[str, Any]] = []
    threshold = extract_threshold(text)
    amounts = [int(v) for v in entities.get("amounts", []) if isinstance(v, int)]
    if threshold and amounts:
        close = [amount for amount in amounts if threshold * 0.95 <= amount < threshold]
        if len(close) >= 2:
            score += 20
            findings.append(
                _finding(
                    "MEDIUM",
                    "Multiple amounts close to an approval threshold",
                    "Several extracted amounts fall immediately below a stated approval threshold.",
                    signal_code="THRESHOLD_PROXIMITY",
                    points=20,
                )
            )
    return score, findings


def _cumulative_amount_indicators(text: str) -> list[dict[str, str]]:
    indicators: list[dict[str, str]] = []
    patterns = [
        re.compile(
            r"(?:total\s+paid|payments?\s+total(?:ing)?|cumulative\s+(?:amount|value)|grand\s+total)"
            r"[^\d]{0,20}(?:inr|₹|rs\.?)?\s*([\d,]+(?:\.\d{1,2})?)",
            re.IGNORECASE,
        ),
        re.compile(
            r"total\s+order\s+(?:is|was)\s+(?:roughly|approximately|about)?\s*([\d.]+)\s*(lakh|lakhs|lac|lacs|l)\b",
            re.IGNORECASE,
        ),
    ]
    for pattern in patterns:
        for match in pattern.finditer(text):
            value = _parse_amount(match.group(1))
            if value is None:
                continue
            unit = match.group(2).casefold() if match.lastindex and match.lastindex >= 2 and match.group(2) else ""
            if unit in {"lakh", "lakhs", "lac", "lacs", "l"}:
                try:
                    value = int(round(float(match.group(1)) * 100_000))
                except ValueError:
                    continue
            indicators.append({"type": "CUMULATIVE_AMOUNT_INR", "value": str(value)})
    return indicators


def analyze_forensic_content(path: Path, extension: str) -> dict[str, Any]:
    text, extractor, limitations = extract_text(path, extension)
    domain, artifact_type, confidence = classify_artifact(
        text=text,
        extension=extension,
        filename=path.name,
    )

    entities = extract_entities(text, artifact_type) if text else {
        "amounts": [], "accounts": [], "invoice_ids": [], "payment_ids": [],
        "po_ids": [], "vendors": [], "beneficiaries": [], "organizations": [],
        "users": [], "actions": [], "emails": [], "urls": [], "ips": [],
        "timestamps": [], "approval_thresholds": [],
    }

    structured_evidence = build_structured_evidence(
        text=text,
        artifact_type=artifact_type,
        domain=domain,
        entities=entities,
    )

    # ArtifactTriage already persists findings_json. Embedding the structured
    # extraction in the forensic profile therefore preserves it across reloads
    # without requiring a database schema migration.
    profile_finding = _profile_finding(
        domain,
        artifact_type,
        confidence,
        extractor,
    )
    profile_finding["structured_evidence"] = structured_evidence

    findings: list[dict[str, Any]] = [
        profile_finding
    ]

    if artifact_type == "ledger":
        score, domain_findings = _ledger_analysis(text, entities)
        analyzer = "FINANCIAL_LEDGER_FORENSICS"
        method = "Transaction-pattern, threshold and payment-cluster analysis"
    elif artifact_type in {"email", "chat_transcript"}:
        score, domain_findings = _email_analysis(text, entities)
        analyzer = (
            "SEMANTIC_COMMUNICATION_FORENSICS"
            if artifact_type == "email"
            else "COMMUNICATION_TRANSCRIPT_FORENSICS"
        )
        method = "Communication intent, approval-path and verification analysis"
    elif artifact_type == "audit_log":
        score, domain_findings = _audit_analysis(text, entities)
        analyzer = "AUDIT_LOG_FORENSICS"
        method = "Audit-event, field-change and administrative anomaly analysis"
    elif artifact_type == "invoice":
        score, domain_findings = _invoice_analysis(text, entities)
        analyzer = "DOCUMENT_FINANCIAL_FORENSICS"
        method = "Invoice entity, beneficiary and payment-instruction analysis"
    elif artifact_type == "payment_confirmation":
        score, domain_findings = _payment_analysis(text, entities)
        analyzer = "PAYMENT_DOCUMENT_FORENSICS"
        method = "Payment-document entity and beneficiary analysis"
    elif domain == "cyber":
        score, domain_findings = _cyber_analysis(text)
        analyzer = (
            "NETWORK_LOG_FORENSICS"
            if artifact_type == "network_or_server_log"
            else "TEXT_SEMANTIC_CYBER_FORENSICS"
        )
        method = (
            "Network/server event and IOC analysis"
            if artifact_type == "network_or_server_log"
            else "Semantic cyber-artifact and IOC analysis"
        )
    elif domain == "financial":
        score, domain_findings = _generic_financial_analysis(text, entities)
        analyzer = "FINANCIAL_DOCUMENT_FORENSICS"
        method = "Financial entity and contextual anomaly analysis"
    else:
        score, domain_findings = 0.0, []
        analyzer = "SEMANTIC_DOCUMENT_FORENSICS"
        method = "Evidence classification and entity extraction"

    findings.extend(domain_findings)

    # Put artifact-specific facts first. Generic entities remain available
    # afterward as secondary supporting evidence.
    indicators = structured_evidence_to_indicators(
        structured_evidence
    )
    indicators.extend(
        entities_to_indicators(
            entities
        )
    )
    indicators.extend(
        _cumulative_amount_indicators(
            text
        )
    )

    # Remove duplicate indicators created by independent extractors.
    deduped_indicators: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in indicators:
        key = (str(item.get("type", "")).upper(), str(item.get("value", "")).casefold())
        if not key[0] or not key[1] or key in seen:
            continue
        seen.add(key)
        deduped_indicators.append(item)

    if not text.strip():
        confidence = min(confidence, 0.35)

    score = round(min(max(float(score), 0.0), 95.0), 2)
    risk_level = "HIGH RISK" if score >= 65 else "SUSPICIOUS" if score >= 35 else "LOW RISK"

    return {
        "analyzer": analyzer,
        "analysis_method": method,
        "risk_score": score,
        "risk_level": risk_level,
        "domain": domain,
        "artifact_type": artifact_type,
        "confidence": round(confidence, 3),
        "extractor": extractor,
        "text_extracted": bool(text.strip()),
        "structured_evidence": structured_evidence,
        "findings": findings,
        "indicators": deduped_indicators,
        "limitations": " ".join(limitations).strip(),
    }
