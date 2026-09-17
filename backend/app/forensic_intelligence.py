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

    findings: list[dict[str, Any]] = [
        _profile_finding(domain, artifact_type, confidence, extractor)
    ]

    if artifact_type == "ledger":
        score, domain_findings = _ledger_analysis(text, entities)
        analyzer = "FINANCIAL_LEDGER_FORENSICS"
        method = "Transaction-pattern, threshold and payment-cluster analysis"
    elif artifact_type == "email":
        score, domain_findings = _email_analysis(text, entities)
        analyzer = "SEMANTIC_COMMUNICATION_FORENSICS"
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
        analyzer = "TEXT_SEMANTIC_CYBER_FORENSICS"
        method = "Semantic cyber-artifact and IOC analysis"
    elif domain == "financial":
        score, domain_findings = _generic_financial_analysis(text, entities)
        analyzer = "FINANCIAL_DOCUMENT_FORENSICS"
        method = "Financial entity and contextual anomaly analysis"
    else:
        score, domain_findings = 0.0, []
        analyzer = "SEMANTIC_DOCUMENT_FORENSICS"
        method = "Evidence classification and entity extraction"

    findings.extend(domain_findings)
    indicators = entities_to_indicators(entities)
    indicators.extend(_cumulative_amount_indicators(text))

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
        "findings": findings,
        "indicators": deduped_indicators,
        "limitations": " ".join(limitations).strip(),
    }
