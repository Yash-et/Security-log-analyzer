"""Parsers for structured JSONL and syslog-style text logs."""

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any


SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+"
    r"(?P<process>[^:]+):\s*(?P<message>.*)$"
)

IP_PATTERN = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
    r"|(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}"
    r"(?![\w:])"
)

SEVERITY_MAP = {
    "0": "CRITICAL",
    "1": "CRITICAL",
    "2": "CRITICAL",
    "3": "ERROR",
    "4": "WARNING",
    "5": "INFO",
    "6": "INFO",
    "7": "DEBUG",
    "emerg": "CRITICAL",
    "emergency": "CRITICAL",
    "alert": "CRITICAL",
    "crit": "CRITICAL",
    "critical": "CRITICAL",
    "err": "ERROR",
    "error": "ERROR",
    "warn": "WARNING",
    "warning": "WARNING",
    "notice": "INFO",
    "info": "INFO",
    "informational": "INFO",
    "debug": "DEBUG",
}

TIMESTAMP_FIELDS = ("timestamp", "datetime", "time", "@timestamp")
MESSAGE_FIELDS = ("message", "msg")
SEVERITY_FIELDS = ("severity", "level", "priority")
SOURCE_IP_FIELDS = ("source_ip", "src_ip", "ip", "client_ip")
SOURCE_TYPE_FIELDS = ("source_type", "log_type")
EVENT_TYPE_FIELDS = ("event_type", "event", "type")



def normalize_timestamp(value: Any) -> str:
    """Convert a supported timestamp into an ISO 8601 UTC string."""
    if isinstance(value, bool) or value is None:
        raise ValueError("A valid timestamp is required.")

    if isinstance(value, datetime):
        parsed = value
        # Treat naive datetime values as UTC.
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            parsed = parsed.astimezone(timezone.utc)

        return parsed.isoformat().replace("+00:00", "Z")

    if isinstance(value, (int, float)):
        # Accept Unix timestamps expressed in seconds.
        try:
            parsed = datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError("Invalid Unix timestamp.") from exc

        return parsed.isoformat().replace("+00:00", "Z")

    if not isinstance(value, str) or not value.strip():
        raise ValueError("A valid timestamp is required.")

    text = value.strip()

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"Unsupported timestamp format: {text!r}"
        ) from exc

    # Naive timestamps are assumed to be UTC.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def normalize_severity(value: Any) -> str:
    """Normalize common textual or numeric severity values."""
    if value is None:
        return "INFO"

    text = str(value).strip().lower()

    if not text:
        return "INFO"

    if text in SEVERITY_MAP:
        return SEVERITY_MAP[text]

    # Unknown severities should remain visible rather than being discarded.
    return text.upper()


def _first_present(record: dict, fields: tuple[str, ...]) -> Any:
    """Return the first non-empty value found among candidate field names."""
    for field in fields:
        value = record.get(field)
        if value is not None and value != "":
            return value
    return None


def _extract_ip(value: Any) -> str | None:
    """Return a valid IP address, or None when no valid address is present."""
    if value is None:
        return None

    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _find_ip(message: str) -> str | None:
    """Find the first valid IP address in a log message."""
    for candidate in IP_PATTERN.findall(message):
        result = _extract_ip(candidate)
        if result:
            return result
    return None


def _classify_event(message: str) -> str:
    """Classify common event patterns without asserting malicious intent."""
    text = message.lower()

    if (
        "failed password" in text
        or "authentication failure" in text
        or "login failed" in text
        or "failed login" in text
        or "invalid user" in text
    ):
        return "AUTH_FAILURE"

    if (
        "accepted password" in text
        or "accepted publickey" in text
        or "login successful" in text
        or "successful login" in text
    ):
        return "AUTH_SUCCESS"

    if "permission denied" in text or "access denied" in text:
        return "ACCESS_DENIED"

    if "traceback" in text or "exception" in text:
        return "APPLICATION_EXCEPTION"

    if "error" in text:
        return "APPLICATION_ERROR"

    return "GENERAL"


def _stable_event_id(
    source_name: str,
    line_number: int,
    raw_record: str,
) -> str:
    """Create a repeatable identifier for the same source record."""
    material = f"{source_name}\0{line_number}\0{raw_record}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


def _build_event(
    *,
    timestamp: Any,
    source_type: Any,
    severity: Any,
    event_type: Any,
    source_ip: Any,
    message: Any,
    raw_record: str,
    source_name: str,
    line_number: int,
    default_source_type: str,
):
    """Validate and construct a normalized SecurityEvent."""
    from security_analyzer.schemas import SecurityEvent

    if not isinstance(message, str) or not message.strip():
        raise ValueError("A non-empty message is required.")

    normalized_message = message.strip()

    if source_type is None or not str(source_type).strip():
        source_type = default_source_type

    normalized_source_type = str(source_type).strip().lower()

    if normalized_source_type not in {
        "system", "authentication", "application", "unknown"
    }:
        normalized_source_type = "unknown"

    return SecurityEvent(
        event_id=_stable_event_id(source_name, line_number, raw_record),
        timestamp=normalize_timestamp(timestamp),
        source_type=normalized_source_type,
        severity=normalize_severity(severity),
        event_type=(
            str(event_type).strip().upper()
            if event_type is not None and str(event_type).strip()
            else _classify_event(normalized_message)
        ),
        source_ip=_extract_ip(source_ip) or _find_ip(normalized_message),
        message=normalized_message,
        raw_record=raw_record,
        source_name=source_name,
        line_number=line_number,
    )


def parse_jsonl_line(
    raw_line: str,
    source_name: str = "<memory>",
    line_number: int = 1,
) -> "SecurityEvent":
    """Parse one JSON object into a normalized security event."""
    if not raw_line.strip():
        raise ValueError("Empty lines are not log records.")

    try:
        record = json.loads(raw_line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc.msg}") from exc

    if not isinstance(record, dict):
        raise ValueError("Each JSONL record must be a JSON object.")

    timestamp = _first_present(record, TIMESTAMP_FIELDS)
    message = _first_present(record, MESSAGE_FIELDS)

    if timestamp is None:
        raise ValueError("Missing timestamp field.")

    if message is None:
        raise ValueError("Missing message field.")

    return _build_event(
        timestamp=timestamp,
        source_type=_first_present(record, SOURCE_TYPE_FIELDS),
        severity=_first_present(record, SEVERITY_FIELDS),
        event_type=_first_present(record, EVENT_TYPE_FIELDS),
        source_ip=_first_present(record, SOURCE_IP_FIELDS),
        message=message,
        raw_record=raw_line.rstrip("\r\n"),
        source_name=source_name,
        line_number=line_number,
        default_source_type="unknown",
    )


def parse_text_log_line(
    raw_line: str,
    source_name: str = "<memory>",
    line_number: int = 1,
    reference_year: int | None = None,
) -> "SecurityEvent":
    """Parse one syslog-style text record."""
    if not raw_line.strip():
        raise ValueError("Empty lines are not log records.")

    match = SYSLOG_PATTERN.match(raw_line.strip())

    if not match:
        raise ValueError("Unrecognized text log format.")

    year = reference_year or datetime.now(timezone.utc).year
    timestamp_text = f"{match.group('timestamp')} {year}"

    try:
        timestamp = datetime.strptime(
            timestamp_text, "%b %d %H:%M:%S %Y"
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("Invalid syslog timestamp.") from exc

    process = match.group("process").strip()
    message = match.group("message").strip()

    if not message:
        raise ValueError("Missing log message.")

    process_name = re.sub(r"\[\d+\]$", "", process).lower()

    if process_name in {"sshd", "ssh", "login", "sudo", "su", "pam_unix"}:
        source_type = "authentication"
    elif any(
        word in process_name
        for word in ("nginx", "apache", "httpd", "gunicorn", "uvicorn")
    ):
        source_type = "application"
    else:
        source_type = "system"

    text_lower = message.lower()

    if any(word in text_lower for word in ("fatal", "critical", "panic")):
        severity = "CRITICAL"
    elif "error" in text_lower or "failed" in text_lower:
        severity = "ERROR"
    elif "warning" in text_lower or "warn" in text_lower:
        severity = "WARNING"
    else:
        severity = "INFO"

    return _build_event(
        timestamp=timestamp,
        source_type=source_type,
        severity=severity,
        event_type=None,
        source_ip=None,
        message=message,
        raw_record=raw_line.rstrip("\r\n"),
        source_name=source_name,
        line_number=line_number,
        default_source_type=source_type,
    )
