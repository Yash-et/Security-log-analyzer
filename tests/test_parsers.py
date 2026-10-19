"""Unit tests for structured and text log parsing."""

import pytest

from security_analyzer.parsers import (
    normalize_severity,
    normalize_timestamp,
    parse_jsonl_line,
    parse_text_log_line,
)


def test_jsonl_event_is_normalized():
    raw = (
        '{"timestamp":"2026-10-18T10:00:00+05:30",'
        '"source_type":"authentication",'
        '"severity":"warning",'
        '"source_ip":"192.0.2.10",'
        '"message":"Failed password for demo"}'
    )

    event = parse_jsonl_line(raw, "test.jsonl", 1)

    assert event.timestamp == "2026-10-18T04:30:00Z"
    assert event.source_type == "authentication"
    assert event.severity == "WARNING"
    assert event.event_type == "AUTH_FAILURE"
    assert event.source_ip == "192.0.2.10"
    assert event.line_number == 1
    assert event.raw_record == raw


def test_jsonl_missing_timestamp_is_rejected():
    raw = '{"message":"Missing timestamp"}'

    with pytest.raises(ValueError, match="Missing timestamp"):
        parse_jsonl_line(raw)


def test_jsonl_requires_object():
    with pytest.raises(ValueError, match="JSON object"):
        parse_jsonl_line('["not", "an", "object"]')


def test_invalid_json_is_rejected():
    with pytest.raises(ValueError, match="Invalid JSON"):
        parse_jsonl_line("not json")


def test_epoch_timestamp_is_converted_to_utc():
    assert normalize_timestamp(1792281600) == "2026-10-18T00:00:00Z"


def test_naive_timestamp_is_assumed_utc():
    assert normalize_timestamp(
        "2026-10-18T10:00:00"
    ) == "2026-10-18T10:00:00Z"


def test_severity_normalization():
    assert normalize_severity("warning") == "WARNING"
    assert normalize_severity("3") == "ERROR"
    assert normalize_severity(None) == "INFO"
    assert normalize_severity("custom-level") == "CUSTOM-LEVEL"


def test_text_authentication_failure_is_parsed():
    raw = (
        "Oct 18 09:00:00 demo-host sshd[1001]: "
        "Failed password for invalid user admin from "
        "192.0.2.10 port 54321 ssh2"
    )

    event = parse_text_log_line(
        raw,
        source_name="auth.log",
        line_number=1,
        reference_year=2026,
    )

    assert event.timestamp == "2026-10-18T09:00:00Z"
    assert event.source_type == "authentication"
    assert event.event_type == "AUTH_FAILURE"
    assert event.source_ip == "192.0.2.10"
    assert event.severity == "ERROR"


def test_text_successful_login_is_classified():
    raw = (
        "Oct 18 09:01:00 demo-host sshd[1003]: "
        "Accepted publickey for demo from 192.0.2.20 "
        "port 54323 ssh2"
    )

    event = parse_text_log_line(
        raw,
        reference_year=2026,
    )

    assert event.event_type == "AUTH_SUCCESS"
    assert event.source_ip == "192.0.2.20"


def test_unrecognized_text_format_is_rejected():
    with pytest.raises(ValueError, match="Unrecognized text log format"):
        parse_text_log_line("this is not a syslog record")


def test_event_ids_are_deterministic():
    raw = (
        '{"timestamp":"2026-10-18T10:00:00Z",'
        '"message":"Synthetic event"}'
    )

    first = parse_jsonl_line(raw, "same.jsonl", 3)
    second = parse_jsonl_line(raw, "same.jsonl", 3)

    assert first.event_id == second.event_id
