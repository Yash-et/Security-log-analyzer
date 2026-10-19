
"""Integration tests for log file ingestion."""

import json

import pytest

from security_analyzer.ingestion import ingest_file, ingest_files


def test_ingest_jsonl_sample():
    result = ingest_file(
        "data/samples/events.jsonl",
        reference_year=2026,
    )

    assert result.files_processed == 1
    assert len(result.events) == 4
    assert result.invalid_records == 1
    assert result.total_records == 5

    assert result.issues[0].line_number == 4
    assert "Invalid JSON" in result.issues[0].error


def test_ingest_text_sample():
    result = ingest_file(
        "data/samples/auth.log",
        reference_year=2026,
    )

    assert result.files_processed == 1
    assert len(result.events) == 4
    assert result.invalid_records == 1

    assert result.events[0].event_type == "AUTH_FAILURE"
    assert result.events[0].source_ip == "192.0.2.10"
    assert result.issues[0].line_number == 5


def test_empty_lines_are_ignored(tmp_path):
    log_path = tmp_path / "empty_lines.jsonl"

    log_path.write_text(
        '\n{"timestamp":"2026-10-18T10:00:00Z",'
        '"message":"Synthetic event"}\n\n',
        encoding="utf-8",
    )

    result = ingest_file(log_path)

    assert len(result.events) == 1
    assert result.invalid_records == 0
    assert result.total_records == 1


def test_unsupported_extension_is_rejected(tmp_path):
    path = tmp_path / "events.csv"
    path.write_text("timestamp,message\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported log format"):
        ingest_file(path)


def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        ingest_file(tmp_path / "missing.jsonl")


def test_multiple_files_are_combined(tmp_path):
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"

    record = {
        "timestamp": "2026-10-18T10:00:00Z",
        "message": "Synthetic event",
    }

    first.write_text(json.dumps(record) + "\n", encoding="utf-8")
    second.write_text(json.dumps(record) + "\n", encoding="utf-8")

    result = ingest_files([first, second])

    assert result.files_processed == 2
    assert len(result.events) == 2
    assert result.invalid_records == 0


def test_to_dict_provides_exportable_fields():
    result = ingest_file("data/samples/events.jsonl")

    event_data = result.events[0].to_dict()
    issue_data = result.issues[0].to_dict()

    assert "event_id" in event_data
    assert "timestamp" in event_data
    assert "raw_record" in event_data
    assert "line_number" in issue_data
    assert "error" in issue_data
