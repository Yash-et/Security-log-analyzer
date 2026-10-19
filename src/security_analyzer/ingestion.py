"""File ingestion for supported security log formats."""

from pathlib import Path
from typing import Iterable

from security_analyzer.parsers import (
    parse_jsonl_line,
    parse_text_log_line,
)
from security_analyzer.schemas import IngestionResult, ParseIssue


JSON_EXTENSIONS = {".jsonl", ".ndjson"}
TEXT_EXTENSIONS = {".log", ".txt"}


def ingest_file(
    file_path: str | Path,
    reference_year: int | None = None,
) -> IngestionResult:
    """Read and parse a supported log file.

    Empty lines are ignored. Invalid non-empty records are collected as
    ParseIssue objects. The original input file is never modified.
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file does not exist: {path}")

    if not path.is_file():
        raise ValueError(f"Expected a log file, received: {path}")

    suffix = path.suffix.lower()

    if suffix not in JSON_EXTENSIONS | TEXT_EXTENSIONS:
        raise ValueError(
            f"Unsupported log format {suffix!r}. "
            "Supported extensions: .jsonl, .ndjson, .log, .txt"
        )

    events = []
    issues = []

    # utf-8-sig also handles UTF-8 files that contain a BOM.
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            if not raw_line.strip():
                continue

            try:
                if suffix in JSON_EXTENSIONS:
                    event = parse_jsonl_line(
                        raw_line,
                        source_name=path.name,
                        line_number=line_number,
                    )
                else:
                    event = parse_text_log_line(
                        raw_line,
                        source_name=path.name,
                        line_number=line_number,
                        reference_year=reference_year,
                    )

                events.append(event)

            except ValueError as exc:
                issues.append(
                    ParseIssue(
                        source_name=path.name,
                        line_number=line_number,
                        raw_record=raw_line.rstrip("\r\n"),
                        error=str(exc),
                    )
                )

    return IngestionResult(
        events=events,
        issues=issues,
        files_processed=1,
    )


def ingest_files(
    file_paths: Iterable[str | Path],
    reference_year: int | None = None,
) -> IngestionResult:
    """Ingest multiple supported files into a single result."""
    combined = IngestionResult(events=[], issues=[])

    for file_path in file_paths:
        result = ingest_file(
            file_path,
            reference_year=reference_year,
        )
        combined.events.extend(result.events)
        combined.issues.extend(result.issues)
        combined.files_processed += result.files_processed

    return combined
