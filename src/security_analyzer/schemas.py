"""Data structures used throughout the log analysis pipeline."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class SecurityEvent:
    """A single normalized log event."""

    event_id: str
    timestamp: str
    source_type: str
    severity: str
    event_type: str
    source_ip: str | None
    message: str
    raw_record: str
    source_name: str
    line_number: int

    def to_dict(self) -> dict:
        """Return the event as a dictionary suitable for exports."""
        return asdict(self)


@dataclass(frozen=True)
class ParseIssue:
    """Details about a log record that could not be parsed."""

    source_name: str
    line_number: int
    raw_record: str
    error: str

    def to_dict(self) -> dict:
        """Return the parsing issue as a dictionary."""
        return asdict(self)


@dataclass
class IngestionResult:
    """Results from processing one or more log files."""

    events: list[SecurityEvent]
    issues: list[ParseIssue]
    files_processed: int = 0

    @property
    def total_records(self) -> int:
        """Number of valid and invalid non-empty records processed."""
        return len(self.events) + len(self.issues)

    @property
    def invalid_records(self) -> int:
        """Number of records that failed parsing."""
        return len(self.issues)
