"""Data export helpers for security events and detection alerts."""
from __future__ import annotations
import json
from dataclasses import asdict
from typing import Iterable
import pandas as pd

from security_analyzer.detection import SecurityAlert
from security_analyzer.schemas import SecurityEvent

EVENT_COLUMNS = [
    "event_id",
    "timestamp",
    "source_type",
    "severity",
    "event_type",
    "source_ip",
    "message",
    "raw_record",
    "source_name",
    "line_number",
]

ALERT_COLUMNS = [
    "alert_id",
    "timestamp",
    "rule_id",
    "title",
    "severity",
    "source_ip",
    "description",
    "evidence",
    "event_ids",
    "source_names",
]


def events_to_dataframe(
    events: Iterable[SecurityEvent],
) -> pd.DataFrame:
    """Convert events to a consistently structured DataFrame."""
    records = [asdict(event) for event in events]
    return pd.DataFrame(records, columns=EVENT_COLUMNS)


def alerts_to_dataframe(
    alerts: Iterable[SecurityAlert],
) -> pd.DataFrame:
    """Convert alerts to a DataFrame with CSV-friendly list fields."""
    records = []

    for alert in alerts:
        record = alert.to_dict()

        for field in ("evidence", "event_ids", "source_names"):
            value = record.get(field, [])
            record[field] = " | ".join(str(item) for item in value)

        records.append(record)

    return pd.DataFrame(records, columns=ALERT_COLUMNS)


def events_to_json(
    events: Iterable[SecurityEvent],
    *,
    indent: int = 2,
) -> str:
    """Serialize events to a JSON array."""
    records = [asdict(event) for event in events]
    return json.dumps(records, indent=indent, ensure_ascii=False)


def alerts_to_json(
    alerts: Iterable[SecurityAlert],
    *,
    indent: int = 2,
) -> str:
    """Serialize alerts to a JSON array, preserving list-valued fields."""
    records = [alert.to_dict() for alert in alerts]
    return json.dumps(records, indent=indent, ensure_ascii=False)


def dataframe_to_csv(dataframe: pd.DataFrame) -> str:
    """Serialize a DataFrame to CSV text without an index column."""
    return dataframe.to_csv(index=False, lineterminator="\n")


def events_to_csv(events: Iterable[SecurityEvent]) -> str:
    """Serialize events to CSV text."""
    return dataframe_to_csv(events_to_dataframe(events))


def alerts_to_csv(alerts: Iterable[SecurityAlert]) -> str:
    """Serialize alerts to CSV text."""
    return dataframe_to_csv(alerts_to_dataframe(alerts))
