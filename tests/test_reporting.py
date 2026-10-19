import csv
import io
import json
from datetime import datetime, timedelta, timezone
from security_analyzer.detection import detect_suspicious_events
from security_analyzer.reporting import (
    ALERT_COLUMNS,
    EVENT_COLUMNS,
    alerts_to_csv,
    alerts_to_dataframe,
    alerts_to_json,
    dataframe_to_csv,
    events_to_csv,
    events_to_dataframe,
    events_to_json,
)
from security_analyzer.schemas import SecurityEvent
BASE_TIME = datetime(2026, 10, 18, 9, 0, tzinfo=timezone.utc)

def make_event(index, *, event_type="AUTH_FAILURE", source_ip="192.0.2.10"):
    timestamp = BASE_TIME + timedelta(seconds=index * 30)
    message = "Failed password"

    return SecurityEvent(
        event_id=f"event-{index}",
        timestamp=timestamp.isoformat().replace("+00:00", "Z"),
        source_type="system",
        severity="WARNING",
        event_type=event_type,
        source_ip=source_ip,
        message=message,
        raw_record=message,
        source_name="auth.log",
        line_number=index + 1,
    )

def make_alerts():
    events = [make_event(index) for index in range(5)]
    return detect_suspicious_events(events)

def test_events_dataframe_has_expected_columns():
    dataframe = events_to_dataframe([make_event(0)])

    assert list(dataframe.columns) == EVENT_COLUMNS
    assert len(dataframe) == 1
    assert dataframe.loc[0, "event_id"] == "event-0"

def test_empty_events_dataframe_keeps_expected_columns():
    dataframe = events_to_dataframe([])

    assert list(dataframe.columns) == EVENT_COLUMNS
    assert dataframe.empty

def test_alerts_dataframe_has_expected_columns():
    alerts = make_alerts()
    dataframe = alerts_to_dataframe(alerts)

    assert list(dataframe.columns) == ALERT_COLUMNS
    assert not dataframe.empty
    assert dataframe.loc[0, "alert_id"]

def test_empty_alerts_dataframe_keeps_expected_columns():
    dataframe = alerts_to_dataframe([])

    assert list(dataframe.columns) == ALERT_COLUMNS
    assert dataframe.empty

def test_events_json_preserves_event_fields():
    payload = json.loads(events_to_json([make_event(0)]))

    assert len(payload) == 1
    assert payload[0]["event_id"] == "event-0"
    assert payload[0]["source_ip"] == "192.0.2.10"
    assert payload[0]["line_number"] == 1

def test_alerts_json_preserves_evidence_as_arrays():
    alerts = make_alerts()
    payload = json.loads(alerts_to_json(alerts))

    assert payload
    assert isinstance(payload[0]["evidence"], list)
    assert isinstance(payload[0]["event_ids"], list)
    assert isinstance(payload[0]["source_names"], list)

def test_events_csv_has_headers_and_no_index_column():
    csv_text = events_to_csv([make_event(0)])
    rows = list(csv.DictReader(io.StringIO(csv_text)))

    assert rows
    assert "event_id" in rows[0]
    assert "source_ip" in rows[0]
    assert "Unnamed: 0" not in rows[0]

def test_alerts_csv_contains_readable_evidence():
    csv_text = alerts_to_csv(make_alerts())
    rows = list(csv.DictReader(io.StringIO(csv_text)))

    assert rows
    assert rows[0]["rule_id"] == "AUTH-001"
    assert "Failed password" in rows[0]["evidence"]
    assert "event-0" in rows[0]["event_ids"]

def test_empty_exports_keep_headers():
    event_csv = events_to_csv([])
    alert_csv = alerts_to_csv([])

    assert next(csv.reader(io.StringIO(event_csv))) == EVENT_COLUMNS
    assert next(csv.reader(io.StringIO(alert_csv))) == ALERT_COLUMNS

    assert json.loads(events_to_json([])) == []
    assert json.loads(alerts_to_json([])) == []

def test_dataframe_to_csv_does_not_export_index():
    import pandas as pd

    dataframe = pd.DataFrame(
        [{"rule_id": "AUTH-001", "count": 5}]
    )

    csv_text = dataframe_to_csv(dataframe)
    rows = list(csv.reader(io.StringIO(csv_text)))

    assert rows[0] == ["rule_id", "count"]
    assert rows[1] == ["AUTH-001", "5"]