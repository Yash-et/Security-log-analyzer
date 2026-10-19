from datetime import datetime, timedelta, timezone
import pytest
from security_analyzer.detection import detect_suspicious_events
from security_analyzer.schemas import SecurityEvent

BASE_TIME = datetime(2026, 10, 18, 9, 0, tzinfo=timezone.utc)

def make_event(
    index,
    *,
    minutes=0,
    seconds=0,
    event_type="INFO",
    severity="INFO",
    source_ip=None,
    source_name="test.log",
    message="Test event",
):
    timestamp = BASE_TIME + timedelta(minutes=minutes, seconds=seconds)

    return SecurityEvent(
        event_id=f"event-{index}",
        timestamp=timestamp.isoformat().replace("+00:00", "Z"),
        source_type="application",
        severity=severity,
        event_type=event_type,
        source_ip=source_ip,
        message=message,
        raw_record=message,
        source_name=source_name,
        line_number=index,
    )


def test_repeated_failed_logins_raise_alert():
    events = [
        make_event(
            i,
            seconds=i * 30,
            event_type="AUTH_FAILURE",
            severity="WARNING",
            source_ip="192.0.2.10",
            message="Failed password",
        )
        for i in range(5)
    ]

    alerts = detect_suspicious_events(events)

    auth_alerts = [
        alert for alert in alerts if alert.rule_id == "AUTH-001"
    ]

    assert len(auth_alerts) == 1
    assert auth_alerts[0].severity == "HIGH"
    assert auth_alerts[0].source_ip == "192.0.2.10"
    assert "5 failed authentication attempts" in auth_alerts[0].description
    assert len(auth_alerts[0].event_ids) == 5
    assert auth_alerts[0].evidence


def test_below_failed_login_threshold_does_not_alert():
    events = [
        make_event(
            i,
            seconds=i * 30,
            event_type="AUTH_FAILURE",
            severity="WARNING",
            source_ip="192.0.2.10",
        )
        for i in range(4)
    ]

    alerts = detect_suspicious_events(events)

    assert not any(alert.rule_id == "AUTH-001" for alert in alerts)


def test_failed_logins_outside_window_do_not_trigger_alert():
    events = [
        make_event(
            i,
            minutes=i * 2,
            event_type="AUTH_FAILURE",
            severity="WARNING",
            source_ip="192.0.2.10",
        )
        for i in range(5)
    ]

    alerts = detect_suspicious_events(events)

    assert not any(alert.rule_id == "AUTH-001" for alert in alerts)


def test_success_after_repeated_failures_raises_alert():
    events = [
        make_event(
            i,
            seconds=i * 20,
            event_type="AUTH_FAILURE",
            severity="WARNING",
            source_ip="192.0.2.10",
            message="Failed password",
        )
        for i in range(5)
    ]

    events.append(
        make_event(
            6,
            minutes=2,
            event_type="AUTH_SUCCESS",
            severity="INFO",
            source_ip="192.0.2.10",
            message="Accepted password",
        )
    )

    alerts = detect_suspicious_events(events)

    success_alerts = [
        alert for alert in alerts if alert.rule_id == "AUTH-002"
    ]

    assert len(success_alerts) == 1
    assert success_alerts[0].source_ip == "192.0.2.10"
    assert "successful login" in success_alerts[0].description.lower()
    assert "Accepted password" in " ".join(success_alerts[0].evidence)


def test_success_without_enough_prior_failures_does_not_alert():
    events = [
        make_event(
            i,
            seconds=i * 20,
            event_type="AUTH_FAILURE",
            severity="WARNING",
            source_ip="192.0.2.10",
        )
        for i in range(3)
    ]

    events.append(
        make_event(
            4,
            minutes=2,
            event_type="AUTH_SUCCESS",
            severity="INFO",
            source_ip="192.0.2.10",
        )
    )

    alerts = detect_suspicious_events(events)

    assert not any(alert.rule_id == "AUTH-002" for alert in alerts)


def test_application_error_burst_raises_alert():
    events = [
        make_event(
            i,
            seconds=i * 10,
            event_type="APPLICATION_ERROR",
            severity="ERROR",
            source_name="application.log",
            message=f"Database timeout {i}",
        )
        for i in range(10)
    ]

    alerts = detect_suspicious_events(events)

    error_alerts = [
        alert for alert in alerts if alert.rule_id == "APP-001"
    ]

    assert error_alerts
    assert error_alerts[0].severity == "MEDIUM"
    assert error_alerts[0].source_names == ("application.log",)
    assert error_alerts[0].evidence
    assert "application.log" in error_alerts[0].description


def test_authentication_failures_are_not_application_errors():
    events = [
        make_event(
            i,
            seconds=i * 10,
            event_type="AUTH_FAILURE",
            severity="ERROR",
            source_ip="192.0.2.10",
            message="Failed login",
        )
        for i in range(10)
    ]

    alerts = detect_suspicious_events(
        events,
        failed_login_threshold=20,
    )

    assert not any(alert.rule_id == "APP-001" for alert in alerts)


def test_alert_ids_are_deterministic():
    events = [
        make_event(
            i,
            seconds=i * 30,
            event_type="AUTH_FAILURE",
            severity="WARNING",
            source_ip="192.0.2.10",
        )
        for i in range(5)
    ]

    first = detect_suspicious_events(events)
    second = detect_suspicious_events(events)

    assert [a.alert_id for a in first] == [a.alert_id for a in second]


def test_invalid_thresholds_are_rejected():
    with pytest.raises(ValueError, match="at least 2"):
        detect_suspicious_events([], failed_login_threshold=1)

    with pytest.raises(ValueError, match="positive"):
        detect_suspicious_events([], error_burst_window_minutes=0)


def test_alert_can_be_converted_to_exportable_dictionary():
    events = [
        make_event(
            i,
            seconds=i * 30,
            event_type="AUTH_FAILURE",
            severity="WARNING",
            source_ip="192.0.2.10",
        )
        for i in range(5)
    ]

    alert = detect_suspicious_events(events)[0]
    result = alert.to_dict()

    assert isinstance(result, dict)
    assert result["alert_id"] == alert.alert_id
    assert isinstance(result["evidence"], list)
    assert isinstance(result["event_ids"], list)
    assert isinstance(result["source_names"], list)
