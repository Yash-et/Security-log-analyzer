"""Explainable, rule-based security event detection."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from security_analyzer.schemas import SecurityEvent


@dataclass(frozen=True)
class SecurityAlert:
    """A security finding with evidence explaining why it was raised."""

    alert_id: str
    timestamp: str
    rule_id: str
    title: str
    severity: str
    source_ip: str | None
    description: str
    evidence: tuple[str, ...]
    event_ids: tuple[str, ...]
    source_names: tuple[str, ...]

    def to_dict(self) -> dict:
        """Return a JSON/CSV-friendly representation."""
        result = asdict(self)
        result["evidence"] = list(self.evidence)
        result["event_ids"] = list(self.event_ids)
        result["source_names"] = list(self.source_names)
        return result


def _parse_timestamp(value: str) -> datetime:
    """Parse a normalized timestamp into a timezone-aware datetime."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _event_time(event: SecurityEvent) -> datetime:
    return _parse_timestamp(event.timestamp)


def _stable_alert_id(rule_id: str, event_ids: Iterable[str]) -> str:
    """Create a deterministic ID from a rule and its supporting events."""
    content = f"{rule_id}|{'|'.join(sorted(event_ids))}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def _make_alert(
    *,
    rule_id: str,
    timestamp: datetime,
    title: str,
    severity: str,
    source_ip: str | None,
    description: str,
    evidence: list[str],
    events: list[SecurityEvent],
) -> SecurityAlert:
    return SecurityAlert(
        alert_id=_stable_alert_id(
            rule_id, (event.event_id for event in events)
        ),
        timestamp=timestamp.astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        rule_id=rule_id,
        title=title,
        severity=severity,
        source_ip=source_ip,
        description=description,
        evidence=tuple(evidence),
        event_ids=tuple(event.event_id for event in events),
        source_names=tuple(sorted({event.source_name for event in events})),
    )


def _is_auth_failure(event: SecurityEvent) -> bool:
    return event.event_type.upper() in {
        "AUTH_FAILURE",
        "AUTH_FAILED",
        "LOGIN_FAILURE",
        "FAILED_LOGIN",
    }


def _is_auth_success(event: SecurityEvent) -> bool:
    return event.event_type.upper() in {
        "AUTH_SUCCESS",
        "LOGIN_SUCCESS",
        "SUCCESSFUL_LOGIN",
    }


def _is_application_error(event: SecurityEvent) -> bool:
    """Exclude authentication events from application error analysis."""
    if _is_auth_failure(event) or _is_auth_success(event):
        return False

    severity = event.severity.upper()
    event_type = event.event_type.upper()

    return (
        severity in {"ERROR", "CRITICAL", "FATAL"}
        or "ERROR" in event_type
        or "EXCEPTION" in event_type
    )


def _within_window(
    earlier: datetime,
    later: datetime,
    window: timedelta,
) -> bool:
    difference = later - earlier
    return timedelta(0) <= difference <= window


def detect_suspicious_events(
    events: Iterable[SecurityEvent],
    *,
    failed_login_threshold: int = 5,
    failed_login_window_minutes: int = 5,
    error_burst_threshold: int = 10,
    error_burst_window_minutes: int = 5,
) -> list[SecurityAlert]:
    """
    Run explainable detection rules against normalized events.

    Rules:
    - AUTH-001: repeated failed logins from one IP.
    - AUTH-002: successful login following repeated failures from one IP.
    - APP-001: application error burst from one log source.

    Events without a usable timestamp or source IP are not used by rules
    that require those fields. Invalid configuration raises ValueError.
    """
    if failed_login_threshold < 2:
        raise ValueError("failed_login_threshold must be at least 2.")

    if failed_login_window_minutes < 1:
        raise ValueError("failed_login_window_minutes must be positive.")

    if error_burst_threshold < 2:
        raise ValueError("error_burst_threshold must be at least 2.")

    if error_burst_window_minutes < 1:
        raise ValueError("error_burst_window_minutes must be positive.")

    ordered_events = sorted(
        events,
        key=lambda event: (_event_time(event), event.event_id),
    )

    alerts: list[SecurityAlert] = []

    failures_by_ip: dict[str, list[SecurityEvent]] = defaultdict(list)
    successes_by_ip: dict[str, list[SecurityEvent]] = defaultdict(list)

    for event in ordered_events:
        if not event.source_ip:
            continue

        if _is_auth_failure(event):
            failures_by_ip[event.source_ip].append(event)
        elif _is_auth_success(event):
            successes_by_ip[event.source_ip].append(event)

    failure_window = timedelta(minutes=failed_login_window_minutes)

    # AUTH-001: One alert per IP when its first threshold-sized window
    # is reached. This avoids producing a separate alert for every event
    # in the same ongoing burst.
    for source_ip, failures in failures_by_ip.items():
        reported = False

        for end_index, current in enumerate(failures):
            current_time = _event_time(current)
            window_events = [
                event
                for event in failures[: end_index + 1]
                if _within_window(
                    _event_time(event), current_time, failure_window
                )
            ]

            if len(window_events) >= failed_login_threshold:
                if not reported:
                    selected = window_events[-failed_login_threshold:]
                    alerts.append(
                        _make_alert(
                            rule_id="AUTH-001",
                            timestamp=current_time,
                            title="Repeated failed logins",
                            severity="HIGH",
                            source_ip=source_ip,
                            description=(
                                f"{len(selected)} failed authentication "
                                f"attempts from {source_ip} occurred within "
                                f"{failed_login_window_minutes} minutes."
                            ),
                            evidence=[
                                f"Failed login count: {len(selected)}",
                                (
                                    "Observation window: "
                                    f"{failed_login_window_minutes} minutes"
                                ),
                                *[
                                    f"{event.timestamp}: {event.message}"
                                    for event in selected
                                ],
                            ],
                            events=selected,
                        )
                    )
                    reported = True

    # AUTH-002: Successful login after the configured number of failures
    # from the same IP within the look-back window.
    for source_ip, successes in successes_by_ip.items():
        failures = failures_by_ip.get(source_ip, [])

        for success in successes:
            success_time = _event_time(success)
            preceding_failures = [
                event
                for event in failures
                if _within_window(
                    _event_time(event), success_time, failure_window
                )
            ]

            if len(preceding_failures) >= failed_login_threshold:
                selected = preceding_failures[-failed_login_threshold:]
                related_events = [*selected, success]

                alerts.append(
                    _make_alert(
                        rule_id="AUTH-002",
                        timestamp=success_time,
                        title="Successful login after repeated failures",
                        severity="HIGH",
                        source_ip=source_ip,
                        description=(
                            f"A successful login from {source_ip} followed "
                            f"{len(selected)} failed attempts within "
                            f"{failed_login_window_minutes} minutes. "
                            "Review whether the activity was expected."
                        ),
                        evidence=[
                            f"Preceding failed login count: {len(selected)}",
                            f"Successful login: {success.timestamp}",
                            *[
                                f"{event.timestamp}: {event.message}"
                                for event in selected
                            ],
                            f"{success.timestamp}: {success.message}",
                        ],
                        events=related_events,
                    )
                )

    # APP-001: Group application errors by source log, not IP. Many
    # application errors have no source IP, but still need to be detected.
    errors_by_source: dict[str, list[SecurityEvent]] = defaultdict(list)

    for event in ordered_events:
        if _is_application_error(event):
            errors_by_source[event.source_name].append(event)

    error_window = timedelta(minutes=error_burst_window_minutes)

    for source_name, errors in errors_by_source.items():
        reported_windows: set[tuple[str, ...]] = set()

        for end_index, current in enumerate(errors):
            current_time = _event_time(current)
            window_events = [
                event
                for event in errors[: end_index + 1]
                if _within_window(
                    _event_time(event), current_time, error_window
                )
            ]

            if len(window_events) < error_burst_threshold:
                continue

            selected = window_events[-error_burst_threshold:]
            signature = tuple(event.event_id for event in selected)

            if signature in reported_windows:
                continue

            reported_windows.add(signature)

            alerts.append(
                _make_alert(
                    rule_id="APP-001",
                    timestamp=current_time,
                    title="Application error burst",
                    severity="MEDIUM",
                    source_ip=None,
                    description=(
                        f"{len(selected)} application errors were recorded "
                        f"in {source_name} within "
                        f"{error_burst_window_minutes} minutes. "
                        "This may indicate an application fault or service "
                        "instability and should be investigated."
                    ),
                    evidence=[
                        f"Application error count: {len(selected)}",
                        f"Log source: {source_name}",
                        (
                            "Observation window: "
                            f"{error_burst_window_minutes} minutes"
                        ),
                        *[
                            f"{event.timestamp}: {event.message}"
                            for event in selected
                        ],
                    ],
                    events=selected,
                )
            )

    # Stable ordering makes tests and exported reports reproducible.
    alerts.sort(key=lambda alert: (alert.timestamp, alert.rule_id, alert.alert_id))
    return alerts
