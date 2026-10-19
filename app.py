"""Streamlit entry point for Security Log Analyzer."""
from __future__ import annotations
import sys
from pathlib import Path
import pandas as pd
import plotly.express as px
import streamlit as st

'Allow running from a repository checkout without installing the package.'
PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from security_analyzer.detection import detect_suspicious_events
from security_analyzer.ingestion import ingest_files
from security_analyzer.reporting import (
    alerts_to_csv,
    alerts_to_dataframe,
    alerts_to_json,
    events_to_csv,
    events_to_dataframe,
    events_to_json,
)

st.set_page_config(
    page_title="Security Log Analyzer",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Security Log Analyzer")
st.caption(
    "Investigate log activity with explainable, rule-based detection. "
    "Alerts are investigation signals, not proof of malicious activity."
)

with st.sidebar:
    st.header("Log sources")
    source_mode = st.radio(
        "Choose input",
        ["Sample logs", "Upload log files"],
    )

    uploaded_files = []
    if source_mode == "Upload log files":
        uploaded_files = st.file_uploader(
            "Select log files",
            type=["jsonl", "ndjson", "log", "txt"],
            accept_multiple_files=True,
            help="Supported: JSONL/NDJSON and supported text log formats.",
        )

    st.divider()
    st.header("Detection settings")
    failed_threshold = st.number_input(
        "Failed login threshold",
        min_value=2,
        max_value=100,
        value=5,
        step=1,
    )
    failed_window = st.number_input(
        "Failed login window (minutes)",
        min_value=1,
        max_value=1440,
        value=5,
        step=1,
    )
    error_threshold = st.number_input(
        "Application error threshold",
        min_value=2,
        max_value=1000,
        value=10,
        step=1,
    )
    error_window = st.number_input(
        "Application error window (minutes)",
        min_value=1,
        max_value=1440,
        value=5,
        step=1,
    )

events = []
parse_issues = []
files_processed = 0
load_error = None

if source_mode == "Sample logs":
    sample_paths = [
        PROJECT_ROOT / "data" / "samples" / "events.jsonl",
        PROJECT_ROOT / "data" / "samples" / "auth.log",
        PROJECT_ROOT / "data" / "samples" / "auth_burst.log",
        PROJECT_ROOT / "data" / "samples" / "application_errors.jsonl",
    ]
    try:
        result = ingest_files(sample_paths, reference_year=2026)
        events = result.events
        parse_issues = result.issues
        files_processed = result.files_processed
    except (OSError, ValueError) as exc:
        load_error = str(exc)

elif uploaded_files:
    # Streamlit uploads are in-memory objects, so write them to a
    # temporary directory before passing paths to the ingestion layer.
    import tempfile

    try:
        with tempfile.TemporaryDirectory(prefix="security-log-") as temp_dir:
            paths = []
            for uploaded in uploaded_files:
                safe_name = Path(uploaded.name).name
                destination = Path(temp_dir) / safe_name
                destination.write_bytes(uploaded.getvalue())
                paths.append(destination)

            result = ingest_files(paths, reference_year=2026)
            events = result.events
            parse_issues = result.issues
            files_processed = result.files_processed
    except (OSError, ValueError) as exc:
        load_error = str(exc)

if load_error:
    st.error(f"Could not load log files: {load_error}")
    st.stop()

if source_mode == "Upload log files" and not uploaded_files:
    st.info("Upload one or more supported log files to begin.")
    st.stop()

try:
    alerts = detect_suspicious_events(
        events,
        failed_login_threshold=int(failed_threshold),
        failed_login_window_minutes=int(failed_window),
        error_burst_threshold=int(error_threshold),
        error_burst_window_minutes=int(error_window),
    )
except (ValueError, TypeError) as exc:
    st.error(f"Detection could not run: {exc}")
    st.stop()

event_df = events_to_dataframe(events)
alert_df = alerts_to_dataframe(alerts)

total_events = len(events)
invalid_count = len(parse_issues)
high_alerts = sum(alert.severity == "HIGH" for alert in alerts)
medium_alerts = sum(alert.severity == "MEDIUM" for alert in alerts)

metric_cols = st.columns(4)
metric_cols[0].metric("Events parsed", total_events)
metric_cols[1].metric("Parse issues", invalid_count)
metric_cols[2].metric("Total alerts", len(alerts))
metric_cols[3].metric("High-severity alerts", high_alerts)

st.caption(
    f"Files processed: {files_processed} · "
    f"Medium-severity alerts: {medium_alerts}"
)

overview_tab, events_tab, alerts_tab, issues_tab, exports_tab = st.tabs(
    ["Overview", "Events", "Alerts", "Parse issues", "Exports"]
)

with overview_tab:
    left, right = st.columns(2)

    with left:
        st.subheader("Event severity")
        if not event_df.empty:
            severity_counts = (
                event_df["severity"]
                .fillna("UNKNOWN")
                .value_counts()
                .rename_axis("Severity")
                .reset_index(name="Count")
            )
            fig = px.bar(
                severity_counts,
                x="Severity",
                y="Count",
                title="Parsed events by severity",
            )
            st.plotly_chart(fig, width="stretch")
        else:
            st.info("No parsed events to chart.")

    with right:
        st.subheader("Alert severity")
        if alerts:
            alert_severity_df = (
                alert_df["severity"]
                .value_counts()
                .rename_axis("Severity")
                .reset_index(name="Count")
            )
            fig = px.pie(
                alert_severity_df,
                names="Severity",
                values="Count",
                title="Detection alerts by severity",
                hole=0.45,
            )
            st.plotly_chart(fig, width="stretch")
        else:
            st.info("No alerts were generated for these events.")

    st.subheader("Events over time")
    if not event_df.empty:
        timeline = event_df.copy()
        timeline["timestamp"] = pd.to_datetime(
            timeline["timestamp"], errors="coerce", utc=True
        )
        timeline = timeline.dropna(subset=["timestamp"])
        if not timeline.empty:
            timeline["Time"] = timeline["timestamp"].dt.floor("min")
            counts = (
                timeline.groupby("Time")
                .size()
                .reset_index(name="Events")
            )
            fig = px.line(
                counts,
                x="Time",
                y="Events",
                markers=True,
                title="Events per minute",
            )
            st.plotly_chart(fig, width="stretch")
        else:
            st.info("No valid timestamps are available for the timeline.")

with events_tab:
    st.subheader("Parsed events")

    if not event_df.empty:
        severity_options = sorted(
            event_df["severity"].fillna("UNKNOWN").unique().tolist()
        )
        selected_severities = st.multiselect(
            "Filter event severity",
            severity_options,
            default=severity_options,
        )
        search_text = st.text_input("Search event messages, IPs, or sources")

        filtered_events = event_df[
            event_df["severity"].fillna("UNKNOWN").isin(selected_severities)
        ].copy()

        if search_text.strip():
            query = search_text.strip()
            searchable = (
                filtered_events["message"].fillna("")
                + " "
                + filtered_events["source_ip"].fillna("")
                + " "
                + filtered_events["source_name"].fillna("")
            )
            filtered_events = filtered_events[
                searchable.str.contains(query, case=False, regex=False)
            ]

        st.caption(f"Showing {len(filtered_events)} of {len(event_df)} events")
        st.dataframe(filtered_events, width="stretch", hide_index=True)
    else:
        filtered_events = event_df
        st.info("No parsed events are available.")

with alerts_tab:
    st.subheader("Detection alerts")

    if not alert_df.empty:
        severities = sorted(alert_df["severity"].unique().tolist())
        rules = sorted(alert_df["rule_id"].unique().tolist())

        selected_alert_severities = st.multiselect(
            "Filter alert severity",
            severities,
            default=severities,
        )
        selected_rules = st.multiselect(
            "Filter detection rule",
            rules,
            default=rules,
        )

        filtered_alerts = alert_df[
            alert_df["severity"].isin(selected_alert_severities)
            & alert_df["rule_id"].isin(selected_rules)
        ].copy()

        st.caption(f"Showing {len(filtered_alerts)} of {len(alert_df)} alerts")
        st.dataframe(filtered_alerts, width="stretch", hide_index=True)

        with st.expander("Inspect alert evidence"):
            alert_ids = filtered_alerts["alert_id"].tolist()
            if alert_ids:
                chosen_id = st.selectbox("Choose an alert", alert_ids)
                chosen = next(
                    alert for alert in alerts if alert.alert_id == chosen_id
                )
                st.write(f"**{chosen.title}** · {chosen.severity}")
                st.write(chosen.description)
                st.write("**Evidence**")
                for item in chosen.evidence:
                    st.write(f"- {item}")
                st.write("**Supporting event IDs**")
                st.code(", ".join(chosen.event_ids))
            else:
                st.info("No alerts match the selected filters.")
    else:
        filtered_alerts = alert_df
        st.info("No alerts were generated.")

with issues_tab:
    st.subheader("Parsing issues")
    if parse_issues:
        issues_df = pd.DataFrame([issue.to_dict() for issue in parse_issues])
        st.dataframe(issues_df, width="stretch", hide_index=True)
        st.warning(
            "Malformed records are shown for review and are not included "
            "in the normalized event dataset."
        )
    else:
        st.success("No parsing issues were found.")

with exports_tab:
    st.subheader("Download results")
    st.write(
        "Downloads respect the filters applied in the Events and Alerts tabs "
        "when those filters have been applied during the current run."
    )

    # Use the current filtered data if available; otherwise export all.
    # Streamlit reruns on widget changes, so initialize safe fallbacks.
    events_export_df = (
        filtered_events if "filtered_events" in locals() else event_df
    )
    alerts_export_df = (
        filtered_alerts if "filtered_alerts" in locals() else alert_df
    )

    event_ids = set(events_export_df["event_id"].tolist())
    events_for_export = [
        event for event in events if event.event_id in event_ids
    ]
    alert_ids = set(alerts_export_df["alert_id"].tolist())
    alerts_for_export = [
        alert for alert in alerts if alert.alert_id in alert_ids
    ]

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Events**")
        st.download_button(
            "Download events CSV",
            data=events_to_csv(events_for_export),
            file_name="security_events.csv",
            mime="text/csv",
            width="stretch",
        )
        st.download_button(
            "Download events JSON",
            data=events_to_json(events_for_export),
            file_name="security_events.json",
            mime="application/json",
            width="stretch",
        )

    with col2:
        st.markdown("**Alerts**")
        st.download_button(
            "Download alerts CSV",
            data=alerts_to_csv(alerts_for_export),
            file_name="security_alerts.csv",
            mime="text/csv",
            width="stretch",
        )
        st.download_button(
            "Download alerts JSON",
            data=alerts_to_json(alerts_for_export),
            file_name="security_alerts.json",
            mime="application/json",
            width="stretch",
        )

st.divider()
st.caption(
    "Security Log Analyzer · Rule-based findings require human review. "
    "A detected pattern is not proof of compromise."
)
