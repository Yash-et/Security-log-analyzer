# Security Log Analyzer

A local-first, defensive cybersecurity application that parses system and application logs, detects suspicious activity using explainable rules, and presents security findings through an interactive Streamlit dashboard.

The project demonstrates a practical security-log analysis pipeline, from raw log ingestion to normalized events, rule-based detection, and exportable investigation results.

## Features

- **Log ingestion:** Read JSON Lines (`.jsonl`, `.ndjson`) and text-based (`.log`, `.txt`) files.
- **Event normalization:** Standardize timestamps, severity levels, event types, source IP addresses, and supporting metadata.
- **Suspicious activity detection:** Identify repeated authentication failures, successful logins following repeated failures, and bursts of application errors.
- **Explainable alerts:** Show detection rule IDs, severity, descriptions, event references, and supporting evidence.
- **Interactive dashboard:** Explore events and alerts using filters, text search, summary metrics, and charts.
- **Parse-issue reporting:** Identify malformed or unsupported log records instead of silently discarding them.
- **Export support:** Download event and alert data in CSV and JSON formats.
- **Automated testing:** Validate parsing, ingestion, detection, reporting, and project setup with pytest.
- **Synthetic sample data:** Explore the application without needing access to real security logs.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python 3.13 | Core application and analysis logic |
| Streamlit | Interactive dashboard |
| Pandas | Tabular event and alert reporting |
| Plotly | Interactive visualizations |
| Pytest | Automated testing |

## Architecture

The application follows a modular processing pipeline:

```text
Raw Log Files
     |
     v
Ingestion and Parsing
     |
     v
Normalized Security Events
     |
     v
Rule-Based Detection
     |
     v
Explainable Security Alerts
     |
     v
Streamlit Dashboard
     |
     v
CSV / JSON Exports
```

### Core modules

| Module | Responsibility |
|---|---|
| `src/security_analyzer/schemas.py` | Event, parse-issue, and ingestion-result data structures |
| `src/security_analyzer/parsers.py` | Parse log records and normalize event fields |
| `src/security_analyzer/ingestion.py` | Read supported files and collect parsing results and issues |
| `src/security_analyzer/detection.py` | Apply detection rules and generate explainable alerts |
| `src/security_analyzer/reporting.py` | Convert events and alerts into tabular, CSV, and JSON outputs |
| `app.py` | Streamlit dashboard, visualizations, filtering, and downloads |

## Detection Rules

The application currently implements three rule-based detections.

| Rule ID | Detection | Default threshold | Severity |
|---|---|---|---|
| `AUTH-001` | Repeated failed logins from the same source IP | 5 failures within 5 minutes | High |
| `AUTH-002` | Successful login following repeated failures from the same source IP | 5 failures within 5 minutes | High |
| `APP-001` | Burst of application errors from the same source log | 10 errors within 5 minutes | Medium |

Thresholds can be adjusted through the dashboard where supported.

**Important:** These rules identify patterns that may warrant investigation. They do not establish that an account, host, or application has been compromised. Findings should be reviewed in context, alongside other available evidence.

## Project Structure

```text
Security-log-analyzer/
├── app.py
├── data/
│   ├── fixtures/
│   └── samples/
│       ├── events.jsonl
│       ├── auth.log
│       ├── auth_burst.log
│       └── application_errors.jsonl
├── docs/
├── reports/
├── src/
│   └── security_analyzer/
│       ├── __init__.py
│       ├── schemas.py
│       ├── parsers.py
│       ├── ingestion.py
│       ├── detection.py
│       └── reporting.py
├── tests/
│   ├── test_setup.py
│   ├── test_parsers.py
│   ├── test_ingestion.py
│   ├── test_detection.py
│   └── test_reporting.py
├── .gitignore
├── LICENSE
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Installation

### Requirements

- Python 3.13
- pip
- Git (optional, for cloning the repository)

### 1. Clone the repository

```bash
git clone https://github.com/Yash-et/Security-log-analyzer.git
cd Security-log-analyzer
```

Replace the placeholder with your repository's actual GitHub URL.

Alternatively, download or open your existing local repository.

### 2. Create a virtual environment

**Windows PowerShell:**

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell prevents activation, you can invoke the environment's Python directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

**macOS/Linux:**

```bash
python3.13 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

With the virtual environment activated:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Running the Dashboard

From the repository root, run:

```bash
python -m streamlit run app.py
```

Streamlit will display a local URL in the terminal. Open that URL in your browser.

### Using the application

1. Choose **Sample logs** to explore the included synthetic dataset, or select the upload option to analyze supported log files.
2. Review the overview metrics and charts.
3. Open the **Events** tab to search and filter normalized events.
4. Open the **Alerts** tab to filter findings and inspect their evidence.
5. Review the **Parse Issues** tab for malformed or unsupported records.
6. Open the **Exports** tab to download event and alert data as CSV or JSON.

The bundled samples include deliberately malformed records to demonstrate how parse issues are reported.

## Running the Tests

Run the full test suite from the repository root:

```bash
python -m pytest -q
```

The current development baseline is **40 passing tests** across project setup, parsing, ingestion, detection, and reporting.

Compile-check the application and package modules with:

```bash
python -m compileall -q src app.py
```

## Privacy and Responsible Use

- The application is designed for local, defensive log analysis.
- Analyze only logs you own or are authorized to access.
- Review logs for credentials, tokens, personal information, and other sensitive data before importing, sharing, or exporting them.
- The included sample data is synthetic and intended for demonstration and testing.
- Detection is rule-based; false positives and missed detections are possible.
- This project is not a replacement for a production SIEM, endpoint detection platform, or incident-response process.
- Findings should be validated by a qualified reviewer before taking consequential action.

## Current Limitations

- Detection is based on a small set of configurable rules rather than machine-learning models or a threat-intelligence feed.
- Supported input formats and field normalization are limited to the implemented parsers.
- Detection quality depends on the completeness, timestamp consistency, and format of the supplied logs.
- The application has not been presented as a production-hardened or independently security-audited system.

## Roadmap

Potential future improvements include:

- Additional detection rules and configurable rule definitions.
- More log formats and normalization mappings.
- Improved dashboard usability and reporting.
- Additional edge-case and integration tests.
- Optional persistent storage for historical analysis.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
