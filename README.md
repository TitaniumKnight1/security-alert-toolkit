# Security Alert Analysis Toolkit

A comprehensive collection of Python tools for security operations, specifically designed for analyzing and documenting security alerts from various sources including phishing emails, endpoint detection alerts, and multi-alert incidents.

## Overview

This repository contains four main tools:

1. **Phishing Email Analyzer** (`autophishreport.py`) - Analyzes phishing email reports to extract IOCs and generate comprehensive summaries
2. **Single Alert Formatter** (`single_alert_formatter.py`) - Formats individual Elastic endpoint security alerts into investigation reports with AI-powered observation statements
3. **Multi-Alert Formatter** (`multi_alert_formatter.py`) - Consolidates multiple related security alerts into a unified investigation report
4. **Exception List Generator** (`exception_list_generator.py`) - Creates EQL exception rules for Elastic Security from alert data

## Repository Structure

```
security-alert-toolkit/
├── autophishreport.py              # Phishing email analysis tool
├── single_alert_formatter.py       # Format single endpoint alerts (renamed from auto_format_alert_v3.1_no_osint.py)
├── multi_alert_formatter.py        # Consolidate multiple alerts (renamed from multi_auto_format_alert_v3.1_no_osint.py)
├── exception_list_generator.py     # Generate EQL exception rules (formerly exception_list.py)
├── create_env.py                   # Setup script for API keys
├── requirements.txt                # Python dependencies
└── README.md                       # This file
```

---

## Tool 1: Phishing Email Analyzer

Analyzes phishing email reports (provided as JSON) to extract key information, assess risks, and generate comprehensive summaries.

### Features

-   **Email Parsing**: Extracts sender, recipient, subject, body, headers, attachments, and URLs from JSON reports
-   **Header Analysis**: Checks SPF, DKIM, and DMARC authentication results
-   **IP Analysis**: Determines the likely sender IP address and checks its reputation via AbuseIPDB and WHOIS lookups
-   **URL Analysis**:
    -   Extracts URLs from headers and body
    -   Decodes obfuscated URLs (Proofpoint URLDefense, Microsoft SafeLinks)
    -   Resolves URL domains to IP addresses (Geolocation)
    -   Checks URL reputation via VirusTotal
-   **Attachment Analysis**:
    -   Identifies potentially dangerous file types based on extension
    -   Checks file hash reputation via VirusTotal
-   **Reporting**: Generates a concise summary and a detailed markdown report suitable for ticketing systems or documentation
-   **Clipboard Integration**: Automatically copies the generated summary and detailed report to the clipboard sequentially

### Usage

1.  **Copy Report JSON:** Copy the entire JSON content of the phishing report to your clipboard.
2.  **Run the Script:**
    ```bash
    python autophishreport.py
    ```
3.  **Follow Prompts:** The script will process the JSON and copy outputs to clipboard sequentially.

---

## Tool 2: Single Alert Formatter

Formats individual security alerts from Elastic Endpoint Security into comprehensive investigation reports.

### Features

-   **Context Extraction**: Parses alert JSON to extract user, host, process, file, and parent process information
-   **VirusTotal Integration**: Automatically checks file and process hashes against VirusTotal
-   **AI-Powered Observations**: Uses Google Gemini to generate natural-language observation statements (with deterministic fallback)
-   **Execution Chain Analysis**: Builds parent→child→file execution chains with security context
-   **KQL Query Generation**: Creates Kibana Discover queries to find related events
-   **Memory/Shellcode Detection**: Automatically includes call stack information for memory-related alerts
-   **Customer Detection**: Identifies organization from domain/hostname patterns
-   **NPM Activity Detection**: Special handling for Node.js package manager activities

### Usage

1.  **Copy Alert JSON:** Copy a single alert JSON object from Elastic Security to your clipboard.
2.  **Run the Script:**
    ```bash
    python single_alert_formatter.py
    ```
3.  **Follow Prompts:**
    - First output: Observation Statement (copied to clipboard)
    - Press Enter for Investigation Report (copied to clipboard)
    - Press Enter for KQL Discover Query (copied to clipboard)

### Output Format

The tool generates:
1. **Observation Statement**: Concise, natural-language summary following "Actors, Assets, Actions" framework
2. **Investigation Report**: Detailed markdown report with:
   - User Information
   - Process/File Execution Chain
   - Process Information (with VT results and signature status)
   - Parent Process Information
   - Associated File Information (if distinct from process)
   - Call Stack details (for memory/shellcode alerts)
3. **KQL Discover Query**: Ready-to-paste Kibana query for finding related events

---

## Tool 3: Multi-Alert Formatter

Consolidates multiple related security alerts into a unified investigation report.

### Features

-   **Multi-Alert Ingestion**: Accepts JSON objects, arrays, or NDJSON format
-   **Smart Deduplication**: Groups identical processes, parents, files, and chains across alerts
-   **Consolidated Observation**: Generates combined observation statement for all alerts
-   **Frequency Analysis**: Shows how many alerts each indicator appeared in
-   **Host Tracking**: Tracks which hosts each indicator appeared on
-   **Combined KQL Query**: Generates unified Discover query spanning all alerts

### Usage

1.  **Run the Script:**
    ```bash
    python multi_alert_formatter.py
    ```
2.  **Ingest Alerts:** Copy alert JSON to clipboard, press Enter to add it (repeat for each alert)
3.  **Type 'done'** when all alerts are added
4.  **Follow Prompts:**
    - First output: Combined Observation Statement
    - Press Enter for Investigation Report (deduplicated, with counts)
    - Press Enter for Combined KQL Query

### Output Format

The tool generates:
1. **Combined Observation Statement**: Natural-language summary covering all alerts
2. **Consolidated Investigation Report**: Deduplicated entities with:
   - Seen In: Count of alerts containing this indicator
   - Hosts: List of affected hosts (if multiple)
3. **Combined KQL Discover Query**: Time-windowed query for all related events

---

## Tool 4: Exception List Generator

Generates EQL exception rules for Elastic Security to suppress false positive alerts.

### Features

-   **Multi-Alert Context**: Analyzes multiple instances to create robust exceptions
-   **Tiered Logic**:
    - **Tier 1**: Code signature + trusted status + process name + parent name (strongest)
    - **Tier 2**: File hash + process name + parent name (for unsigned binaries)
    - **Tier 3**: Process path patterns + command line matching (for scripts)
-   **AI-Powered Generation**: Uses Google Gemini to analyze alert patterns
-   **Deterministic Fallback**: If AI fails, uses rule-based exception builder
-   **Pattern Generalization**: Automatically strips version numbers and generalizes paths
-   **Safety Checks**: Ensures exceptions include parent process and strong indicators

### Usage

1.  **Run the Script:**
    ```bash
    python exception_list_generator.py
    ```
2.  **Ingest Alerts:** Copy alert JSON to clipboard, press Enter to add it (repeat for multiple alerts)
3.  **Type 'done'** when finished
4.  **Follow Prompts:**
    - First output: Observation Statement with "Duplicate of Case #"
    - Press Enter for Exception List (EQL format, ready to paste)

### Output Format

```
***Recommended Exception List:***

process.code_signature.subject_name IS "Microsoft Corporation"
AND process.code_signature.trusted IS "true"
AND process.name IS "powershell.exe"
AND process.parent.name IS "explorer.exe"
AND rule.name IS "Suspicious PowerShell Execution"
```

---

## Installation

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/TitaniumKnight1/security-alert-toolkit.git
    cd security-alert-toolkit
    ```

2.  **Create a Virtual Environment (Recommended):**
    ```bash
    python -m venv .venv
    # Activate the environment:
    # Windows (Cmd/PowerShell):
    # .\.venv\Scripts\activate
    # macOS/Linux (Bash/Zsh):
    # source .venv/bin/activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Configuration (API Keys)

These tools require API keys for various services:
- **VirusTotal** (required for file/URL reputation checks)
- **AbuseIPDB** (required for IP reputation checks in phishing analyzer)
- **Google Gemini** (required for AI-powered observation statements and exception generation)

API keys are managed securely using a `.env` file.

1.  **Run the Setup Script:**
    ```bash
    python create_env.py
    ```
    The script will prompt you to enter your API keys.

2.  **Enter Your Keys:** Paste your actual API keys when prompted. If you leave a key blank, features requiring that service will be skipped or use fallback methods.

3.  **IMPORTANT - Security:** The `.env` file contains sensitive credentials and **MUST NOT** be committed to Git. This is already configured in `.gitignore`.

### Required API Keys by Tool

| Tool | VirusTotal | AbuseIPDB | Gemini |
|------|------------|-----------|--------|
| Phishing Email Analyzer | ✓ | ✓ | ✗ |
| Single Alert Formatter | ✓ | ✗ | ✓ (optional) |
| Multi-Alert Formatter | ✓ | ✗ | ✓ (optional) |
| Exception List Generator | ✗ | ✗ | ✓ (required) |

*Note: When Gemini API is not available, alert formatters will use deterministic fallback methods for observation statements.*

---

## Best Practices

### Alert Formatting Workflow

1. **Single Alert Investigation:**
   - Use `single_alert_formatter.py` for initial triage
   - Copy observation statement to ticket title
   - Copy investigation report to ticket body
   - Use KQL query to search for related activity

2. **Multiple Related Alerts:**
   - Use `multi_alert_formatter.py` when investigating clusters
   - Ingest all related alerts before generating output
   - Review deduplicated indicators for patterns
   - Use combined KQL query for comprehensive searching

3. **Creating Exceptions:**
   - Gather 2-5 confirmed false positive alerts of the same type
   - Use `exception_list_generator.py` to create robust exceptions
   - Review generated exception before deploying
   - Test exception in non-production environment first

### Tips

- **Customer Patterns**: Add new customer domain patterns to `extract_customer_info()` function in alert formatters
- **LOLBin Detection**: The exception generator automatically requires command-line scoping for system tools
- **VT Caching**: Hash lookups are cached within a session to avoid rate limits
- **Clipboard Workflow**: All tools use sequential clipboard copying - paste after each prompt

---

## Troubleshooting

### Common Issues

**"Clipboard is empty" error:**
- Ensure JSON is copied before running the script
- Try copying again if clipboard access fails

**"No text generated" from Gemini:**
- Check API key is valid and has quota remaining
- Tools will automatically use deterministic fallbacks

**"VT Rate Limit" messages:**
- Free tier limits to 4 requests/minute
- Script includes automatic 5-second retry delays

**Exception too broad:**
- Add more sample alerts (5+ recommended for patterns)
- Manually review and tighten generated exceptions
- Ensure parent process is included in conditions

---

## Contributing

-   Feel free to fork, submit issues, and suggest improvements via pull requests.
-   **Note:** Originally developed for TAMUS Cyber Operations Division
-   This project is licensed under the MIT License. See the `LICENSE` file for details.

## Suggested Repository Names

Consider renaming the repository to one of:
- `security-alert-toolkit` (recommended)
- `elastic-alert-analyzer`
- `security-ops-toolkit`
- `alert-investigation-tools`
- `soc-analyst-toolkit`
