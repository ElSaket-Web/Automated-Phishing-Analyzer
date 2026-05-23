# Automated Phishing Analyzer & Triage Service

A modular Python-based Security Orchestration, Automation, and Response (SOAR) component designed to automatically ingest unread emails via IMAP, extract critical Indicators of Compromise (IoCs), and enrich them with threat intelligence via the VirusTotal API. The service automatically compiles findings into consumer-ready HTML triage reports for Security Operations Center (SOC) analysts.

## Features

- **Automated Ingestion:** Continuously checks a designated email inbox for unread alerts using `imaplib`.
- **Regex Parsing Engine:** Parses raw email headers and body content to extract IPv4 addresses and URLs automatically.
- **Threat Intelligence Enrichment:** Leverages the VirusTotal API (v3) to determine malicious classifications.
- **URL Base64 Encoding:** Securely handles complex tracking and phishing URLs by dynamically converting them to the required Base64 URL identifiers before scanning.
- **Clean HTML UX Reporting:** Automatically exports beautiful, human-readable triage cards with color-coded safety metrics instead of unformatted JSON terminal outputs.
- **Secure Secret Management:** Separates infrastructure logic from authentication variables using local `.env` environment isolation.

---

## Architecture & File Structure

The project follows a split-module architecture to avoid dense scripts and ensure code maintainability:

```text
├── analyzer.py          # The Core Engine (Regex parser & VirusTotal API loop)
├── main.py              # The Service Controller (IMAP connection, loop, & HTML report generator)
├── .env                 # API keys & passwords (Local only, hidden from version control)
└── .gitignore           # Bouncer configuration preventing accidental credential leaks
```
Configuration & Setup

1. Prerequisites
Ensure you have Python 3.10+ installed along with the required environment wrapper and HTTP library:

**Bash**
```text
pip install python-dotenv requests
```
2. Environment Setup (.env)
Create a .env file in the root directory. Store your infrastructure configurations cleanly without quotation marks:

```text
EMAIL_ACCOUNT=your_test_email@gmail.com
APP_PASSWORD=your_16_character_app_password
IMAP_SERVER=imap.gmail.com
VT_API_KEY=your_virustotal_api_key_here
```
Security Note: Never use your primary email account password. Generate a unique 16-character App Password through your email provider's security settings.

3. Local Ingestion Controls
By default, the controller operates in a safe Read-Only Mode (readonly=True) during triage testing to protect email server status flags. It is pre-configured to slice and analyze the newest incoming unread indicators to manage API traffic effectively.

## Usage
To start the background daemon execution loop, navigate to the project directory and run:

**Bash**
```text
python main.py
```
Upon processing incoming flags, the root directory will automatically populate unique triage web assets structured as:
Threat_Report_YYYYMMDD_HHMMSS.html

Double-click any generated dashboard report file to view the enriched indicator summaries natively inside any standard web browser.
