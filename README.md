# Phishing Email Analysis and Reporting Tool

This Python program analyzes phishing email reports (provided as JSON) to extract key information, assess risks, and generate comprehensive summaries. It leverages external APIs like VirusTotal and AbuseIPDB for threat intelligence on URLs, file attachments, and sender IP addresses.

## Features

-   **Email Parsing**: Extracts sender, recipient, subject, body, headers, attachments, and URLs from JSON reports.
-   **Header Analysis**: Checks SPF, DKIM, and DMARC authentication results.
-   **IP Analysis**: Determines the likely sender IP address and checks its reputation via AbuseIPDB and WHOIS lookups.
-   **URL Analysis**:
    -   Extracts URLs from headers and body.
    -   Decodes obfuscated URLs (Proofpoint URLDefense, Microsoft SafeLinks).
    -   Resolves URL domains to IP addresses (Geolocation).
    -   Checks URL reputation via VirusTotal.
-   **Attachment Analysis**:
    -   Identifies potentially dangerous file types based on extension.
    -   Checks file hash reputation via VirusTotal.
-   **Reporting**: Generates a concise summary and a detailed markdown report suitable for ticketing systems or documentation.
-   **Clipboard Integration**: Automatically copies the generated summary and detailed report to the clipboard sequentially.
-   **Secure Configuration**: Uses a `.env` file to manage sensitive API keys securely.

## Installation

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/TitaniumKnight1/autophishreport.git
    cd autophishreport
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
    Ensure your virtual environment is active, then install the required packages listed in `requirements.txt`.
    ```bash
    pip install -r requirements.txt
    ```
    *(If `requirements.txt` is not present, you'll need to create it or install manually: `pip install requests pyperclip ipwhois alive_progress ipaddress python-dotenv`)*

## Configuration (API Keys)

This tool requires API keys for VirusTotal and AbuseIPDB to function fully. These keys are managed securely using a `.env` file.

1.  **Run the Setup Script:**
    Execute the provided helper script to create your local `.env` file:
    ```bash
    python create_env.py
    ```
    The script will prompt you to enter your API keys.

2.  **Enter Your Keys:** Paste your actual API keys when prompted. If you leave a key blank, that service's checks will be skipped.

3.  **`.env` File Creation:** The script will create a `.env` file in the project directory containing the keys you entered.

4.  **IMPORTANT - Git Ignore:** This `.env` file contains sensitive credentials and **MUST NOT** be committed to Git. Ensure your project's `.gitignore` file includes the following line:
    ```gitignore
    .env
    ```
    *(This line is usually included in standard Python `.gitignore` templates, but double-check!)*

## Usage

1.  **Activate Virtual Environment** (if you created one):
    ```bash
    # Windows: .\.venv\Scripts\activate
    # macOS/Linux: source .venv/bin/activate
    ```

2.  **Copy Report JSON:** Copy the *entire* JSON content of the phishing report you want to analyze to your clipboard.

3.  **Run the Main Script:**
    ```bash
    python phishing_analyzer.py
    ```

4.  **Follow Prompts:**
    -   The script will process the JSON from your clipboard (or prompt for manual input if the clipboard is empty/invalid).
    -   It will display progress bars during API lookups.
    -   Once processing is complete, it will copy a **short description** to your clipboard. Paste this where needed (e.g., ticket title).
    -   Press **Enter** in the terminal.
    -   It will then copy the **detailed markdown report** to your clipboard. Paste this into the main body of your ticket or notes.
    -   The script will pause until you press Enter again, then exit.

## Contribution / License

-   Feel free to fork, submit issues, and suggest improvements via pull requests.
-   **Note:** Original intent was for use within the TAMUS Cyber Operations Division, but usage is governed by the license.
-   This project is licensed under the MIT License. See the `LICENSE` file for details.


<!-- Security scan triggered at 2025-09-02 00:01:17 -->

<!-- Security scan triggered at 2025-09-09 05:25:28 -->