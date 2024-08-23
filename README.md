# Phishing Email Analysis and Reporting Tool

This Python program is designed to analyze phishing email reports and provide detailed insights into potential threats. The tool processes JSON input from phishing reports, extracts relevant information, and performs checks using VirusTotal and AbuseIPDB APIs. It generates a comprehensive report highlighting key details such as the email sender, subject, body, URLs, attachments, and the sender's IP address. Additionally, it evaluates the threat level of URLs and files by querying VirusTotal and checks the sender's IP reputation using AbuseIPDB.

## Features
- **Email Analysis**: Extracts and analyzes critical fields from phishing email reports.
- **SPF, DKIM, and DMARC Checks**: Verifies email authentication results to assess the legitimacy of the email.
- **URL Deobfuscation**: Decodes and analyzes obfuscated URLs, including SafeLinks, to reveal the true destination.
- **VirusTotal Integration**: Checks URLs and file hashes for malicious activity using the VirusTotal API.
- **AbuseIPDB Integration**: Evaluates the reputation of the sender's IP address using the AbuseIPDB API.
- **File Type Identification**: Identifies and flags potentially dangerous file types in attachments.
- **Detailed Reporting**: Generates a well-formatted report with all relevant information, ready to be shared or documented.
- **Clipboard Integration**: Automatically copies the generated report to the clipboard for easy access.

## Usage
1. **Setup**: Ensure you have valid API keys for VirusTotal and AbuseIPDB.
2. **Run the Program**: Execute the script and provide JSON input of a phishing report. The input can be pasted from the clipboard or entered manually.
3. **Review the Output**: The program processes the input and generates a detailed report, which is then copied to the clipboard for easy sharing.

## Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/phishing-email-analysis-tool.git
    ```
2. Navigate to the project directory:
    ```bash
    cd phishing-email-analysis-tool
    ```
3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Configuration
Replace the placeholder API keys with your actual keys in the script:
```python
VIRUSTOTAL_API_KEY = 'your_virustotal_api_key'
ABUSEIPDB_API_KEY = 'your_abuseipdb_api_key'
```

## Example
```python
python autophishreport.py
```

# Contribution / License
- Feel free to fork this repository, submit issues, and send pull requests.
- This is only for use within the TAMUS Cyber Operations Division.
- This project is licensed under the MIT License
