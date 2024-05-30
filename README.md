Phishing Email Analysis and Reporting Tool
This Python program is designed to analyze phishing email reports and provide detailed insights into the potential threats. The tool processes JSON input from phishing reports, extracts relevant information, and performs checks using the VirusTotal and AbuseIPDB APIs. It generates a comprehensive report highlighting key details such as email sender, subject, body, URLs, attachments, and the sender's IP address. Additionally, it evaluates the threat level of URLs and files by querying VirusTotal, and checks the sender's IP reputation using AbuseIPDB.

Features
Email Analysis: Extracts and analyzes critical fields from phishing email reports.
VirusTotal Integration: Checks URLs and file hashes for malicious activity using the VirusTotal API.
AbuseIPDB Integration: Evaluates the reputation of the sender's IP address using the AbuseIPDB API.
Detailed Reporting: Generates a well-formatted report with all relevant information, ready to be shared or documented.
Clipboard Integration: Automatically copies the generated report to the clipboard for easy access.

Usage
Setup: Ensure you have valid API keys for VirusTotal and AbuseIPDB.
Run the Program: Execute the script and provide JSON input of a phishing report.
Review the Output: The program processes the input and generates a detailed report, which is then copied to the clipboard.

Installation
Clone the repository:
bash
Copy code
git clone https://github.com/yourusername/phishing-email-analysis-tool.git
Navigate to the project directory:
bash
Copy code
cd phishing-email-analysis-tool
Install the required dependencies:
bash
Copy code
pip install -r requirements.txt

Configuration
Replace the placeholder API keys with your actual keys in the script:
python
Copy code
VIRUSTOTAL_API_KEY = 'your_virustotal_api_key'
ABUSEIPDB_API_KEY = 'your_abuseipdb_api_key'

Example
python
Copy code
python phishing_analysis.py
Contributing
Feel free to fork this repository, submit issues, and send pull requests.

License
This project is licensed under the MIT License.
