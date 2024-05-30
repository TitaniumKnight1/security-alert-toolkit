import requests
import json
import base64
import time
from urllib.parse import urlparse
import pyperclip
import re

# API keys
VIRUSTOTAL_API_KEY = 'your_virustotal_api_key'
ABUSEIPDB_API_KEY = 'your_abuseipdb_api_key'

# Function to convert URL to URL-safe base64 format
def url_to_base64(url):
    url_bytes = url.encode('utf-8')
    base64_bytes = base64.urlsafe_b64encode(url_bytes)
    base64_string = base64_bytes.decode('utf-8')
    return base64_string.rstrip('=')

# Function to query VirusTotal for a URL
def query_virustotal(url):
    url_id = url_to_base64(url)
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers)
    return response.json()

# Function to check file hash on VirusTotal
def check_file_hash(hash_value):
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(f'https://www.virustotal.com/api/v3/files/{hash_value}', headers=headers)
    return response.json()

# Function to check IP on AbuseIPDB
def check_ip_abuseipdb(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90',
        'verbose': ''
    }
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    response = requests.get(url, headers=headers, params=querystring)
    return response.json()

# Function to extract a valid email from a given string
def extract_email(email_str):
    match = re.search(r'<(.+?)>', email_str)
    if match:
        return match.group(1)
    if re.match(r"[^@]+@[^@]+\.[^@]+", email_str):
        return email_str
    return 'N/A'

# Function to extract IP from Authentication-Results header
def extract_ip_from_auth_results(auth_results):
    match = re.search(r'sender IP is (\d+\.\d+\.\d+\.\d+)', auth_results)
    if match:
        return match.group(1)
    return 'N/A'

# Function to process the JSON input
def process_phishing_report(report):
    to = extract_email(report.get('fields').get('email.reporter', ['N/A'])[0])
    from_address = extract_email(report.get('fields').get('email.from.address', ['N/A'])[0])
    reply_to = extract_email(report.get('fields').get('email.headers.Reply-To', ['N/A'])[0]) if 'email.headers.Reply-To' in report.get('fields') else 'N/A'
    subject = report.get('fields').get('email.subject.text', ['N/A'])[0]
    body = report.get('fields').get('email.body_plaintext', ['N/A'])[0].replace('\n', ' ').replace('\r', '').strip()
    urls = report.get('fields').get('email.urls.data', [])
    attachments = report.get('fields').get('email.attachments', [])
    auth_results = report.get('fields').get('email.headers.Authentication-Results', ['N/A'])[0]
    
    # Extract and check sender IP
    sender_ip = extract_ip_from_auth_results(auth_results)
    abuseipdb_result = check_ip_abuseipdb(sender_ip)
    
    # Remove duplicate URLs
    urls = list(set(urls))

    # Query VirusTotal for URLs
    virustotal_url_results = {}
    for url in urls:
        virustotal_url_results[url] = query_virustotal(url)
        time.sleep(15)  # Sleep to respect the rate limit

    # Check file hashes on VirusTotal
    virustotal_file_results = {}
    for attachment in attachments:
        for file_hash in attachment.get('file.hash.sha256', []):
            virustotal_file_results[file_hash] = check_file_hash(file_hash)

    # Prepare the output in the required format
    virustotal_url_links = []
    for url, result in virustotal_url_results.items():
        domain = urlparse(url).netloc
        if 'data' in result and 'id' in result['data']:
            analysis_url = f"`{domain}`: [VirusTotal](https://www.virustotal.com/gui/url/{result['data']['id']}/detection)"
        else:
            analysis_url = f"`{domain}`: No VT Results"
        virustotal_url_links.append(analysis_url)

    virustotal_file_links = []
    for attachment in attachments:
        for file_hash in attachment.get('file.hash.sha256', []):
            file_name = attachment.get('file.name', ['unknown'])[0]
            virustotal_link = f"https://www.virustotal.com/gui/file/{file_hash}/detection"
            virustotal_file_links.append({"name": file_name, "hash": file_hash, "virustotal_link": virustotal_link})

    abuseipdb_summary = {
        "ipAddress": abuseipdb_result['data']['ipAddress'],
        "abuseConfidenceScore": abuseipdb_result['data']['abuseConfidenceScore'],
        "country": abuseipdb_result['data']['countryName'],
        "usageType": abuseipdb_result['data']['usageType'],
        "isp": abuseipdb_result['data']['isp'],
        "domain": abuseipdb_result['data']['domain'],
        "totalReports": abuseipdb_result['data']['totalReports'],
        "lastReportedAt": abuseipdb_result['data']['lastReportedAt']
    }

    return {
        "to": to,
        "from": from_address,
        "reply_to": reply_to,
        "subject": subject if subject else "N/A",
        "body": body,
        "sender_ip": sender_ip,
        "abuseipdb_result": abuseipdb_summary,
        "urls": virustotal_url_links,
        "files": virustotal_file_links
    }

# Function to get JSON input from clipboard or user input
def get_json_input():
    try:
        json_input = pyperclip.paste()
        report = json.loads(json_input)
    except Exception as e:
        print("Error reading clipboard data or clipboard empty. Please provide JSON input directly:")
        json_input = input("Enter JSON data: ")
        report = json.loads(json_input)
    return report

# Get JSON input
report = get_json_input()

# Process the report
results = process_phishing_report(report)

# Prepare the description output
if results['subject'] and results['subject'] != 'N/A':
    description_output = f"`{results['to']}` reported an email originating from `{results['from']}` with the subject `{results['subject']}`."
else:
    description_output = f"`{results['to']}` reported an email originating from `{results['from']}` with no subject."

# Copy the description output to the clipboard
try:
    pyperclip.copy(description_output)
    print("The description has been successfully copied to the clipboard. Please paste it now.")
except Exception as e:
    print(f"Failed to copy to clipboard: {e}")

# Wait for the user to press Enter after pasting the description
input("Press Enter after pasting the description...")

# Prepare the formatted output
output = []
output.append(f"To: `{results['to']}`")
output.append(f"From: `{results['from']}`")
if results['reply_to'] and results['reply_to'] != 'N/A':
    output.append(f"Reply: `{results['reply_to']}`")
output.append(f"Subject: `{results['subject']}`")

output.append(f"Sender IP: `{results['sender_ip']}`")
output.append("AbuseIPDB Result:")
output.append(f"  - IP Address: {results['abuseipdb_result']['ipAddress']}")
output.append(f"  - Abuse Confidence Score: {results['abuseipdb_result']['abuseConfidenceScore']}")
output.append(f"  - Country: {results['abuseipdb_result']['country']}")
output.append(f"  - Usage Type: {results['abuseipdb_result']['usageType']}")
output.append(f"  - ISP: {results['abuseipdb_result']['isp']}")
output.append(f"  - Domain: {results['abuseipdb_result']['domain']}")
output.append(f"  - Total Reports: {results['abuseipdb_result']['totalReports']}")
output.append(f"  - Last Reported At: {results['abuseipdb_result']['lastReportedAt']}")

if results['body'] and results['body'] != 'N/A':
    output.append("Body:")
    output.append("```")
    output.append(f"{results['body']}")
    output.append("```")
else:
    output.append("Body: N/A")

if results['urls']:
    output.append("Urls:")
    for url in results['urls']:
        output.append(url)

if results['files']:
    output.append("Files:")
    for file in results['files']:
        output.append(f"Name: {file['name']}")
        output.append(f"Hash: {file['hash']}")
        output.append(f"[VirusTotal]({file['virustotal_link']})")

# Join the output list into a single string
formatted_output = "\n".join(output)

# Copy the formatted output to the clipboard
try:
    pyperclip.copy(formatted_output)
    print("The detailed report has been successfully copied to the clipboard.")
except Exception as e:
    print(f"Failed to copy to clipboard: {e}")
