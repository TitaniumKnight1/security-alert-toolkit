import requests
import json
import base64
import time
from urllib.parse import urlparse, parse_qs
import pyperclip
import re

# API keys
VIRUSTOTAL_API_KEY = 'VIRUSTOTAL_API_KEY'
ABUSEIPDB_API_KEY = 'ABUSEIPDB_API_KEY'
ALIENVAULT_API_KEY = 'ALIENVAULT_API_KEY'
GOOGLE_API_KEY = 'GOOGLE_API_KEY'

# Function to extract URLs from the email report
def extract_urls_from_report(report):
    return report.get('fields', {}).get('email.urls.data', [])

# Function to convert URL to URL-safe base64 format
def url_to_base64(url):
    url_bytes = url.encode('utf-8')
    base64_bytes = base64.urlsafe_b64encode(url_bytes)
    base64_string = base64_bytes.decode('utf-8')
    return base64_string.rstrip('=')

# Function to format email body for better readability
def format_email_body(body):
    body = re.sub(r'\s+', ' ', body)
    body = re.sub(r'(\s*-{2,}\s*Forwarded message\s*-{2,})', r'\n\n\1\n', body)
    body = re.sub(r'(\s*-{2,}\s*Original message\s*-{2,})', r'\n\n\1\n', body)
    body = re.sub(r'(\s*From:\s)', r'\n\n\1', body)
    body = re.sub(r'(\s*Date:\s)', r'\n\1', body)
    body = re.sub(r'(\s*Subject:\s)', r'\n\1', body)
    body = re.sub(r'(\s*To:\s)', r'\n\1', body)
    body = body.replace('   ', '\n\n')
    return body

# Function to decode SafeLinks
def decode_safelink(url):
    parsed_url = urlparse(url)
    if 'safelinks.protection.outlook.com' in parsed_url.netloc:
        query_params = parse_qs(parsed_url.query)
        if 'url' in query_params:
            return query_params['url'][0]
    return url

# Function to truncate URLs
def truncate_url(url, max_length=100):
    if len(url) > max_length:
        return f"`{url[:max_length]}...`"
    return f"`{url}`"

# Function to query VirusTotal for a URL
def query_virustotal(url):
    url_id = url_to_base64(url)
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers)
    return response.json()

# Function to check file hash on VirusTotal
def check_file_hash(hash_value):
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(f'https://www.virustotal.com/api/v3/files/{hash_value}', headers=headers)
    return response.json()

# Function to validate IP address
def is_valid_ip(ip):
    ipv4_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    ipv6_pattern = re.compile(r"^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
                              r"([0-9a-fA-F]{1,4}:){1,7}:|"
                              r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
                              r"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
                              r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
                              r"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
                              r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
                              r"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
                              r":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
                              r"fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
                              r"::(ffff(:0{1,4}){0,1}:){0,1}"
                              r"(([0-9]{1,3}\.){3,3}[0-9]{1,3})|"
                              r"([0-9a-fA-F]{1,4}:){1,4}:([0-9]{1,3}\.){3,3}[0-9]{1,3}$")
    return ipv4_pattern.match(ip) or ipv6_pattern.match(ip)

# Function to check IP on AbuseIPDB
def check_ip_abuseipdb(ip):
    if not is_valid_ip(ip):
        print(f"Error: Invalid IP address format '{ip}'")
        return None
    
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
    
    if response.status_code != 200:
        print(f"Error: Received status code {response.status_code} from AbuseIPDB. Response: {response.text}")
        return None

    try:
        result = response.json()
        if 'data' in result:
            return result
        else:
            print(f"Error: AbuseIPDB response does not contain 'data'. Response: {result}")
            return None
    except json.JSONDecodeError:
        print(f"Error: Failed to parse JSON response from AbuseIPDB. Response: {response.text}")
        return None

# Function to extract a valid email from a given string
def extract_email(email_str):
    match = re.search(r'<(.+?)>', email_str)
    if match:
        return match.group(1)
    if re.match(r"[^@]+@[^@]+\.[^@]+", email_str):
        return email_str
    return 'N/A'

# Function to extract IP from Authentication-Results header (updated to handle IPv6)
def extract_ip_from_auth_results(auth_results):
    match_ipv4 = re.search(r'sender IP is (\d+\.\d+\.\d+\.\d+)', auth_results)
    match_ipv6 = re.search(r'sender IP is ([a-fA-F0-9:]+)', auth_results)
    if match_ipv4:
        return match_ipv4.group(1)
    elif match_ipv6:
        return match_ipv6.group(1)
    return None

# Function to extract IP from Received-SPF header
def extract_ip_from_received_spf(received_spf):
    match_ipv4 = re.search(r'client-ip=(\d+\.\d+\.\d+\.\d+)', received_spf)
    match_ipv6 = re.search(r'client-ip=([a-fA-F0-9:]+)', received_spf)
    if match_ipv4:
        return match_ipv4.group(1)
    elif match_ipv6:
        return match_ipv6.group(1)
    return None

# Function to query Google Safe Browsing for a URL
def query_google_safe_browsing(url):
    api_url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
    params = {
        'key': GOOGLE_API_KEY
    }
    body = {
        "client": {
            "clientId": "yourcompanyname",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["WINDOWS", "LINUX", "ALL_PLATFORMS"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    response = requests.post(api_url, params=params, json=body)
    if response.status_code == 200:
        return response.json()
    else:
        return None
    
# Function to query AlienVault OTX for IP intelligence
def query_alienvault(ip):
    headers = {'X-OTX-API-KEY': ALIENVAULT_API_KEY}
    response = requests.get(f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general', headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Function to expand shortened URLs using Unshorten.me
def expand_url(url):
    response = requests.get(f'https://unshorten.me/json/{url}')
    return response.json()

# Update the process_phishing_report function to use the new extract_urls_from_report function
def process_phishing_report(report):
    to = extract_email(report.get('fields', {}).get('email.reporter', ['N/A'])[0])
    from_address = extract_email(report.get('fields', {}).get('email.from.address', ['N/A'])[0])
    reply_to = extract_email(report.get('fields', {}).get('email.headers.Reply-To', ['N/A'])[0]) if 'email.headers.Reply-To' in report.get('fields', {}) else 'N/A'
    subject = report.get('fields', {}).get('email.subject.text', ['N/A'])[0]
    body = report.get('fields', {}).get('email.body_plaintext', ['N/A'])[0].replace('\n', ' ').replace('\r', '').strip()
    body = format_email_body(body)  # Apply the formatting function
    urls = extract_urls_from_report(report)
    attachments = report.get('fields', {}).get('email.attachments', [])
    auth_results = report.get('fields', {}).get('email.headers.Authentication-Results', ['N/A'])[0]
    received_spf = report.get('fields', {}).get('email.headers.Received-SPF', ['N/A'])[0]
    
    # Extract and check sender IP
    sender_ip = extract_ip_from_auth_results(auth_results)
    if not sender_ip:
        sender_ip = extract_ip_from_received_spf(received_spf)
    
    abuseipdb_result = None
    if sender_ip:
        abuseipdb_result = check_ip_abuseipdb(sender_ip)
    else:
        print("No valid sender IP found in Authentication-Results or Received-SPF.")
    
    # Decode SafeLinks and remove duplicates
    decoded_urls = list(set([decode_safelink(url) for url in urls]))

    # Expand shortened URLs
    expanded_urls = []
    for url in decoded_urls:
        expanded_url = expand_url(url)
        if 'resolved_url' in expanded_url:
            expanded_urls.append(expanded_url['resolved_url'])
        else:
            print(f"Error: Failed to expand URL {url}. Response: {expanded_url}")
            expanded_urls.append(url)  # Fallback to the original URL if expansion fails

    # Remove empty or malformed URLs
    expanded_urls = [url for url in expanded_urls if url]

    # Query Google Safe Browsing for URLs
    google_safe_browsing_results = {}
    for url in expanded_urls:
        result = query_google_safe_browsing(url)
        if result:
            google_safe_browsing_results[url] = result
        else:
            google_safe_browsing_results[url] = {"message": "No Threat Found"}
        time.sleep(1)  # To respect rate limits
    
    # Proceed even if abuseipdb_result is None
    if abuseipdb_result is None:
        print("Skipping AbuseIPDB check due to invalid sender IP.")
        abuseipdb_summary = {}
    else:
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

    # Query VirusTotal for URLs
    virustotal_url_results = {}
    for url in expanded_urls:
        virustotal_url_results[url] = query_virustotal(url)
        time.sleep(15)  # Sleep to respect the rate limit

    # Check file hashes on VirusTotal
    virustotal_file_results = {}
    for attachment in attachments:
        for file_hash in attachment.get('file.hash.sha256', []):
            virustotal_file_results[file_hash] = check_file_hash(file_hash)

    # Query AlienVault OTX for IP
    alienvault_result = query_alienvault(sender_ip) if sender_ip else None

    # Prepare the output in the required format
    virustotal_url_links = []
    for url, result in virustotal_url_results.items():
        domain = urlparse(url).netloc
        if 'data' in result and 'id' in result['data']:
            analysis_url = f"[VirusTotal](https://www.virustotal.com/gui/url/{result['data']['id']}/detection)"
        else:
            analysis_url = "No VT Results"
        truncated_url = truncate_url(url)
        virustotal_url_links.append(f"{truncated_url}\n{analysis_url}")

    virustotal_file_links = []
    for attachment in attachments:
        for file_hash in attachment.get('file.hash.sha256', []):
            file_name = attachment.get('file.name', ['unknown'])[0]
            file_result = virustotal_file_results.get(file_hash, {})
            if 'data' in file_result and 'id' in file_result['data']:
                virustotal_link = f"https://www.virustotal.com/gui/file/{file_result['data']['id']}/detection"
            else:
                virustotal_link = "No VT Results"
            virustotal_file_links.append({"name": file_name, "hash": file_hash, "virustotal_link": virustotal_link})

    alienvault_summary = {}
    if alienvault_result:
        alienvault_summary = {
            "reputation": alienvault_result.get('reputation', 'N/A'),
            "country": alienvault_result.get('country_name', 'N/A'),
            "city": alienvault_result.get('city', 'N/A'),
            "latitude": alienvault_result.get('latitude', 'N/A'),
            "longitude": alienvault_result.get('longitude', 'N/A'),
            "adversary": alienvault_result.get('adversary', 'N/A')
        }

    return {
        "to": to,
        "from": from_address,
        "reply_to": reply_to,
        "subject": subject if subject else "N/A",
        "body": body,
        "sender_ip": sender_ip if sender_ip else "N/A",
        "abuseipdb_result": abuseipdb_summary,
        "alienvault_result": alienvault_summary,
        "google_safe_browsing_results": google_safe_browsing_results,
        "urls": virustotal_url_links,
        "files": virustotal_file_links,
        "decoded_urls": decoded_urls,
        "expanded_urls": expanded_urls
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

if results:
    if results['subject'] and results['subject'] != 'N/A':
        description_output = f"`{results['to']}` reported an email originating from `{results['from']}` with the subject `{results['subject']}`."
    else:
        description_output = f"`{results['to']}` reported an email originating from `{results['from']}` with no subject."

    try:
        pyperclip.copy(description_output)
        print("The description has been successfully copied to the clipboard. Please paste it now.")
    except Exception as e:
        print(f"Failed to copy to clipboard: {e}")

    input("Press Enter after pasting the description...")

    output = []
    output.append(f"To: `{results['to']}`")
    output.append(f"From: `{results['from']}`")
    if results['reply_to'] and results['reply_to'] != 'N/A':
        output.append(f"Reply: `{results['reply_to']}`")
    output.append(f"Subject: `{results['subject']}`")
    output.append(f"Sender IP: `{results['sender_ip']}`")
    output.append("")
    
    if 'ipAddress' in results['abuseipdb_result']:
        output.append("***AbuseIPDB Result:***")
        output.append(f"  - IP Address: {results['abuseipdb_result']['ipAddress']}")
        output.append(f"  - Abuse Confidence Score: {results['abuseipdb_result']['abuseConfidenceScore']}")
        output.append(f"  - Country: {results['abuseipdb_result']['country']}")
        output.append(f"  - Usage Type: {results['abuseipdb_result']['usageType']}")
        output.append(f"  - ISP: {results['abuseipdb_result']['isp']}")
        output.append(f"  - Domain: {results['abuseipdb_result']['domain']}")
        output.append(f"  - Total Reports: {results['abuseipdb_result']['totalReports']}")
        output.append(f"  - Last Reported At: {results['abuseipdb_result']['lastReportedAt']}")
    
        output.append("")
    
        output.append("***AlienVault OTX Result:***")
        output.append(f"  - Reputation: {results['alienvault_result']['reputation']}")
        output.append(f"  - Country: {results['alienvault_result']['country']}")
        output.append(f"  - City: {results['alienvault_result']['city']}")
        output.append(f"  - Latitude: {results['alienvault_result']['latitude']}")
        output.append(f"  - Longitude: {results['alienvault_result']['longitude']}")
        output.append(f"  - Adversary: {results['alienvault_result']['adversary']}")
    else:
        output.append("No valid IP address found for scanning.")

    if results['body'] and results['body'] != 'N/A':
        output.append("")
        output.append("***Body:***")
        output.append("```")
        output.append(f"{results['body']}")
        output.append("```")
    else:
        output.append("***Body:*** N/A")

    if results['urls']:
        output.append("***Urls:***")
        for url in results['urls']:
            output.append(url)

    if results['files']:
        output.append("")
        output.append("***Files***:")
        for file in results['files']:
            output.append(f"Name: {file['name']}")
            output.append(f"Hash: {file['hash']}")
            if file['virustotal_link'] != "No VT Results":
                output.append(f"[VirusTotal]({file['virustotal_link']})")
            else:
                output.append(file['virustotal_link'])
                
    if results['google_safe_browsing_results']:
        output.append("")
        output.append("***Google Safe Browsing Results***:")
        for url, result in results['google_safe_browsing_results'].items():
            truncated_url = truncate_url(url)
            if 'matches' in result:
                output.append(f"{truncated_url}\nThreat: {result['matches'][0]['threatType']}")
            else:
                output.append(f"{truncated_url}\nNo Threat Found")

    formatted_output = "\n".join(output)

    try:
        pyperclip.copy(formatted_output)
        print("The detailed report has been successfully copied to the clipboard.")
    except Exception as e:
        print(f"Failed to copy to clipboard: {e}")
else:
    print("Failed to process the report due to an error in the AbuseIPDB response.")
