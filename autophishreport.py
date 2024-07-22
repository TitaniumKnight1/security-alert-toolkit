import requests
import json
import re
import pyperclip
from urllib.parse import unquote
import base64

# API keys
VIRUSTOTAL_API_KEY = 'VIRUSTOTAL_API_KEY'
ABUSEIPDB_API_KEY = 'ABUSEIPDB_API_KEY'
ALIENVAULT_API_KEY = 'ALIENVAULT_API_KEY'

# Function to extract and decode URLs from the email report
def extract_and_decode_urls(json_data):
    urls = []

    # Extract URLs from email.urls.data
    if "email.urls.data" in json_data["fields"]:
        urls.extend(json_data["fields"]["email.urls.data"])

    # Extract URLs from email.body_plaintext
    if "email.body_plaintext" in json_data["fields"]:
        for body in json_data["fields"]["email.body_plaintext"]:
            found_urls = re.findall(r'(https?://\S+)', body)
            urls.extend(found_urls)

    # Remove duplicates
    urls = list(set(urls))

    # Decode and clean URLs
    decoded_urls = []
    for url in urls:
        deobfuscation_steps = []

        # Unquote URL
        unquoted_url = unquote(url)
        if unquoted_url != url:
            deobfuscation_steps.append(f"Decoded: `{unquoted_url}`")

        # Handle obfuscated JavaScript URLs
        js_obfuscated = re.search(r'var url\s*=\s*\[(.*?)\]\.join', unquoted_url)
        if (js_obfuscated):
            parts = js_obfuscated.group(1).replace("'", "").split(",")
            reconstructed_url = "".join(parts)
            deobfuscation_steps.append(f"Reconstructed from JS: `{reconstructed_url}`")
            final_url = reconstructed_url
        else:
            final_url = unquoted_url

        decoded_urls.append({
            "original_url": url,
            "final_url": final_url,
            "steps": deobfuscation_steps
        })

    return decoded_urls

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

    if response.status_code != 200:
        return {"message": f"Error: Received status code {response.status_code}"}

    try:
        result = response.json()
        if 'data' in result:
            return result
        else:
            return {"message": "No data found"}
    except json.JSONDecodeError:
        return {"message": "Failed to parse JSON"}

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

# Function to check file hash on VirusTotal
def check_file_hash(hash_value):
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(f'https://www.virustotal.com/api/v3/files/{hash_value}', headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {"message": "No results found"}

# Function to manually generate URL ID
def generate_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

# Function to check URL on VirusTotal
def check_url_virustotal(url):
    url_id = generate_url_id(url)
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers)
    if response.status_code == 200:
        url_obj = response.json()
        if 'data' in url_obj:
            score = url_obj['data']['attributes']['last_analysis_stats']
            # Remove 'timeout' from score
            score.pop('timeout', None)
            formatted_score = ', '.join([f"{k}: {v}" for k, v in score.items()])
            return f"[VirusTotal](https://www.virustotal.com/gui/url/{url_id}) - {formatted_score}"
        else:
            return "No results found"
    else:
        return {"message": f"Error: Received status code {response.status_code}"}

# Function to query AlienVault OTX for IP intelligence
def query_alienvault(ip):
    headers = {'X-OTX-API-KEY': ALIENVAULT_API_KEY}
    response = requests.get(f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general', headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return {"message": f"Error: Received status code {response.status_code}"}

# Update the process_phishing_report function to use the new extract_and_decode_urls function
def process_phishing_report(report):
    to = extract_email(report.get('fields', {}).get('email.reporter', ['N/A'])[0])
    from_address = extract_email(report.get('fields', {}).get('email.from.address', ['N/A'])[0])
    reply_to = extract_email(report.get('fields', {}).get('email.headers.Reply-To', ['N/A'])[0]) if 'email.headers.Reply-To' in report.get('fields', {}) else 'N/A'
    subject = report.get('fields', {}).get('email.subject.text', ['N/A'])[0]
    body = report.get('fields', {}).get('email.body_plaintext', ['N/A'])[0].replace('\n', ' ').replace('\r', '').strip()
    body = format_email_body(body)  # Apply the formatting function
    urls = extract_and_decode_urls(report)
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

    # Proceed even if abuseipdb_result is None
    if abuseipdb_result is None:
        abuseipdb_summary = {}
    elif 'message' in abuseipdb_result:
        abuseipdb_summary = {"error": abuseipdb_result['message']}
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

    # Check file hashes on VirusTotal
    virustotal_file_results = {}
    for attachment in attachments:
        for file_hash in attachment.get('file.hash.sha256', []):
            virustotal_result = check_file_hash(file_hash)
            virustotal_file_results[file_hash] = virustotal_result

    # Query AlienVault OTX for sender IP intelligence
    alienvault_result = query_alienvault(sender_ip) if sender_ip else None

    # Construct VirusTotal file links
    virustotal_file_links = []
    for file_hash, file_result in virustotal_file_results.items():
        for file_name in attachment.get('file.name', []):
            if 'data' in file_result:
                virustotal_link = f"https://www.virustotal.com/gui/file/{file_result['data']['id']}/detection"
            else:
                virustotal_link = "No VT Results"
            virustotal_file_links.append({
                "name": file_name,
                "hash": file_hash,
                "virustotal_link": virustotal_link
            })

    alienvault_summary = {}
    if alienvault_result is None:
        alienvault_summary = {}
    elif 'message' in alienvault_result:
        alienvault_summary = {"error": alienvault_result['message']}
    else:
        alienvault_summary = {
            "reputation": alienvault_result.get('reputation', 'N/A'),
            "country": alienvault_result.get('country_name', 'N/A'),
            "city": alienvault_result.get('city', 'N/A'),
            "latitude": alienvault_result.get('latitude', 'N/A'),
            "longitude": alienvault_result.get('longitude', 'N/A'),
            "adversary": alienvault_result.get('adversary', 'N/A')
        }

    # Check URLs on VirusTotal
    for url in urls:
        vt_result = check_url_virustotal(url['final_url'])
        url['virustotal_result'] = vt_result

    return {
        "to": to,
        "from": from_address,
        "reply_to": reply_to,
        "subject": subject if subject else "N/A",
        "body": body,
        "sender_ip": sender_ip if sender_ip else "N/A",
        "abuseipdb_result": abuseipdb_summary,
        "alienvault_result": alienvault_summary,
        "urls": urls,
        "files": virustotal_file_links,
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
    elif 'error' in results['abuseipdb_result']:
        output.append("***AbuseIPDB Result:***")
        output.append(f"  - Error: {results['abuseipdb_result']['error']}")

    output.append("")

    if 'reputation' in results['alienvault_result']:
        output.append("***AlienVault OTX Result:***")
        output.append(f"  - Reputation: {results['alienvault_result']['reputation']}")
        output.append(f"  - Country: {results['alienvault_result']['country']}")
        output.append(f"  - City: {results['alienvault_result']['city']}")
        output.append(f"  - Latitude: {results['alienvault_result']['latitude']}")
        output.append(f"  - Longitude: {results['alienvault_result']['longitude']}")
        output.append(f"  - Adversary: {results['alienvault_result']['adversary']}")
    elif 'error' in results['alienvault_result']:
        output.append("***AlienVault OTX Result:***")
        output.append(f"  - Error: {results['alienvault_result']['error']}")

    if results['body'] and results['body'] != 'N/A':
        output.append("")
        output.append("***Body:***")
        output.append("```")
        output.append(f"{results['body']}")
        output.append("```")
    else:
        output.append("***Body:*** N/A")

    if results['urls']:
        output.append("")
        output.append("***Urls:***")
        for url in results['urls']:
            if url['steps']:
                output.append(f"---")
                output.append(f"Original URL: `{url['original_url']}`")
                output.append(f"***Deobfuscation steps:***")
                for step in url['steps']:
                    output.append(step)
                output.append(f"Final URL: `{url['final_url']}`")
                output.append("")
                output.append("---")
            else:
                output.append(f"Url: `{url['original_url']}`")
            output.append(f"{url['virustotal_result']}")
            output.append("")  # Add blank line for separation

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

    formatted_output = "\n".join(output)

    try:
        pyperclip.copy(formatted_output)
        print("The detailed report has been successfully copied to the clipboard.")
    except Exception as e:
        print(f"Failed to copy to clipboard: {e}")
else:
    print("Failed to process the report due to an error in the AbuseIPDB response.")
