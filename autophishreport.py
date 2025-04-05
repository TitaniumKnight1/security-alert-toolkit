import requests
import json
import re
import pyperclip
from urllib.parse import unquote, urlparse, parse_qs
import base64
from alive_progress import alive_bar
from time import sleep
import ipaddress
import socket
from ipwhois import IPWhois
from emailrep import EmailRep

# API keys
VIRUSTOTAL_API_KEY = 'API_KEY'
ABUSEIPDB_API_KEY = 'API_KEY'

def url_geolocation(url):
    try:
        ip_address = socket.gethostbyname(urlparse(url).netloc)
        return ip_address
    except socket.gaierror:
        return "Could not resolve"

def whois_lookup(ip_address):
    obj = IPWhois(ip_address)
    results = obj.lookup_rdap()
    return results

def format_whois_data(whois_data):
    if not whois_data or 'network' not in whois_data:
        return "No WHOIS data available"
    
    network_info = whois_data.get('network', {})
    org_info = whois_data.get('objects', {}).get('TAMU', {}).get('contact', {})
    technical_info = whois_data.get('objects', {}).get('NG16-ORG-ARIN', {}).get('contact', {})

    whois_output = []
    whois_output.append(f"- ASN Registry: {whois_data.get('asn_registry', 'N/A')}")
    whois_output.append(f"- ASN: {whois_data.get('asn', 'N/A')}")
    whois_output.append(f"- ASN CIDR: {whois_data.get('asn_cidr', 'N/A')}")
    whois_output.append(f"- ASN Country Code: {whois_data.get('asn_country_code', 'N/A')}")
    whois_output.append(f"- ASN Description: {whois_data.get('asn_description', 'N/A')}")
    whois_output.append(f"- Network Handle: {network_info.get('handle', 'N/A')}")
    whois_output.append(f"- IP Range: {network_info.get('cidr', 'N/A')}")
    whois_output.append(f"- Network Name: {network_info.get('name', 'N/A')}")
    whois_output.append(f"- Organization: {org_info.get('name', 'N/A')}")
    whois_output.append(f"- Tech Contact: {technical_info.get('name', 'N/A')}")
    whois_output.append(f"- Tech Email: `{', '.join([email['value'] for email in technical_info.get('email', [])])}`")
    whois_output.append(f"- Tech Phone: {', '.join([phone['value'] for phone in technical_info.get('phone', [])])}")

    return "\n".join(whois_output)

# def email_address_verification(email, api_key):
#     emailrep = EmailRep(api_key=api_key)
#     result = emailrep.query(email)
#     return result

# Function to perform SPF, DKIM, and DMARC checks
def check_email_authentication(report):
    spf_result = report.get('fields', {}).get('email.headers.Received-SPF', ['N/A'])[0]
    dkim_result = report.get('fields', {}).get('email.headers.Authentication-Results', ['N/A'])[0]
    dmarc_result = report.get('fields', {}).get('email.headers.Authentication-Results', ['N/A'])[0]

    spf_passed = 'pass' in spf_result.lower()
    dkim_passed = 'dkim=pass' in dkim_result.lower()
    dmarc_passed = 'dmarc=pass' in dmarc_result.lower()

    return {
        "SPF": "Passed" if spf_passed else "Failed",
        "DKIM": "Passed" if dkim_passed else "Failed",
        "DMARC": "Passed" if dmarc_passed else "Failed"
    }

def extract_sender_ip_from_received(received_headers):
    """
    Extracts the first IP address from the 'Received' headers in an email.
    :param received_headers: A list of 'Received' headers.
    :return: The first IP address found in the headers.
    """
    for header in received_headers:
        # Use regex to find the first occurrence of an IPv4 or IPv6 address
        match_ipv4 = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header)
        match_ipv6 = re.search(r'\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b', header)

        if match_ipv4:
            return match_ipv4.group()
        elif match_ipv6:
            return match_ipv6.group()
    
    return None  # Return None if no IP is found

# Function to identify file types of attachments
def identify_file_types(attachments):
    file_warnings = []
    dangerous_types = ['exe', 'bat', 'cmd', 'js', 'vbs', 'scr', 'msi']

    for attachment in attachments:
        for file_name in attachment.get('file.name', []):
            file_extension = file_name.split('.')[-1].lower()
            if file_extension in dangerous_types:
                file_warnings.append({
                    "name": file_name,
                    "warning": f"Potentially dangerous file type: {file_extension.upper()}"
                })
            else:
                file_warnings.append({
                    "name": file_name,
                    "warning": f"File type: {file_extension.upper()}"
                })

    return file_warnings

def decode_urldefense(url):
    try:
        # Find the encoded URL part between the double underscores "__"
        start = url.find("__") + 2
        end = url.rfind("__")
        encoded_url = url[start:end]
        
        # Decode the URL
        decoded_url = unquote(encoded_url)
        
        # The decoded URL may still contain parts that need unquoting
        if "https://" in decoded_url or "http://" in decoded_url:
            decoded_url = decoded_url.split("__")[0]  # Extract URL before any further "__"
            fully_decoded_url = unquote(decoded_url)
        else:
            fully_decoded_url = decoded_url

        return fully_decoded_url
    except Exception as e:
        return f"Error decoding URL: {str(e)}"

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

    # Maintain a set of seen URLs to avoid duplicates
    seen_urls = set()
    decoded_urls = []

    for url in urls:
        if url not in seen_urls:
            seen_urls.add(url)
            final_url = url

            # Decode urldefense links
            if "urldefense.com" in url:
                final_url = decode_urldefense(url)
                seen_urls.add(final_url)

            # Check if URL is a SafeLink
            parsed_url = urlparse(final_url)
            if parsed_url.netloc == 'nam10.safelinks.protection.outlook.com':
                query_params = parse_qs(parsed_url.query)
                if 'url' in query_params:
                    # Extract the original URL
                    safe_link_url = query_params['url'][0]
                    # Decode URL encoding
                    decoded_url = unquote(safe_link_url)
                    if decoded_url not in seen_urls:
                        seen_urls.add(decoded_url)
                        final_url = decoded_url
                    else:
                        continue

            decoded_urls.append({"final_url": final_url})

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

def extract_ip_from_auth_results(auth_results):
    match = re.search(r'sender ip is (\d+\.\d+\.\d+\.\d+)', auth_results)
    if match:
        return match.group(1)
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

def is_valid_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Check if the IP is a valid public address (not private, reserved, loopback, etc.)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved:
            return False
        return True
    except ValueError:
        return False  # If the IP is not valid at all
    
# Function to check URL on VirusTotal
def check_url_virustotal(url):
    url_id = generate_url_id(url)
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers)
    sleep(15)  # Sleep for 15 seconds to avoid rate limiting
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
    elif(response.status_code == 404):
        return f"No VT Result"
    else:
        return f"Error: Received status code {response.status_code}"

def process_phishing_report(report):
    with alive_bar(7, title="Processing Report") as bar:
        to = extract_email(report.get('fields', {}).get('email.reporter', ['N/A'])[0])
        from_address = extract_email(report.get('fields', {}).get('email.from.address', ['N/A'])[0])
        reply_to = extract_email(report.get('fields', {}).get('email.headers.Reply-To', ['N/A'])[0]) if 'email.headers.Reply-To' in report.get('fields', {}) else 'N/A'
        subject = report.get('fields', {}).get('email.subject.text', ['N/A'])[0]
        body = report.get('fields', {}).get('email.body_plaintext', ['N/A'])[0].replace('\n', ' ').replace('\r', '').strip()
        body = format_email_body(body)  # Apply the formatting function
        bar()  # progress after formatting body
        
        urls = extract_and_decode_urls(report)
        attachments = report.get('fields', {}).get('email.attachments', [])
        bar()  # progress after extracting URLs and attachments

        # SPF, DKIM, and DMARC Checks
        email_authentication_results = check_email_authentication(report)
        bar()  # progress after email authentication checks

        # Extract and check sender IP from Received headers
        received_headers = report.get('fields', {}).get('email.headers.Received', [])
        sender_ip = extract_sender_ip_from_received(received_headers)

        tamu_ip_range = ipaddress.IPv4Network('128.194.0.0/16')

        if sender_ip and is_valid_public_ip(sender_ip):
            ip_obj = ipaddress.IPv4Address(sender_ip)
            if ip_obj in tamu_ip_range:
                # Extract new sender IP from ARC-Authentication-Results
                arc_auth_results = report.get('fields', {}).get('email.headers.ARC-Authentication-Results', [''])[0]
                new_sender_ip = extract_ip_from_auth_results(arc_auth_results)
                
                if new_sender_ip and is_valid_public_ip(new_sender_ip):
                    sender_ip = new_sender_ip  # Replace the sender IP with the one from ARC-Authentication-Results

            # Perform the AbuseIPDB check
            abuseipdb_result = check_ip_abuseipdb(sender_ip)
            
            # Perform the WHOIS lookup
            whois_raw_data = whois_lookup(sender_ip)
            whois_data = format_whois_data(whois_raw_data)
        else:
            abuseipdb_result = None
            whois_data = "No valid IP found"
        
        bar()  # progress after IP check (or skip)

        # Email address verification
        #email_verification = email_address_verification(from_address, "YOUR_EMAILREP_API_KEY")
        #bar()  # progress after email verification

        # Process all file hashes on VirusTotal and handle file output
        virustotal_file_results = []
        for attachment in attachments:
            file_names = attachment.get('file.name', [])
            file_hashes = attachment.get('file.hash.sha256', [])
            
            # Ensure each file name and its corresponding hash are paired correctly
            for file_name, file_hash in zip(file_names, file_hashes):
                virustotal_result = check_file_hash(file_hash)
                virustotal_file_results.append({
                    "name": file_name,
                    "hash": file_hash,
                    "virustotal_result": virustotal_result
                })
                sleep(15)  # Sleep for 15 seconds to avoid rate limiting
            
            # If there are more hashes than names or vice versa, handle them separately
            if len(file_hashes) > len(file_names):
                for file_hash in file_hashes[len(file_names):]:
                    virustotal_result = check_file_hash(file_hash)
                    virustotal_file_results.append({
                        "name": "Unknown",  # Use a placeholder if there's no name
                        "hash": file_hash,
                        "virustotal_result": virustotal_result
                    })
                    sleep(15)  # Sleep for 15 seconds to avoid rate limiting
            
            elif len(file_names) > len(file_hashes):
                for file_name in file_names[len(file_hashes):]:
                    virustotal_file_results.append({
                        "name": file_name,
                        "hash": "Unknown",  # Use a placeholder if there's no hash
                        "virustotal_result": "No hash available"
                    })

        bar()  # progress after VirusTotal file checks

        # Check URLs on VirusTotal and perform URL Geolocation
        for url_data in urls:
            ip_address = url_geolocation(url_data["final_url"])
            virustotal_result = check_url_virustotal(url_data["final_url"])
            url_data['virustotal_result'] = virustotal_result
            url_data['ip_address'] = ip_address
        bar()  # progress after VirusTotal URL checks

        # Identify file types and flag dangerous types
        file_type_warnings = identify_file_types(attachments)

        # Output VirusTotal file results
        virustotal_file_links = []
        for file in virustotal_file_results:
            file_name = file['name']
            file_hash = file['hash']
            file_result = file['virustotal_result']
            if isinstance(file_result, dict) and 'data' in file_result:
                virustotal_link = f"https://www.virustotal.com/gui/file/{file_result['data']['id']}/detection"
            else:
                virustotal_link = "No VT Results"
            virustotal_file_links.append({
                "name": file_name,
                "hash": file_hash,
                "virustotal_link": virustotal_link
            })
        bar()  # progress after constructing VirusTotal file links

    return {
        "to": to,
        "from": from_address,
        "reply_to": reply_to,
        "subject": subject if subject else "N/A",
        "body": body,
        "sender_ip": sender_ip,
        "abuseipdb_result": abuseipdb_result,
        "whois_data": whois_data,
        #"email_verification": email_verification,
        "email_authentication_results": email_authentication_results,
        "file_type_warnings": file_type_warnings,
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
    
    if results['sender_ip']:
        output.append(f"Sender IP: `{results['sender_ip']}`")

        if results['abuseipdb_result'] and 'data' in results['abuseipdb_result']:
            output.append("")
            output.append("***AbuseIPDB Result:***")
            output.append(f"  - IP Address: {results['abuseipdb_result']['data']['ipAddress']}")
            output.append(f"  - Abuse Confidence Score: {results['abuseipdb_result']['data']['abuseConfidenceScore']}")
            output.append(f"  - Country: {results['abuseipdb_result']['data']['countryName']}")
            output.append(f"  - Usage Type: {results['abuseipdb_result']['data']['usageType']}")
            output.append(f"  - ISP: {results['abuseipdb_result']['data']['isp']}")
            output.append(f"  - Domain: {results['abuseipdb_result']['data']['domain']}")
            output.append(f"  - Total Reports: {results['abuseipdb_result']['data']['totalReports']}")
            output.append(f"  - Last Reported At: {results['abuseipdb_result']['data']['lastReportedAt']}")
        elif results['abuseipdb_result'] and 'error' in results['abuseipdb_result']:
            output.append("***AbuseIPDB Result:***")
            output.append(f"  - Error: {results['abuseipdb_result']['error']}")
    else:
        output.append("Sender IP: No valid public IP address found")
    
    output.append("")
    if results['whois_data']:
        output.append("***WHOIS Data:***")
        output.append(f"{results['whois_data']}")
        output.append("")

    # if results['email_verification']:
    #     output.append("***Email Verification:***")
    #     output.append(f"  - {results['email_verification']}")
    #     output.append("")

    if results['email_authentication_results']:
        output.append("***Email Authentication Results:***")
        output.append(f"  - **SPF:** `{results['email_authentication_results']['SPF']}` *(SPF verifies that the email is sent from an authorized server for the sender's domain.)*")
        output.append(f"  - **DKIM:** `{results['email_authentication_results']['DKIM']}` *(DKIM ensures that the email content has not been altered and confirms the sender's identity.)*")
        output.append(f"  - **DMARC:** `{results['email_authentication_results']['DMARC']}` *(DMARC uses SPF and DKIM results to determine authenticity of the domain.)*")

    if results['file_type_warnings']:
        output.append("")
        output.append("***File Type Warnings:***")
        for warning in results['file_type_warnings']:
            output.append(f"  - {warning['name']}: {warning['warning']}")

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
        output.append("")
        for url in results['urls']:
            output.append(f"Url: `{url['final_url']}`")
            output.append(f"IP Address: `{url['ip_address']}`")
            output.append(f"{url['virustotal_result']}")
            output.append("")
            output.append("---")
            output.append("")



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
            output.append("")


    formatted_output = "\n".join(output)

    try:
        pyperclip.copy(formatted_output)
        print("The detailed report has been successfully copied to the clipboard.")
    except Exception as e:
        print(f"Failed to copy to clipboard: {e}")
else:
    print("Failed to process the report due to an error in the AbuseIPDB response.")
