# -*- coding: utf-8 -*- # Ensure handling of diverse characters

# --- Core Libraries ---
import requests
import json
import re
import pyperclip
import base64
import os
import logging
import ipaddress
import socket
from time import sleep, time
from urllib.parse import unquote, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Third-Party Libraries ---
from ipwhois import IPWhois                       # For WHOIS lookups
from alive_progress import alive_bar              # For visual progress indication
from dotenv import load_dotenv                    # To load environment variables from .env file
from requests.exceptions import RequestException  # To catch general request errors
from json import JSONDecodeError                  # To catch JSON parsing errors

# --- Load Environment Variables ---
# Load variables from .env file into environment if it exists.
# This should be called early, before accessing environment variables.
load_dotenv()

# --- Configuration & Constants ---

# Attempt to load API keys from environment variables (or .env file via load_dotenv).
# Placeholders are used if keys are not found, checked later in main().
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', 'YOUR_DEFAULT_VT_KEY')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', 'YOUR_DEFAULT_ABUSEIPDB_KEY')

# Logging setup for script execution details and errors.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set of file extensions considered potentially dangerous.
DANGEROUS_FILE_TYPES = {'exe', 'bat', 'cmd', 'js', 'vbs', 'scr', 'msi', 'dll', 'ps1'}

# Delay (in seconds) between VirusTotal Public API calls to respect rate limits (4 requests/minute).
VT_PUBLIC_API_SLEEP = 15

# Maximum number of concurrent worker threads for non-sequential API calls (like WHOIS, AbuseIPDB, Geolocation).
MAX_WORKERS = 5

# --- Helper Functions ---

def get_nested_value(data_dict, keys, default=None):
    """
    Safely retrieves a value from a potentially nested dictionary structure.
    Handles cases where keys might be missing or intermediate values are lists.
    If the final value is a list with one element, returns that element directly.
    """
    temp_dict = data_dict
    for key in keys:
        if isinstance(temp_dict, dict):
            temp_dict = temp_dict.get(key)
        # Handle common case in Kibana JSON where a value is wrapped in a list: ["value"]
        elif isinstance(temp_dict, list) and len(temp_dict) == 1 and isinstance(temp_dict[0], dict):
             temp_dict = temp_dict[0].get(key)
        else:
            return default # Cannot traverse further
        if temp_dict is None:
            return default # Key not found

    # Post-traversal list handling
    if isinstance(temp_dict, list):
        if len(temp_dict) == 1:
             return temp_dict[0] # Extract single element
        elif len(temp_dict) > 1:
             return temp_dict # Return full list if multiple elements (e.g., 'Received' headers)
        else:
             return default # Return default if list is empty
    return temp_dict # Return the final value

def extract_email(email_str):
    """
    Extracts an email address from a string.
    Prioritizes content within angle brackets (e.g., "Name <email@example.com>").
    Falls back to a basic regex check if no brackets are found.
    """
    if not isinstance(email_str, str):
        return 'N/A'
    # Check for email within angle brackets
    match = re.search(r'<(.+?)>', email_str)
    if match:
        return match.group(1).strip()
    # If no brackets, clean up the string and do a basic regex check
    email_str = email_str.strip(' \t\n\r"\'')
    if re.match(r"[^@\s]+@[^@\s]+\.[^@\s]+", email_str):
        return email_str
    return 'N/A' # Return 'N/A' if no valid email is found

def is_valid_public_ip(ip):
    """
    Checks if a given string represents a valid, public IP address (IPv4 or IPv6).
    Excludes private, loopback, multicast, reserved, and unspecified addresses.
    """
    if not ip or not isinstance(ip, str):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Check against various non-public IP categories
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved)
    except ValueError:
        return False # String is not a valid IP address format

# --- URL Processing Functions ---

def decode_urldefense(url):
    """
    Attempts to decode Proofpoint URLDefense wrapped URLs.
    Handles different encoding variations (e.g., __...__, u=...).
    Tries standard URL decoding and falls back to Base64 decoding.
    """
    try:
        encoded_part = None
        # Try extracting the common pattern between double underscores
        match = re.search(r'__([^_]+)__', url)
        if match:
            encoded_part = match.group(1)
        else:
            # Fallback: Try extracting from the 'u=' parameter
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            if 'u' in query_params:
                encoded_part = query_params['u'][0]

        if not encoded_part:
            logging.warning(f"Could not find encoded part in URLDefense URL: {url}")
            return url # Return original if no encoded part identified

        # Attempt 1: Standard URL decoding with Proofpoint replacements
        try:
            decoded_url = encoded_part.replace('-', '%').replace('_', '/').replace('.', '=')
            # Multiple unquotes might be necessary
            final_url = unquote(unquote(decoded_url))
            if final_url.startswith(("http://", "https://")):
                 final_url = final_url.split("__")[0] # Clean potential trailing parts
                 return final_url
        except Exception as e:
            logging.debug(f"Standard URLDefense decoding failed for {url}: {e}")
            pass # Continue to Base64 attempt if standard decoding fails

        # Attempt 2: Base64 decoding (especially if standard decoding failed)
        try:
            # Use standard Base64 replacements, ensure padding
            b64_encoded_part = encoded_part.replace('-', '+').replace('_', '/')
            b64_encoded_part += '=' * (-len(b64_encoded_part) % 4)
            decoded_bytes = base64.urlsafe_b64decode(b64_encoded_part)
            possible_url = decoded_bytes.decode('utf-8', errors='ignore')
            if possible_url.startswith(('http://', 'https://')):
                logging.info(f"Decoded URLDefense using Base64 for: {url}")
                return possible_url
        except Exception as b64_e:
            logging.warning(f"Base64 decoding attempt also failed for URLDefense '{url}': {b64_e}")
            pass # Log failure but proceed

        # If both attempts fail
        logging.warning(f"Failed to decode URLDefense URL: {url}")
        return url # Return original if all decoding fails

    except Exception as e:
        logging.error(f"Generic error decoding URLDefense URL '{url}': {str(e)}")
        return url # Return original on error

def decode_safelink(url):
    """
    Decodes Microsoft SafeLink URLs by extracting and unquoting the 'url' parameter.
    Applies unquote multiple times to handle potential double encoding.
    """
    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        if 'url' in query_params:
            decoded_url = query_params['url'][0]
            # Apply unquote iteratively up to 3 times
            for _ in range(3):
                new_decode = unquote(decoded_url)
                if new_decode == decoded_url:
                    break # Stop if no change occurs
                decoded_url = new_decode
            return decoded_url
        else:
            logging.warning(f"Could not find 'url' parameter in SafeLink: {url}")
            return url # Return original if parameter missing
    except Exception as e:
        logging.error(f"Error decoding SafeLink URL '{url}': {str(e)}")
        return url # Return original on error

def extract_and_decode_urls(report_fields):
    """
    Extracts URLs from 'email.urls.data' and 'email.body_plaintext' fields.
    Handles the Kibana structure where 'email.urls.data' is a list of {"data": "url"} dicts.
    Decodes URLDefense and SafeLink wrappers.
    Returns a list of dictionaries, each containing 'original_url' and 'final_url'.
    """
    urls = set() # Use a set to automatically store unique URLs

    # Extract from 'email.urls.data' (list of dictionaries)
    urls_list_of_dicts = report_fields.get('email.urls.data', [])
    if isinstance(urls_list_of_dicts, list):
        for item in urls_list_of_dicts:
            if isinstance(item, dict) and 'data' in item and isinstance(item.get('data'), str):
                urls.add(item['data']) # Extract URL from the 'data' key
            elif isinstance(item, str):
                 urls.add(item) # Handle case where it might be just a list of strings

    # Extract from 'email.body_plaintext' using regex
    body_text = get_nested_value(report_fields, ['email.body_plaintext'], default='')
    if isinstance(body_text, str):
        # Regex to find URLs, avoiding inclusion of trailing punctuation common in text
        found_urls_in_body = re.findall(r'https?://[^\s"\'<>`]+', body_text)
        cleaned_urls = {url.rstrip('.,;:)\]>') for url in found_urls_in_body} # Remove trailing chars
        urls.update(cleaned_urls)

    # Decode and deduplicate URLs
    decoded_urls_data = []
    processed_urls = set() # Track final URLs to avoid duplicates post-decoding

    for url in urls:
        if not isinstance(url, str) or not url.startswith(('http://', 'https://')):
            logging.warning(f"Skipping invalid or non-HTTP(S) URL extracted: {url}")
            continue # Skip processing if it's not a valid web URL

        final_url = url
        # Apply decoders
        if "urldefense.com" in url.lower():
            final_url = decode_urldefense(url)
        # Parse the potentially decoded URL before checking for SafeLinks
        parsed_final_url = urlparse(final_url)
        if parsed_final_url.netloc and 'safelinks.protection.outlook.com' in parsed_final_url.netloc.lower():
            final_url = decode_safelink(final_url)

        # Add to results if the final URL is valid and hasn't been seen
        if final_url not in processed_urls:
            processed_urls.add(final_url)
            # Final validation check after decoding
            if isinstance(final_url, str) and final_url.startswith(('http://', 'https://')):
                 decoded_urls_data.append({"original_url": url, "final_url": final_url})
            else:
                 logging.warning(f"URL became invalid after decoding, skipping: {final_url} (from {url})")

    logging.info(f"Extracted and decoded {len(decoded_urls_data)} unique URLs.")
    return decoded_urls_data

# --- IP Address Functions ---

def extract_ip_from_received(received_headers):
    """
    Extracts the first potential public IP address found by scanning 'Received' headers.
    Parses headers from last to first, looking for IPs after 'from' or 'by'.
    NOTE: This is generally less reliable than using authentication headers.
    """
    if not isinstance(received_headers, list):
        return None

    # Regex targeting IPs (v4/v6) often found within brackets/parentheses after 'from' or 'by'
    ip_pattern = re.compile(
        r'(?:from|by)\s+[^(\[]*' # Look after 'from'/'by', skip non-bracket chars
        r'[(\[]?' # Optional opening bracket/paren
        r'((?:\d{1,3}\.){3}\d{1,3}|(?:[a-fA-F0-9:]+:+[a-fA-F0-9.:]+))' # Capture IP
        r'[\])]?' # Optional closing bracket/paren
        , re.IGNORECASE)

    # Scan headers in reverse order (newest first)
    for header in reversed(received_headers):
        if not isinstance(header, str): continue
        matches = ip_pattern.findall(header)
        # Check matches found in this header in reverse order (often last IP is sender)
        for ip in reversed(matches):
            if is_valid_public_ip(ip):
                logging.debug(f"Found potential public IP in Received header: {ip}")
                return ip # Return the first valid public IP encountered
    logging.debug("No valid public IP found while parsing Received headers.")
    return None

def extract_ip_from_auth_results(auth_results_header):
    """
    Extracts an IP address from specific email authentication headers like
    Authentication-Results, ARC-Authentication-Results, or Received-SPF.
    Looks for common patterns like 'client-ip=', 'sender IP is', 'ip='.
    """
    if not isinstance(auth_results_header, str):
        return None
    # Regex matching common IP indicators in auth headers (case-insensitive)
    match = re.search(r'\b(?:sender IP is|client-ip=|ip=)\s*([0-9\.]{7,15}|[a-fA-F0-9:]{3,})\b', auth_results_header, re.IGNORECASE)
    if match:
        ip = match.group(1)
        # Ignore placeholder IPs
        if ip in ('0.0.0.0', '::'): return None
        if is_valid_public_ip(ip):
            return ip # Return the valid public IP
    return None

def determine_sender_ip(report_fields):
    """
    Determines the most likely external sender IP address by checking headers in order of reliability:
    1. Authentication-Results
    2. Received-SPF
    3. ARC-Authentication-Results
    4. Falls back to parsing 'Received' headers if no IP found in auth headers.
    Returns the IP address string or None.
    """
    sender_ip = None
    logging.debug("Attempting to determine sender IP...")

    # 1. Check Authentication-Results
    auth_results = get_nested_value(report_fields, ['email.headers.Authentication-Results'], default='')
    sender_ip = extract_ip_from_auth_results(auth_results)
    if sender_ip:
        logging.info(f"Sender IP found in Authentication-Results: {sender_ip}")
        return sender_ip

    # 2. Check Received-SPF
    received_spf = get_nested_value(report_fields, ['email.headers.Received-SPF'], default='')
    sender_ip = extract_ip_from_auth_results(received_spf)
    if sender_ip:
        logging.info(f"Sender IP found in Received-SPF: {sender_ip}")
        return sender_ip

    # 3. Check ARC-Authentication-Results (useful for forwarded mail)
    arc_auth_results = get_nested_value(report_fields, ['email.headers.ARC-Authentication-Results'], default='')
    sender_ip = extract_ip_from_auth_results(arc_auth_results)
    if sender_ip:
        logging.info(f"Sender IP found in ARC-Authentication-Results: {sender_ip}")
        return sender_ip

    # 4. Fallback: Parse Received headers (less reliable)
    logging.info("Sender IP not found in auth headers, trying Received headers as fallback...")
    received_headers_data = get_nested_value(report_fields, ['email.headers.Received'], default=[])
    # Ensure we have a list to iterate over
    received_headers = received_headers_data if isinstance(received_headers_data, list) else [received_headers_data] if isinstance(received_headers_data, str) else []

    sender_ip = extract_ip_from_received(received_headers)

    if sender_ip:
         logging.info(f"Using Sender IP found via Received headers fallback: {sender_ip}")
         # Optional: Add check here to discard if IP is known internal, if needed.
    else:
        logging.warning("Could not determine a valid public sender IP from any header source.")

    return sender_ip

def url_geolocation(url):
    """
    Resolves the domain name (hostname) of a given URL to an IP address.
    Handles basic parsing and potential errors during DNS lookup.
    """
    if not url or not isinstance(url, str):
         return "Invalid URL provided"
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc
        if not hostname:
            # Handle URLs missing scheme (e.g., "www.google.com/path")
            if '//' not in url and '.' in url:
                 hostname = url.split('/')[0] # Basic guess
            else:
                 logging.warning(f"Cannot extract hostname from URL: {url}")
                 return "Invalid URL (no domain)"

        # Remove port if present (e.g., "example.com:8080")
        hostname = hostname.split(':')[0]

        logging.debug(f"Resolving hostname '{hostname}' for geolocation.")
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
         logging.warning(f"Could not resolve domain: {hostname} (from URL: {url})")
         return "Could not resolve domain"
    except Exception as e:
        # Catch other potential errors like invalid hostname characters
        logging.error(f"Error during geolocation for {url}: {e}")
        return f"Error resolving domain: {e}"

def whois_lookup(ip_address):
    """
    Performs a WHOIS lookup for a given public IP address using the ipwhois library (RDAP).
    Returns the parsed WHOIS data dictionary or an error dictionary.
    """
    if not is_valid_public_ip(ip_address):
         return {"error": "Invalid or non-public IP for WHOIS lookup"}
    try:
        logging.info(f"Performing WHOIS lookup for {ip_address}")
        obj = IPWhois(ip_address)
        # Use RDAP (preferred) lookup with limited depth for efficiency
        results = obj.lookup_rdap(depth=1)
        logging.info(f"WHOIS lookup successful for {ip_address}")
        return results
    except Exception as e:
        # Catch potential exceptions from the ipwhois library or network issues
        logging.error(f"WHOIS lookup failed for {ip_address}: {e}", exc_info=True)
        return {"error": f"WHOIS lookup failed: {e}"}

def format_whois_data(whois_data):
    """
    Formats the raw WHOIS data dictionary (from ipwhois) into a readable string.
    Attempts to dynamically find relevant organization and technical contact info.
    """
    # Handle error states or empty data
    if not whois_data or (isinstance(whois_data, dict) and whois_data.get("error")):
        return f"WHOIS Error: {whois_data.get('error', 'No data available')}"
    if not isinstance(whois_data, dict):
        logging.warning(f"Unexpected WHOIS data format received: {type(whois_data)}")
        return "WHOIS Error: Unexpected data format"

    # Helper to get specific contact details (email, phone) from an entity
    def get_contact_detail(entity, detail_type):
        contact = entity.get('contact') if isinstance(entity, dict) else None
        if not isinstance(contact, dict): return 'N/A'
        details = contact.get(detail_type, [])
        if not isinstance(details, list): return 'N/A'
        # Extract 'value' from list of dictionaries like [{'value': '...', 'label': '...'}, ...]
        values = [item.get('value') for item in details if isinstance(item, dict) and item.get('value')]
        return ', '.join(values) if values else 'N/A'

    # Extract Network Information
    network_info = whois_data.get('network', {}) or {} # Ensure it's a dict
    cidr = network_info.get('cidr', 'N/A')
    net_name = network_info.get('name', 'N/A')
    country = network_info.get('country', 'N/A')

    # Extract ASN Information
    asn_registry = whois_data.get('asn_registry', 'N/A')
    asn = whois_data.get('asn', 'N/A')
    asn_cidr = whois_data.get('asn_cidr', 'N/A')
    asn_country_code = whois_data.get('asn_country_code', country) # Fallback to network country
    asn_description = whois_data.get('asn_description', 'N/A')

    # Dynamically find Organization and Technical Contact from Entities
    org_name, tech_name, tech_email, tech_phone = 'N/A', 'N/A', 'N/A', 'N/A'
    entities = whois_data.get('objects', {})
    if isinstance(entities, dict):
        for entity_data in entities.values():
             if not isinstance(entity_data, dict): continue
             roles = entity_data.get('roles', [])
             contact_info = entity_data.get('contact', {}) if isinstance(entity_data.get('contact'), dict) else {}
             current_org_name = contact_info.get('organization') or contact_info.get('name') # Prefer org name

             # Assign Organization Name (usually 'registrant' or 'administrative')
             if ('registrant' in roles or 'administrative' in roles) and current_org_name and org_name == 'N/A':
                  org_name = current_org_name

             # Assign Technical Contact Details
             if 'technical' in roles:
                  if current_org_name and tech_name == 'N/A': tech_name = current_org_name
                  if get_contact_detail(entity_data, 'email') != 'N/A' and tech_email == 'N/A':
                       tech_email = get_contact_detail(entity_data, 'email')
                  if get_contact_detail(entity_data, 'phone') != 'N/A' and tech_phone == 'N/A':
                       tech_phone = get_contact_detail(entity_data, 'phone')

    # Build the formatted output string
    whois_output = [
        f"- ASN Registry: {asn_registry}",
        f"- ASN: {asn}",
        f"- ASN CIDR: {asn_cidr}",
        f"- ASN Country Code: {asn_country_code}",
        f"- ASN Description: {asn_description}", # Keep description even if N/A
        f"- IP Range: {cidr}",
        f"- Network Name: {net_name}",
        f"- Organization: {org_name}", # Keep org name even if N/A initially
        f"- Tech Contact: {tech_name}", # Keep tech contact even if N/A initially
        f"- Tech Email: `{tech_email}`" if tech_email != 'N/A' else "- Tech Email: N/A",
        f"- Tech Phone: {tech_phone}",
    ]
    # Filter out lines that are just "Key: N/A", unless specified to keep
    keep_na_keys = {'- ASN Description:', '- Organization:', '- Tech Contact:'}
    cleaned_output = [line for line in whois_output if not line.endswith(': N/A') or any(line.startswith(k) for k in keep_na_keys)]

    return "\n".join(cleaned_output) if cleaned_output else "No relevant WHOIS details found."

def check_ip_abuseipdb(ip):
    """
    Checks the reputation of a public IP address against the AbuseIPDB API.
    Requires ABUSEIPDB_API_KEY to be set.
    Returns the API response dictionary or an error dictionary.
    """
    global ABUSEIPDB_API_KEY # Use the potentially modified global variable
    if not is_valid_public_ip(ip):
        return {"error": "Invalid or non-public IP for AbuseIPDB check"}
    if not ABUSEIPDB_API_KEY: # Check if key was missing/invalidated
        logging.warning("AbuseIPDB check skipped: API key not configured.")
        return {"error": "AbuseIPDB API key not configured."}

    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': ''} # Check reports within 90 days
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}

    try:
        logging.info(f"Checking AbuseIPDB for IP: {ip}")
        response = requests.get(url, headers=headers, params=params, timeout=15)
        response.raise_for_status() # Raises HTTPError for 4xx/5xx responses
        logging.info(f"AbuseIPDB check successful for IP: {ip}")
        return response.json() # Parse JSON response
    except JSONDecodeError:
        logging.error(f"AbuseIPDB Error: Failed parsing JSON for IP {ip}. Status: {response.status_code}. Response: {response.text[:200]}")
        return {"error": "Failed to parse JSON response"}
    except RequestException as e:
        status_code = e.response.status_code if e.response is not None else "N/A"
        logging.error(f"AbuseIPDB API request failed for IP {ip}: Status {status_code}, Error: {e}")
        return {"error": f"API request failed: Status {status_code}, {e}"}
    except Exception as e:
        logging.error(f"Unexpected error checking AbuseIPDB for IP {ip}: {e}", exc_info=True)
        return {"error": f"An unexpected error occurred: {e}"}

# --- File/Attachment Functions ---

def identify_file_types(attachments):
    """
    Identifies file extensions from a list of attachment dictionaries.
    Flags extensions listed in DANGEROUS_FILE_TYPES.
    Returns a list of dictionaries containing file name and warning message.
    """
    file_warnings = []
    if not isinstance(attachments, list):
        return file_warnings # Return empty list if input is not a list

    for attachment_dict in attachments:
        if not isinstance(attachment_dict, dict): continue # Skip non-dictionary items

        # Extract file name robustly using get_nested_value
        file_name = get_nested_value(attachment_dict, ['file.name'], default=None)

        if not file_name or not isinstance(file_name, str) or '.' not in file_name:
             warning_msg = "Unknown file type or name missing"
             # Add hash prefix for context if name is missing
             fhash_preview = get_nested_value(attachment_dict, ['file.hash.sha256'], default="N/A")[:10]
             display_name = file_name or f"Unknown (hash:{fhash_preview}...)"
             file_warnings.append({"name": display_name, "warning": warning_msg})
             continue # Skip if no valid name/extension found

        # Extract extension and check against dangerous list
        file_extension = file_name.split('.')[-1].lower()
        warning_msg = f"File type: {file_extension.upper()}"
        if file_extension in DANGEROUS_FILE_TYPES:
            # Use markdown bold for dangerous types in the warning message
            warning_msg = f"Potentially dangerous file type: **{file_extension.upper()}**"

        file_warnings.append({"name": file_name, "warning": warning_msg})

    return file_warnings

def check_file_hash_vt(file_hash):
    """
    Checks a file hash (MD5, SHA1, SHA256) against the VirusTotal API v3.
    Requires VIRUSTOTAL_API_KEY to be set. Enforces rate limiting sleep.
    Returns the API response dictionary or an error dictionary.
    """
    global VIRUSTOTAL_API_KEY # Use potentially modified global
    if not VIRUSTOTAL_API_KEY: # Check if key was missing/invalidated
        logging.warning(f"VirusTotal hash check skipped for {file_hash[:10]}...: API key not configured.")
        return {"error": "VirusTotal API key not configured."}
    # Basic validation of hash format
    if not file_hash or not isinstance(file_hash, str) or len(file_hash) not in {32, 40, 64}:
        logging.warning(f"Invalid hash format provided for VT check: {file_hash}")
        return {"error": "Invalid hash format"}

    headers = {'x-apikey': VIRUSTOTAL_API_KEY, 'Accept': 'application/json'}
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'

    logging.info(f"Checking VT for file hash: {file_hash[:10]}... (Waiting {VT_PUBLIC_API_SLEEP}s for rate limit)")
    sleep(VT_PUBLIC_API_SLEEP) # Pause *before* the request to respect rate limit

    try:
        response = requests.get(url, headers=headers, timeout=20)
        # Process response based on status code
        if response.status_code == 200:
            logging.info(f"VT hash check successful for {file_hash[:10]}.")
            return response.json()
        elif response.status_code == 404:
            logging.warning(f"VT hash check: Hash {file_hash[:10]} not found (404).")
            return {"error": "Hash not found on VirusTotal"}
        else:
            # Raise an exception for other client/server errors (like 401, 429, 5xx)
            logging.error(f"VT hash check error for {file_hash[:10]}: Status {response.status_code}, Response: {response.text[:200]}")
            response.raise_for_status()
            # This return is unlikely to be reached if raise_for_status works, but acts as a fallback
            return {"error": f"VT API Error: Status {response.status_code}"}
    except JSONDecodeError:
        logging.error(f"VT hash check: Failed parsing JSON for hash {file_hash[:10]}. Status: {response.status_code}. Response: {response.text[:200]}")
        return {"error": "Failed to parse JSON response"}
    except RequestException as e:
        status_code = e.response.status_code if e.response is not None else "N/A"
        logging.error(f"VT hash check: API request failed for hash {file_hash[:10]}: Status {status_code}, Error: {e}")
        return {"error": f"API request failed: Status {status_code}, {e}"}
    except Exception as e:
        logging.error(f"VT hash check: Unexpected error for hash {file_hash[:10]}: {e}", exc_info=True)
        return {"error": f"An unexpected error occurred: {e}"}

# --- URL Analysis Functions ---

def generate_url_id_vt(url):
    """Generates the Base64 URL-safe ID required by the VirusTotal API v3 for URLs."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def check_url_vt(url):
    """
    Checks a URL against the VirusTotal API v3.
    Requires VIRUSTOTAL_API_KEY. Enforces rate limiting sleep.
    Generates the necessary URL ID for the API call.
    Returns the API response dictionary or an error dictionary.
    """
    global VIRUSTOTAL_API_KEY # Use potentially modified global
    if not VIRUSTOTAL_API_KEY: # Check if key was missing/invalidated
        logging.warning(f"VirusTotal URL check skipped for {url[:60]}...: API key not configured.")
        return {"error": "VirusTotal API key not configured."}
    # Validate URL format before proceeding
    if not url or not isinstance(url, str) or not url.startswith(('http://', 'https://')):
         logging.warning(f"Invalid URL format provided for VT check: {url}")
         return {"error": "Invalid URL format for VT check"}

    try:
        url_id = generate_url_id_vt(url)
    except Exception as e:
        logging.error(f"Failed to generate VirusTotal URL ID for '{url}': {e}")
        return {"error": "Failed to generate VT URL ID"}

    headers = {'x-apikey': VIRUSTOTAL_API_KEY, 'Accept': 'application/json'}
    api_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'

    logging.info(f"Checking VT for URL: {url[:60]}... (Waiting {VT_PUBLIC_API_SLEEP}s for rate limit)")
    sleep(VT_PUBLIC_API_SLEEP) # Pause *before* the request

    try:
        response = requests.get(api_url, headers=headers, timeout=25) # Longer timeout for URL scans
        # Process response
        if response.status_code == 200:
            logging.info(f"VT URL check successful for: {url[:60]}.")
            return response.json()
        elif response.status_code == 404:
            logging.warning(f"VT URL check: URL '{url[:60]}' (ID: {url_id}) not found on VT (404).")
            # Consider submitting the URL for analysis here if desired
            # submit_url_for_analysis(url)
            return {"error": "URL not found on VirusTotal"}
        else:
            logging.error(f"VT URL check error for '{url[:60]}': Status {response.status_code}, Response: {response.text[:200]}")
            response.raise_for_status() # Raise for other errors (401, 429, 5xx)
            return {"error": f"VT API Error: Status {response.status_code}"} # Fallback
    except JSONDecodeError:
        logging.error(f"VT URL check: Failed parsing JSON for URL '{url[:60]}'. Status: {response.status_code}. Response: {response.text[:200]}")
        return {"error": "Failed to parse JSON response"}
    except RequestException as e:
        status_code = e.response.status_code if e.response is not None else "N/A"
        logging.error(f"VT URL check: API request failed for URL '{url[:60]}': Status {status_code}, Error: {e}")
        return {"error": f"API request failed: Status {status_code}, {e}"}
    except Exception as e:
        logging.error(f"VT URL check: Unexpected error for URL '{url[:60]}': {e}", exc_info=True)
        return {"error": f"An unexpected error occurred: {e}"}

def format_vt_url_result(vt_data, url):
    """
    Formats the raw VirusTotal URL API response into a concise, readable string for output.
    Includes a link to the VT report page and a summary status (Malicious, Suspicious, Clean, etc.).
    """
    # Generate the VT GUI link for the URL
    try:
         url_id = generate_url_id_vt(url) if (url and isinstance(url, str)) else "invalid_id"
         base_link = f"https://www.virustotal.com/gui/url/{url_id}"
    except Exception:
         base_link = "https://www.virustotal.com/gui/" # Fallback link

    # Handle specific error conditions passed down from the check function
    if isinstance(vt_data, dict) and vt_data.get("error") == "VirusTotal API key not configured.":
         return "VirusTotal Check Skipped (API Key Missing)"
    if isinstance(vt_data, dict) and vt_data.get("error"):
        error_msg = vt_data["error"]
        if "not found" in error_msg.lower():
             # Link to the analysis page, which might show scan history or allow submission
             return f"[VirusTotal]({base_link}/analysis) - Not Found"
        return f"VirusTotal Error: {error_msg}" # Display other errors

    # Check if the data structure is as expected
    if not isinstance(vt_data, dict) or 'data' not in vt_data or 'attributes' not in vt_data['data']:
        logging.warning(f"Unexpected VT URL data format for {url[:60]}: {str(vt_data)[:200]}")
        return f"[VirusTotal]({base_link}) - Error: Unexpected data format"

    # Extract analysis statistics
    attributes = vt_data['data']['attributes']
    stats = attributes.get('last_analysis_stats', {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    # Determine a summary status based on detection counts
    if malicious > 0:
        status = f"**Malicious ({malicious})**"
    elif suspicious > 0:
        status = f"*Suspicious ({suspicious})*"
    elif harmless > 0 or undetected > 0:
         clean_count = harmless + undetected
         status = f"Clean ({clean_count})" if clean_count > 0 else "Clean/Undetected"
    else:
        status = "No Verdict" # Case where stats might be empty

    # Add threat names if malicious/suspicious and available
    threat_names = attributes.get("threat_names", [])
    if (malicious > 0 or suspicious > 0) and threat_names:
         # Show first 2 threat names, add ellipsis if more exist
         status += f" (Threats: {', '.join(threat_names[:2])}{'...' if len(threat_names) > 2 else ''})"

    # Return formatted string with link to the detection page and the determined status
    return f"[VirusTotal]({base_link}/detection) - {status}"

# --- Email Analysis Functions ---

def check_email_authentication(report_fields):
    """
    Checks SPF, DKIM, and DMARC results based on email headers.
    Uses Authentication-Results primarily, falls back to Received-SPF for SPF.
    Returns a dictionary with the status ('Passed', 'Failed', 'Neutral', etc.) for each protocol.
    """
    # Get relevant headers, defaulting to empty strings if not found
    auth_results = get_nested_value(report_fields, ['email.headers.Authentication-Results'], default='')
    received_spf = get_nested_value(report_fields, ['email.headers.Received-SPF'], default='')

    # Ensure inputs are strings for consistent processing
    auth_results = auth_results if isinstance(auth_results, str) else ''
    received_spf = received_spf if isinstance(received_spf, str) else ''

    # Determine which header to check for each protocol
    spf_header_to_check = received_spf or auth_results # Prefer Received-SPF if present
    dkim_header_to_check = auth_results
    dmarc_header_to_check = auth_results

    # Helper function to determine status based on keywords in the header
    def get_status(header, pass_kw='pass', fail_kw='fail'):
        header_lower = header.lower()
        # Check for primary keywords first
        if pass_kw in header_lower: return "Passed"
        if fail_kw in header_lower: return "Failed"
        # Check for secondary keywords
        if 'softfail' in header_lower: return "SoftFail"
        if 'neutral' in header_lower: return "Neutral"
        if 'temperror' in header_lower: return "TempError"
        if 'permerror' in header_lower: return "PermError"
        if 'none' in header_lower: return "None"
        # Fallback if header exists but status is unclear or header is missing
        if not header: return "Not Found"
        return "Unknown"

    # Determine status for each protocol
    spf_status = get_status(spf_header_to_check, pass_kw='spf=pass', fail_kw='spf=fail')
    # Handle SenderID as another SPF-like check if present
    if spf_status in ["Not Found", "None", "Unknown"] and 'senderid=pass' in auth_results.lower():
        spf_status = "Passed (SenderID)"
    elif spf_status in ["Not Found", "None", "Unknown"] and 'senderid=fail' in auth_results.lower():
        spf_status = "Failed (SenderID)"

    dkim_status = get_status(dkim_header_to_check, pass_kw='dkim=pass', fail_kw='dkim=fail')
    dmarc_status = get_status(dmarc_header_to_check, pass_kw='dmarc=pass', fail_kw='dmarc=fail')

    return {
        "SPF": spf_status,
        "DKIM": dkim_status,
        "DMARC": dmarc_status
    }

def format_email_body(body):
    """
    Performs basic formatting on the email body plain text for better readability.
    Normalizes line breaks, spacing, and adds gaps before common forwarded headers.
    """
    if not isinstance(body, str): return "N/A"
    # Normalize line endings to \n
    body = re.sub(r'\r\n', '\n', body)
    # Limit consecutive newlines to a maximum of two (one blank line)
    body = re.sub(r'\n{3,}', '\n\n', body)
    # Normalize whitespace (spaces, tabs) to single spaces
    body = re.sub(r'[ \t]+', ' ', body)
    # Remove trailing spaces from lines
    body = re.sub(r' +\n', '\n', body)
    # Add line breaks before forwarded/original message markers if they start a line
    body = re.sub(r'(^\s*-{2,}\s*(?:Forwarded message|Original message)\s*-{2,})', r'\n\n\1', body, flags=re.MULTILINE | re.IGNORECASE)
    # Add line breaks before common headers if they appear at the start of a line in the body
    body = re.sub(r'(^\s*(?:From|Date|Subject|To): )', r'\n\n\1', body, flags=re.MULTILINE)

    return body.strip() # Remove leading/trailing whitespace from the final body

# --- Main Processing Function ---

def process_phishing_report(report):
    """
    Orchestrates the analysis of the phishing report JSON data.
    Extracts key email fields, determines sender IP, analyzes headers,
    extracts/decodes URLs, processes attachments, and performs external lookups
    (WHOIS, AbuseIPDB, VirusTotal) using concurrent and sequential execution.
    Returns a dictionary containing all processed results.
    """
    if not isinstance(report, dict):
        logging.error("Invalid report format: Input is not a dictionary.")
        return None

    # Determine the primary source of email fields ('fields' or '_source')
    if 'fields' in report and isinstance(report.get('fields'), dict):
        fields = report['fields']
        logging.debug("Using 'fields' as primary data source.")
    elif '_source' in report and isinstance(report.get('_source'), dict):
        fields = report['_source']
        logging.warning("Using '_source' as primary data source ('fields' missing or invalid).")
    else:
        logging.error("Invalid report format: Cannot find 'fields' or '_source' dictionary.")
        return None

    results = {} # Initialize dictionary to store analysis results

    # --- 1. Extract Basic Email Information ---
    logging.info("Extracting basic email information...")
    results['to'] = extract_email(get_nested_value(fields, ['email.reporter'], 'N/A'))
    results['from'] = extract_email(get_nested_value(fields, ['email.from.address'], 'N/A'))
    results['reply_to'] = extract_email(get_nested_value(fields, ['email.headers.Reply-To'], 'N/A'))
    # Handle subject potentially being in different fields or encoded
    subject_text = get_nested_value(fields, ['email.subject.text']) # Preferred field
    subject_raw = get_nested_value(fields, ['email.subject'])     # Fallback field
    results['subject'] = subject_text if subject_text else (subject_raw if subject_raw else 'N/A')
    # Extract and format body text
    raw_body = get_nested_value(fields, ['email.body_plaintext'], default='N/A')
    results['body'] = format_email_body(raw_body)

    # --- 2. Analyze Email Authentication Headers ---
    logging.info("Checking email authentication headers...")
    results['email_authentication'] = check_email_authentication(fields)

    # --- 3. Determine Sender IP Address ---
    logging.info("Determining sender IP address...")
    sender_ip = determine_sender_ip(fields)
    results['sender_ip'] = sender_ip

    # --- 4. Process Attachments ---
    logging.info("Processing attachments...")
    attachments_list = get_nested_value(fields, ['email.attachments'], [])
    attachments_list = attachments_list if isinstance(attachments_list, list) else [] # Ensure list type
    # Identify file types and check for dangerous extensions
    results['file_type_warnings'] = identify_file_types(attachments_list)
    # Extract valid file hashes for VirusTotal checking
    file_hashes = []
    for att_dict in attachments_list:
         if not isinstance(att_dict, dict): continue
         name = get_nested_value(att_dict, ['file.name'], default="Unknown Name")
         fhash = get_nested_value(att_dict, ['file.hash.sha256'], default=None)
         name = str(name) if not isinstance(name, str) else name # Ensure name is string
         # Add if hash looks valid (SHA256 length)
         if fhash and isinstance(fhash, str) and len(fhash) == 64:
             file_hashes.append({"name": name, "hash": fhash})
         elif name != "Unknown Name":
              logging.warning(f"Attachment '{name}' found but missing/invalid SHA256 hash.")

    # --- 5. Extract and Decode URLs ---
    logging.info("Extracting and decoding URLs...")
    urls_data = extract_and_decode_urls(fields)
    results['urls'] = urls_data # Store list of {"original_url": ..., "final_url": ...}

    # --- 6. Perform Concurrent and Sequential API Lookups ---
    logging.info("Starting API lookups...")
    # Use ThreadPoolExecutor for managing concurrent/sequential tasks
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Dictionaries to hold future objects for tracking
        futures = {}         # For concurrent tasks (WHOIS, AbuseIPDB, GeoIP)
        vt_file_futures = {} # For sequential VirusTotal file hash checks
        vt_url_futures = {}  # For sequential VirusTotal URL checks

        # -- Submit Concurrent Tasks --
        # Submit IP-related tasks if a valid sender IP was found
        if sender_ip:
            logging.info(f"Submitting concurrent tasks for IP: {sender_ip}")
            futures[executor.submit(check_ip_abuseipdb, sender_ip)] = "abuseipdb"
            futures[executor.submit(whois_lookup, sender_ip)] = "whois"
        else:
            # Set default error results if no IP to check
            results['abuseipdb'] = {"error": "No valid sender IP found"}
            results['whois_raw'] = {"error": "No valid sender IP found"}

        # Submit URL Geolocation tasks (these can run concurrently)
        logging.info(f"Submitting {len(urls_data)} URL geolocation tasks...")
        url_geo_futures = {executor.submit(url_geolocation, u['final_url']): u['final_url'] for u in urls_data}
        futures.update(url_geo_futures) # Add these to the main concurrent futures dictionary

        # -- Prepare Sequential Tasks (VirusTotal) --
        # Map futures for VT checks, but execution will be handled sequentially later
        logging.info(f"Preparing {len(file_hashes)} VT file hash checks...")
        vt_file_futures = {f['hash']: executor.submit(check_file_hash_vt, f['hash']) for f in file_hashes}

        logging.info(f"Preparing {len(urls_data)} VT URL checks...")
        vt_url_futures = {u['final_url']: executor.submit(check_url_vt, u['final_url']) for u in urls_data}

        # -- Process Concurrent Results --
        total_concurrent_tasks = len(futures)
        url_ip_map = {} # To store resolved IPs for URLs
        if total_concurrent_tasks > 0:
            logging.info(f"Waiting for {total_concurrent_tasks} concurrent tasks...")
            # Use alive_bar for progress visualization
            with alive_bar(total_concurrent_tasks, title="Analyzing IP/URLs (Phase 1)") as bar:
                # Process results as they complete using as_completed
                for future in as_completed(futures):
                    try:
                        result = future.result() # Retrieve result (or exception) from the completed future
                        task_type = futures[future] # Identify the task type

                        # Store results based on task type
                        if task_type == "abuseipdb":
                            results['abuseipdb'] = result
                        elif task_type == "whois":
                            results['whois_raw'] = result # Store raw WHOIS data
                        elif task_type in url_geo_futures.values(): # Check if it was a URL geo task
                            url = task_type # The URL was stored as the identifier
                            url_ip_map[url] = result # Map the resolved IP to the final URL

                    except Exception as exc:
                        # Log exceptions from concurrent tasks
                        failed_task_desc = futures.get(future, "Unknown task") # Get task description
                        logging.error(f'Concurrent task "{failed_task_desc}" generated an exception: {exc}', exc_info=True)
                        # Assign error status to results if possible
                        if futures.get(future) == "abuseipdb": results['abuseipdb'] = {"error": f"Task failed: {exc}"}
                        if futures.get(future) == "whois": results['whois_raw'] = {"error": f"Task failed: {exc}"}
                        # Geolocation errors will be handled later when updating url_data

                    finally:
                        bar() # Update progress bar

        # Add resolved IP addresses to the URL data after concurrent tasks are done
        for url_data in results['urls']:
            url_data['ip_address'] = url_ip_map.get(url_data['final_url'], "Geolocation Error or Skipped")

        # -- Process Sequential VirusTotal Tasks --
        # Process File Hashes (sequential due to rate limits)
        vt_file_results = {}
        total_vt_files = len(vt_file_futures)
        if total_vt_files > 0:
             logging.info(f"Executing {total_vt_files} VT file hash checks sequentially...")
             with alive_bar(total_vt_files, title="Checking VT Hashes (Sequential)") as bar:
                 # Iterate through the prepared file futures
                 for fhash, future in vt_file_futures.items():
                     try:
                         # future.result() blocks here, the sleep is inside check_file_hash_vt
                         vt_file_results[fhash] = future.result()
                     except Exception as e:
                         logging.error(f"Error getting VT file result for {fhash[:10]}: {e}", exc_info=True)
                         vt_file_results[fhash] = {"error": f"Task execution failed: {e}"}
                     finally:
                        bar() # Update progress after each check completes

        # Process URLs (sequential due to rate limits)
        vt_url_results = {}
        total_vt_urls = len(vt_url_futures)
        if total_vt_urls > 0:
            logging.info(f"Executing {total_vt_urls} VT URL checks sequentially...")
            with alive_bar(total_vt_urls, title="Checking VT URLs (Sequential)") as bar:
                # Iterate through the prepared URL futures
                for url, future in vt_url_futures.items():
                    try:
                        # future.result() blocks here, sleep is inside check_url_vt
                        vt_url_results[url] = future.result()
                    except Exception as e:
                        logging.error(f"Error getting VT URL result for {url[:50]}: {e}", exc_info=True)
                        vt_url_results[url] = {"error": f"Task execution failed: {e}"}
                    finally:
                        bar() # Update progress

    # --- 7. Format Final Results ---
    logging.info("Formatting WHOIS data...")
    results['whois_formatted'] = format_whois_data(results.get('whois_raw', {}))

    logging.info("Formatting VirusTotal file results...")
    results['files_vt'] = [] # Initialize list for formatted file results
    for file_info in file_hashes:
        fhash = file_info['hash']
        # Get the VT result for this hash, default to an error dict if missing
        vt_result_data = vt_file_results.get(fhash, {"error": "Result not processed or missing"})
        link = "No VT Link" # Default link status
        status = "Error or Skipped" # Default status

        # Determine status and link based on the VT result data
        if isinstance(vt_result_data, dict) and vt_result_data.get("error") == "VirusTotal API key not configured.":
             status = "Skipped (API Key Missing)"
             link = status # Use status message as link placeholder
        elif isinstance(vt_result_data, dict) and 'data' in vt_result_data and 'id' in vt_result_data['data']:
            file_id = vt_result_data['data']['id'] # VT File ID (often the hash itself)
            link = f"https://www.virustotal.com/gui/file/{file_id}/detection" # Link to VT detection page
            # Determine status from analysis stats
            stats = vt_result_data['data'].get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            if malicious > 0: status = f"**Malicious ({malicious})**"
            elif suspicious > 0: status = f"*Suspicious ({suspicious})*"
            else: status = "Clean/Undetected"
        elif isinstance(vt_result_data, dict) and vt_result_data.get("error"):
            # Handle errors like "Not Found" or other API errors
            status = f"Error: {vt_result_data['error']}"
            if "not found" in status.lower():
                status = "Not Found"
                # Provide a link even if not found, maybe it exists now
                link = f"https://www.virustotal.com/gui/file/{fhash}/detection"

        # Append formatted file result
        results['files_vt'].append({
            "name": file_info['name'],
            "hash": fhash,
            "virustotal_link": link,
            "virustotal_status": status
        })

    logging.info("Formatting VirusTotal URL results...")
    # Add the formatted VT result string to each URL dictionary
    for url_data in results['urls']:
        final_url = url_data['final_url']
        vt_result_data = vt_url_results.get(final_url, {"error": "Result not processed or missing"})
        url_data['virustotal_formatted'] = format_vt_url_result(vt_result_data, final_url)

    logging.info("Phishing report processing complete.")
    return results

# --- Output Formatting Function ---

def format_output(results):
    """
    Formats the aggregated analysis results into two strings suitable for output:
    1. A short description summarizing the report.
    2. A detailed markdown-formatted report for pasting into tickets/notes.
    """
    if not results:
        logging.error("Cannot format output: No results data provided.")
        return None, None

    # --- Generate Short Description ---
    to_addr = results.get('to', 'N/A')
    from_addr = results.get('from', 'N/A')
    subject_str = results.get('subject', 'N/A')

    # Attempt to decode Base64 encoded subjects (common format: =?UTF-8?B?...?=)
    if isinstance(subject_str, str) and subject_str.startswith('=?') and subject_str.endswith('?='):
         try:
              from email.header import decode_header
              # Decode header parts, handling potential multiple encodings/parts
              decoded_parts = decode_header(subject_str)
              subject_str = ' '.join([
                  part.decode(encoding or 'utf-8', 'ignore') if isinstance(part, bytes) else part
                  for part, encoding in decoded_parts
              ])
         except Exception as e:
              logging.warning(f"Could not decode subject '{subject_str}': {e}")
              # Keep original encoded subject if decoding fails

    # Construct the description sentence
    if subject_str and subject_str != 'N/A':
        description_output = f"`{to_addr}` reported an email originating from `{from_addr}` with the subject `{subject_str}`."
    else:
        description_output = f"`{to_addr}` reported an email originating from `{from_addr}` with no subject."

    # --- Generate Detailed Report (Markdown Formatted) ---
    output = [] # List to hold lines of the detailed report

    # Basic Email Info
    output.append(f"To: `{to_addr}`")
    output.append(f"From: `{from_addr}`")
    reply_to = results.get('reply_to', 'N/A')
    # Only include Reply-To if it's present and different from the From address
    if reply_to and reply_to != 'N/A' and reply_to != from_addr:
        output.append(f"Reply-To: `{reply_to}`")
    output.append(f"Subject: `{subject_str}`")

    # Sender IP and Reputation Analysis
    sender_ip = results.get('sender_ip')
    if sender_ip:
        output.append(f"Sender IP: `{sender_ip}`")
        # AbuseIPDB Results
        abuse_res = results.get('abuseipdb', {})
        output.append("\n***AbuseIPDB Result:***")
        if isinstance(abuse_res, dict) and 'data' in abuse_res:
            data = abuse_res['data']
            score = data.get('abuseConfidenceScore', 0)
            # Highlight scores indicating high confidence of abuse
            score_str = f"**{score}%** (High Confidence)" if score >= 75 else f"{score}%"
            output.append(f"  - Abuse Score: {score_str}")
            output.append(f"  - Country: {data.get('countryCode', 'N/A')}")
            output.append(f"  - ISP: {data.get('isp', 'N/A')}")
            output.append(f"  - Domain: {data.get('domain', 'N/A')}")
            output.append(f"  - Usage Type: {data.get('usageType', 'N/A')}")
            output.append(f"  - Reports: {data.get('totalReports', 'N/A')}")
            output.append(f"  - [View on AbuseIPDB](https://www.abuseipdb.com/check/{sender_ip})") # Direct link
        elif isinstance(abuse_res, dict) and abuse_res.get("error"):
             output.append(f"  - Error: {abuse_res['error']}") # Display API/check errors
        else:
            output.append("  - No data returned or unexpected format.")

        # WHOIS Results
        whois_fmt = results.get('whois_formatted', "Error retrieving WHOIS")
        output.append("\n***WHOIS Data:***")
        output.append(f"{whois_fmt}") # Append the pre-formatted WHOIS string

    else:
        # Message if no valid public sender IP was determined
        output.append("Sender IP: `No valid public IP address found`")

    # Email Authentication Results
    auth = results.get('email_authentication', {})
    if auth:
        output.append("\n***Email Authentication:***")
        # Provide brief explanations for common statuses
        spf_status = auth.get('SPF', 'N/A')
        dkim_status = auth.get('DKIM', 'N/A')
        dmarc_status = auth.get('DMARC', 'N/A')
        spf_expl = "(Authorized Sender)" if spf_status == "Passed" else "(Sender Not Authorized or Issue)" if spf_status in ["Failed", "SoftFail"] else "(Status Unknown/Not Checked)"
        dkim_expl = "(Signature Valid)" if dkim_status == "Passed" else "(Signature Invalid or Issue)" if dkim_status == "Failed" else "(Not Signed or Issue)"
        dmarc_expl = "(Policy Alignment OK)" if dmarc_status == "Passed" else "(Policy Violation or Issue)" if dmarc_status == "Failed" else "(No Policy or Issue)"
        output.append(f"  - **SPF:** `{spf_status}` {spf_expl}")
        output.append(f"  - **DKIM:** `{dkim_status}` {dkim_expl}")
        output.append(f"  - **DMARC:** `{dmarc_status}` {dmarc_expl}")

    # Attachment File Type Warnings
    warnings = results.get('file_type_warnings', [])
    if warnings:
        output.append("\n***Attachment Types:***")
        for warning in warnings:
            name_fmt = f"`{warning.get('name', 'Unknown')}`" # Use code formatting for filenames
            output.append(f"  - {name_fmt}: {warning.get('warning', 'N/A')}") # Display warning (may include markdown)

    # Email Body Preview
    body = results.get('body', 'N/A')
    output.append("\n***Body Preview (Plain Text):***")
    if body and body != 'N/A':
        output.append("```text") # Use markdown code block for plain text
        max_body_len = 1500 # Limit preview length
        body_preview = body[:max_body_len]
        output.append(f"{body_preview}")
        # Indicate if body was truncated
        if len(body) > max_body_len:
             output.append("\n[... Body truncated ...]")
        output.append("```")
    else:
        output.append("`N/A or Empty`") # Message for missing/empty body

    # URLs Found and Analyzed
    urls = results.get('urls', [])
    if urls:
        output.append("\n***URLs Found:***")
        for i, url_info in enumerate(urls):
            final_url = url_info.get('final_url', 'N/A')
            original_url = url_info.get('original_url', final_url)
            # Display final URL, and original if significantly different (not just wrapper)
            url_display = f"`{final_url}`"
            is_wrapper = "urldefense" in original_url or "safelinks" in original_url
            if final_url != original_url and not is_wrapper:
                 url_display += f" (Original: `{original_url[:70]}{'...' if len(original_url)>70 else ''}`)"

            output.append(f"\n{i+1}. **URL:** {url_display}")
            output.append(f"   - **Resolved IP:** `{url_info.get('ip_address', 'N/A')}`")
            output.append(f"   - **Analysis:** {url_info.get('virustotal_formatted', 'Analysis Error/Skipped')}")

    # Files Found and Scanned (VirusTotal)
    files = results.get('files_vt', [])
    if files:
        output.append("\n***Files Found (VirusTotal Scan):***")
        for i, file_info in enumerate(files):
            output.append(f"\n{i+1}. **Name:** `{file_info.get('name', 'N/A')}`")
            output.append(f"   - **Hash (SHA256):** `{file_info.get('hash', 'N/A')}`")
            link = file_info.get('virustotal_link', 'No VT Link')
            status = file_info.get('virustotal_status', 'Unknown')
            # Create a clickable link using the status as text if link is valid
            if link != 'No VT Link' and "Skipped" not in link and "Error" not in status:
                 output.append(f"   - **Status:** [{status}]({link})")
            else:
                 output.append(f"   - **Status:** {status}") # Display status plainly if link is invalid/error

    # Join all parts of the detailed report into a single string
    return description_output, "\n".join(output)

# --- Main Execution Block ---

def main():
    """
    Main function to run the phishing analysis script.
    Checks API keys, gets JSON input, processes the report,
    formats the results, and copies them to the clipboard.
    """
    # --- API Key Availability Check ---
    global VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY # Allow modification of global vars if keys invalid
    vt_key_ok = True
    abuse_key_ok = True

    # Check if VirusTotal key is missing or is the default placeholder
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == 'YOUR_DEFAULT_VT_KEY':
        print("❌ ERROR: VIRUSTOTAL_API_KEY not set or is placeholder.")
        print("   Please set it via environment variable or .env file.")
        print("   VirusTotal checks will be skipped.")
        VIRUSTOTAL_API_KEY = None # Set to None to signal functions to skip calls
        vt_key_ok = False

    # Check if AbuseIPDB key is missing or is the default placeholder
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY == 'YOUR_DEFAULT_ABUSEIPDB_KEY':
        print("❌ ERROR: ABUSEIPDB_API_KEY not set or is placeholder.")
        print("   Please set it via environment variable or .env file.")
        print("   AbuseIPDB checks will be skipped.")
        ABUSEIPDB_API_KEY = None # Set to None to signal functions to skip calls
        abuse_key_ok = False

    # Pause if keys are missing to ensure user sees the warning
    if not vt_key_ok or not abuse_key_ok:
         input("\n>>> Press Enter to continue without the missing API key(s)...")
    # --- End API Key Check ---

    # --- 1. Get JSON Input ---
    try:
        print("\nAttempting to read JSON report from clipboard...")
        json_input = pyperclip.paste()
        # Check if clipboard content looks like JSON before trying to parse
        if not json_input or not json_input.strip().startswith(('{', '[')):
            print("Clipboard empty or doesn't contain JSON. Please paste JSON input directly:")
            print("(Paste JSON, press Enter, then Ctrl+D/Ctrl+Z + Enter to finish)")
            # Read multi-line input from terminal
            json_input_lines = []
            while True:
                 try: line = input(); json_input_lines.append(line)
                 except EOFError: break # Stop reading on EOF (Ctrl+D/Z)
            json_input = "\n".join(json_input_lines)

        if not json_input.strip(): # Check if input is empty after trying clipboard/manual input
             print("No JSON input received. Exiting.")
             return

        # Parse the collected JSON string
        report = json.loads(json_input)
        logging.info("Successfully loaded JSON report.")
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON input provided: {e}")
        print(f"\n❌ Error: Invalid JSON format. Could not parse.")
        print(f"   Details: {e}")
        print("\n--- Input Start (First 500 chars) ---")
        print(json_input[:500])
        print("--- Input End ---")
        return # Exit if JSON is invalid
    except Exception as e:
        logging.error(f"Unexpected error getting input: {e}", exc_info=True)
        print(f"\n❌ An unexpected error occurred while getting input: {e}")
        return

    # --- 2. Process the Report ---
    print("\nProcessing report... (API calls may take time due to rate limits)")
    start_time = time()
    # Call the main processing function
    results = process_phishing_report(report)
    processing_time = time() - start_time
    logging.info(f"Report processing finished in {processing_time:.2f} seconds.")
    print(f"Processing finished in {processing_time:.2f} seconds.")

    # --- 3. Format and Output Results ---
    if results:
        print("\nFormatting results for output...")
        description, detailed_report = format_output(results)

        # Copy short description to clipboard
        if description:
            try:
                pyperclip.copy(description)
                print("\n✅ Short description copied to clipboard.")
                print("   Paste it now (e.g., into ticket title/summary).")
            except Exception as e:
                logging.error(f"Failed to copy description to clipboard: {e}")
                print(f"\n⚠️ Failed to copy description to clipboard: {e}")
                print("\n--- Description ---")
                print(description)
                print("--- End Description ---")
        else:
             print("\n⚠️ Could not generate short description.")

        # Wait for user confirmation before copying detailed report
        input("\n>>> Press Enter after pasting the description to copy the detailed report...")

        # Copy detailed report to clipboard
        if detailed_report:
            try:
                pyperclip.copy(detailed_report)
                print("\n✅ Detailed report copied to clipboard.")
                print("   Paste it into the ticket body/notes.")
                # Show a brief preview in the terminal
                print("\n--- Report Preview (Top Section) ---")
                print("\n".join(detailed_report.splitlines()[:15])) # Show first 15 lines
                print("...")
                print("--- End Preview ---")
            except Exception as e:
                 logging.error(f"Failed to copy detailed report to clipboard: {e}")
                 print(f"\n⚠️ Failed to copy detailed report to clipboard: {e}")
                 # Print full report to terminal if copy fails
                 print("\n--- Detailed Report (Full) ---")
                 print(detailed_report)
                 print("--- End Detailed Report ---")
        else:
             print("\n⚠️ Could not generate detailed report.")

    else:
        # Message if processing failed entirely
        print("\n❌ Failed to process the report. Check logs or errors above for details.")

# --- Script Entry Point ---
if __name__ == "__main__":
    main() # Execute the main function when script is run directly