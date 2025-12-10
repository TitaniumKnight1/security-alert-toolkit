import json
import pyperclip
import sys
import os
import re
import requests
import time
import traceback
import google.generativeai as genai
from datetime import datetime, timedelta
from dotenv import load_dotenv

# --- Load Environment Variables ---
load_dotenv()

# --- Configuration ---
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
GEMINI_MODEL_NAME = "gemini-2.5-flash"

# --- Helper Functions ---

def extract_customer_info(hostname, user_domain, host_domain):
    """
    Derive a concise org/customer label for use before "user".
    Priority: user.domain (if not generic like AUTH) -> host.domain -> hostname patterns.
    Examples:
        - user.domain "ENGR" -> label "ENGR"
        - user.domain "engr.tamu.edu" -> label "ENGR" (first subdomain uppercased)
        - else host.domain "engr.tamu.edu" -> label "ENGR"
    Returns a label string (e.g., "ENGR", "CSISD") or None if not identifiable.
    """
    if not hostname or hostname == "N/A":
        hostname = ""
    if not user_domain or user_domain == "N/A":
        user_domain = ""
    if not host_domain or host_domain == "N/A":
        host_domain = ""
    
    # Common customer patterns (expand as needed)
    customer_patterns = {
        'csisd': 'CSISD',
        'uiw': 'UIW',
        'tamuk': 'TAMUK',
        'tamucc': 'TAMU-CC',
        'tamu-cc': 'TAMU-CC',
        'tamuds': 'TAMU-DS',
        'tamusa': 'TAMUSA',
        'corpus': 'Corpus Christi',
        'ccad': 'Corpus Christi Army Depot',
        'ait': 'AIT',
        'agnet': 'AGNET',
        'engr': 'ENGR',
        # Add more customer patterns as discovered
    }
    
    # Generic/non-meaningful domain values to skip
    generic_domains = {'auth', 'nt authority', 'workgroup', 'builtin', ''}
    
    # PRIORITY 1: user.domain
    user_domain_lower = user_domain.lower()
    if user_domain_lower not in generic_domains and user_domain_lower:
        # If user.domain contains dots, take first label; else use whole value
        try:
            first_label = user_domain_lower.split('.')[0] if '.' in user_domain_lower else user_domain_lower
            if first_label and first_label not in generic_domains and first_label not in {'www'}:
                mapped = customer_patterns.get(first_label)
                return mapped if mapped else first_label.upper()
        except Exception:
            pass
        # Fallback to pattern mapping on user.domain
        for pattern, customer_name in customer_patterns.items():
            if pattern in user_domain_lower:
                return customer_name

    # PRIORITY 2: host.domain -> first subdomain uppercased
    host_domain_lower = host_domain.lower()
    if host_domain_lower not in generic_domains and host_domain_lower:
        try:
            first_label = host_domain_lower.split('.')[0]
            if first_label and first_label not in generic_domains and first_label not in {'www'}:
                mapped = customer_patterns.get(first_label)
                return mapped if mapped else first_label.upper()
        except Exception:
            pass
        # Pattern mapping fallback on host.domain
        for pattern, customer_name in customer_patterns.items():
            if pattern in host_domain_lower:
                return customer_name
    
    # Fall back to hostname mapping last
    hostname_lower = hostname.lower()
    for pattern, customer_name in customer_patterns.items():
        if pattern in hostname_lower:
            return customer_name
    
    return None

def generate_observation_statement(context, api_key):
    """
    Uses the Gemini API to generate a concise, natural-language observation statement
    following the "Actors, Assets, and Actions" framework with customer information included.
    Key entities are enclosed in backticks.
    """
    def determine_action(rule_name: str) -> str:
        rn = (rule_name or "").lower()
        if any(k in rn for k in ("download", "downloader")):
            return "downloaded"
        if any(k in rn for k in ("execution", "execut")):
            return "executed"
        if any(k in rn for k in ("prevent", "blocked", "block", "prevention")):
            return "triggered a prevention alert for"
        if "memory" in rn:
            return "triggered memory protection for"
        if any(k in rn for k in ("malware", "trojan", "worm", "virus", "adware", "pup")):
            return "encountered malware"
        if any(k in rn for k in ("child process", "spawn", "parent")):
            return "spawned suspicious process"
        if any(k in rn for k in ("phish", "phishing")):
            return "interacted with suspected phishing content"
        if "ransomware" in rn:
            return "triggered ransomware-related behavior"
        if any(k in rn for k in ("credential", "creds", "mimikatz")):
            return "triggered credential access behavior"
        if "lateral" in rn:
            return "triggered lateral movement behavior"
        if "persistence" in rn:
            return "established persistence-related behavior"
        if any(k in rn for k in ("defense evasion", "obfuscat", "tamper")):
            return "triggered defense evasion behavior"
        return "triggered alert involving"
    # Extract customer information
    customer = extract_customer_info(
        context.get('hostname', 'N/A'), 
        context.get('user_domain', 'N/A'),
        context.get('host_domain', 'N/A')
    )
    
    primary_actor_fallback = context.get('proc_name', "N/A") if context.get('proc_name', "N/A") != "N/A" else context.get('parent_proc_name', 'N/A')
    rule_name_val = context.get('rule_name', 'N/A')
    action_phrase = determine_action(rule_name_val)
    
    # Check if we have a distinct file entity to focus on
    file_val = context.get('file_name', 'N/A')
    proc_val = context.get('proc_name', 'N/A')
    has_distinct_file = file_val != "N/A" and file_val != proc_val

    subject_is_file = has_distinct_file or \
                      'file' in rule_name_val.lower() or \
                      'download' in rule_name_val.lower() or \
                      'execution' in rule_name_val.lower() or \
                      'malware' in rule_name_val.lower() or \
                      'prevented' in rule_name_val.lower()
    subject_fallback = context.get('file_name', 'N/A') if subject_is_file and context.get('file_name', 'N/A') != "N/A" else primary_actor_fallback

    # Build deterministic fallback with customer info included and natural alert type integration
    sentence_parts_fb = []
    if customer:
        sentence_parts_fb.append(f"{customer} user `{context.get('user_name', 'N/A')}`")
    else:
        sentence_parts_fb.append(f"User `{context.get('user_name', 'N/A')}`")

    # Describe the action with process/file context
    proc_name = context.get('proc_name', 'N/A')
    parent_proc_name = context.get('parent_proc_name', 'N/A')

    # Action (+ inline alert name when using generic phrasing)
    def _article(word: str) -> str:
        if not isinstance(word, str) or not word:
            return "a"
        return "an" if word[0].lower() in "aeiou" else "a"

    # Helper to convert rule name to natural language
    def _naturalize_alert(rule_name: str) -> str:
        """Convert a rule name like 'Malicious File Prevention Alert: Trojan' to 'malicious file prevention alert'"""
        if not rule_name or rule_name == 'N/A':
            return ""
        # Remove common noise words and colons
        cleaned = re.sub(r'(?i)(alert|prevention|threat|memory|endpoint|event)(?=\s*:)', '', rule_name)
        cleaned = cleaned.replace(":", "").strip()
        # Remove trailing descriptors after colon if any remain
        if ':' in cleaned:
            cleaned = cleaned.split(':')[0].strip()
        return cleaned.lower()

    inline_alert = False
    if rule_name_val and rule_name_val != 'N/A':
        # Always inline the alert naturally after user
        natural_alert = _naturalize_alert(rule_name_val)
        if natural_alert:
            sentence_parts_fb.append(f"triggered {_article(natural_alert)} {natural_alert} alert for")
            inline_alert = True
        else:
            sentence_parts_fb.append(action_phrase)
    else:
        sentence_parts_fb.append(action_phrase)

    # Asset
    if subject_is_file and subject_fallback != "N/A":
        sentence_parts_fb.append(f"`{subject_fallback}`")
        if proc_name != "N/A" and proc_name != subject_fallback:
            sentence_parts_fb.append(f"via process `{proc_name}`")
        if parent_proc_name != "N/A" and parent_proc_name != proc_name:
            sentence_parts_fb.append(f"from parent `{parent_proc_name}`")
    elif primary_actor_fallback != "N/A":
        sentence_parts_fb.append(f"`{primary_actor_fallback}`")
        if parent_proc_name != "N/A" and parent_proc_name != primary_actor_fallback:
            sentence_parts_fb.append(f"from parent `{parent_proc_name}`")

    # Target detail if present
    unique_fn = context.get('unique_arg_filename', 'N/A')
    if unique_fn != "N/A":
        sentence_parts_fb.append(f"targeting `{unique_fn}`")

    # Host (omit domain)
    _host_name = context.get('hostname', 'N/A')
    sentence_parts_fb.append(f"on host `{_host_name}`")

    fallback_sentence = " ".join(sentence_parts_fb).strip()
    if not fallback_sentence.endswith('.'):
        fallback_sentence += '.'

    if not api_key:
        return f"***Observation Statement***\n\n{fallback_sentence}\n(Observation generated locally due to missing GEMINI_API_KEY)"
    try:
        genai.configure(api_key=api_key)
        
        # Configure model with strict instruction to preserve semantics
        system_instruction = (
            "You are a precise text formatter. Return exactly one sentence, "
            "fixing grammar minimally. Do NOT remove or alter any backticked tokens, "
            "parenthetical segments, or the action phrase enclosed in quotes below. "
            "Do NOT paraphrase verbs. Do NOT add or remove entities."
        )
        model = genai.GenerativeModel(
            model_name=GEMINI_MODEL_NAME,
            system_instruction=system_instruction
        )

        data_for_prompt = {
            "customer": customer if customer else "N/A",
            "rule_name": context.get('rule_name', 'N/A'),
            "process_name": context.get('proc_name', 'N/A'),
            "parent_name": context.get('parent_proc_name', 'N/A'),
            "file_name": context.get('file_name', 'N/A'),
            "user_name": context.get('user_name', 'N/A'),
            "host_name": context.get('hostname', 'N/A'),
            "host_domain": context.get('host_domain', 'N/A'),
            "unique_arg_filename": context.get('unique_arg_filename', 'N/A')
        }

        # --- Ultra-Direct Prompt with guarded tokens ---
        # Build the base sentence with process context, then ask the model to minimally polish.
        prompt_parts = []
        
        # Pre-resolved action verb
        action = action_phrase
        
        # Build detailed sentence with process context
        sentence_parts = []
        
        # Start with customer and user
        if data_for_prompt['customer'] != "N/A":
            sentence_parts.append(f"{data_for_prompt['customer']} user `{data_for_prompt['user_name']}`")
        else:
            sentence_parts.append(f"User `{data_for_prompt['user_name']}`")
        
        # Integrate alert naturally after user
        def _naturalize_alert_gen(rule_name: str) -> str:
            """Convert a rule name to natural language description"""
            if not rule_name or rule_name == 'N/A':
                return ""
            # Remove common noise words and colons
            cleaned = re.sub(r'(?i)(alert|prevention|threat|memory|endpoint|event)(?=\s*:)', '', rule_name)
            cleaned = cleaned.replace(":", "").strip()
            # Remove trailing descriptors after colon if any remain
            if ':' in cleaned:
                cleaned = cleaned.split(':')[0].strip()
            return cleaned.lower()
        
        # Add alert integration or action
        if data_for_prompt['rule_name'] != "N/A":
            natural_alert = _naturalize_alert_gen(data_for_prompt['rule_name'])
            if natural_alert:
                art = "an" if natural_alert[0].lower() in "aeiou" else "a"
                sentence_parts.append(f"triggered {art} {natural_alert} alert for")
            else:
                sentence_parts.append(action)
        else:
            sentence_parts.append(action)
        
        # Determine what to highlight based on alert type
        file_name = data_for_prompt['file_name']
        process_name = data_for_prompt['process_name']
        parent_name = data_for_prompt['parent_name']
        
        # Build asset description with process context
        if file_name != "N/A" and file_name != process_name:
            # File is distinct from process
            sentence_parts.append(f"`{file_name}`")
            if process_name != "N/A":
                sentence_parts.append(f"via process `{process_name}`")
        elif process_name != "N/A":
            # Process-focused alert
            sentence_parts.append(f"`{process_name}`")
        
        # Add parent process context when available and different
        if parent_name != "N/A" and parent_name != process_name:
            sentence_parts.append(f"from parent `{parent_name}`")
        
        # Add host only (omit domain in observation statement)
        sentence_parts.append(f"on host `{data_for_prompt['host_name']}`")

        # Construct the rewrite instruction - preserve tokens and natural alert integration
        base_sentence = " ".join(sentence_parts)
        prompt_parts.append(
            "Polish minimally for grammar and readability. Keep all backticked entities (processes, files, usernames, hostnames) "
            "exactly as-is. The alert type has already been naturally integrated after the user. "
            "Preserve the alert description in natural language form. "
            "Maintain the existing structure: customer+user → alert type → asset → parent context → host.\n"
            f"Sentence: {base_sentence}"
        )

        final_prompt = "\n".join(prompt_parts)
        
        # Aggressive token configuration - giving model maximum headroom
        # The MAX_TOKENS issue suggests internal reasoning is consuming tokens
        generation_config = genai.types.GenerationConfig(
            temperature=0.0,
            max_output_tokens=8192,  # Maximum allowed - give plenty of headroom
            candidate_count=1
        )
        
        safety_settings=[
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"}, 
        ]

        print("   Sending request to Gemini API for Observation Statement...")
        response = model.generate_content(final_prompt, generation_config=generation_config, safety_settings=safety_settings)
        
        # Try to extract text even if finish_reason is MAX_TOKENS
        # The model may have produced valid output before hitting the limit
        generated_sentence = None
        try:
            if hasattr(response, 'text') and response.text:
                generated_sentence = response.text.strip()
        except Exception as e:
            print(f"   DEBUG: Could not extract text: {e}")
        
        # Check finish reason - but allow MAX_TOKENS if we got valid text
        finish_reason = None
        if hasattr(response, 'candidates') and response.candidates:
            finish_reason = response.candidates[0].finish_reason.name
        
        # If we have no text or it's empty, use fallback
        if not generated_sentence:
            reason = finish_reason if finish_reason else "Unknown (no text generated)"
            print(f"Warning: Observation generation failed. Reason: {reason}. Using fallback.")
            return f"***Observation Statement***\n\n{fallback_sentence}\n(Observation generation failed: {reason})"
        
        # If finish_reason is MAX_TOKENS but we have text, that's actually OK for a single sentence
        # Just warn if it seems incomplete
        if finish_reason == "MAX_TOKENS":
            # Check if sentence looks complete (ends with period, backtick, or similar)
            if not generated_sentence.rstrip().endswith(('.', '`', ')', ']')):
                print(f"   WARNING: Sentence may be incomplete. Using fallback.")
                return f"***Observation Statement***\n\n{fallback_sentence}\n(Observation may be incomplete due to MAX_TOKENS)"

        generated_sentence = response.text.strip()
        
        if len(generated_sentence.splitlines()) > 1:
            print("Warning: Observation statement generation returned multiple lines. Using first line.")
            generated_sentence = generated_sentence.splitlines()[0]

        # Simplified validation - just check for critical elements
        missing_elements = []
        def check_element(element_name, element_value):
            if element_value != "N/A" and f"`{element_value}`" not in generated_sentence:
                missing_elements.append(element_name)

        # Validate critical elements: user, host, verb/alert presence
        check_element("user name", context.get('user_name', 'N/A'))
        check_element("hostname", context.get('hostname', 'N/A'))
        
        # Check for either action verb or "alert" keyword (since we're integrating it naturally)
        verb_root = (action_phrase or '').split(' ')[0].lower()
        has_action = (verb_root and verb_root in generated_sentence.lower()) or 'alert' in generated_sentence.lower()
        if not has_action:
            missing_elements.append("action verb or alert keyword")
        
        # Domain is intentionally omitted from observation; no domain validation
        
        # Check if customer info should be present
        if customer and customer.lower() not in generated_sentence.lower():
            missing_elements.append(f"customer identifier ({customer})")

        # Extra validation to avoid awkward duplications
        if generated_sentence.lower().count("alert") > 2:
            missing_elements.append("excessive 'alert' repetition")
        # Avoid dangling prepositions
        if generated_sentence.rstrip().lower().endswith(("involving", "via", "from", "with")):
            missing_elements.append("dangling phrase")

        if missing_elements:
            print(f"Warning: Generated sentence might be missing elements: {', '.join(missing_elements)}. Using fallback.")
            return f"***Observation Statement***\n\n{fallback_sentence}\n(Observation generation missing elements)"
        else:
            return f"***Observation Statement***\n\n{generated_sentence}"

    except Exception as e:
        error_msg = f"Observation Generation Error: {e}"
        print(f"Error during observation generation: {error_msg}")
        err_str = str(e).lower()
        if "429" in err_str: error_msg = "API Rate Limit Exceeded"
        elif "permission_denied" in err_str or "api key not valid" in err_str: error_msg = "Invalid API Key or Permissions Issue"
        elif "deadline exceeded" in err_str: error_msg = "API Request Timeout"
        return f"***Observation Statement***\n\n{fallback_sentence}\n(Observation generated locally due to API error: {error_msg})"

def get_nested_value(data, key_path):
    """
    Safely retrieves a nested value from a dictionary using a dot-separated key path.
    """
    keys = key_path.split('.')
    current_data = data
    for key in keys:
        if isinstance(current_data, dict) and key in current_data:
            current_data = current_data[key]
        else:
            return None
    
    # Handle final value if it's a list (e.g., event.type: ["info", "start"])
    if isinstance(current_data, list):
        return ' '.join([str(item) for item in current_data if item is not None])
    
    # Format boolean values to lowercase string (true/false) as required by EQL
    if isinstance(current_data, bool):
        return str(current_data).lower()
    
    # Return raw string or other non-dict type
    return current_data

def parse_multiple_json(text):
    """
    Parses text that might contain a single JSON object, a list, or NDJSON.
    """
    text = text.strip()
    results = []

    # Attempt 1: Try parsing as a standard JSON (Dict or List)
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass 

    # Attempt 2: Parse concatenated JSON objects (NDJSON)
    decoder = json.JSONDecoder()
    pos = 0
    while pos < len(text):
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        try:
            obj, json_len = decoder.raw_decode(text[pos:])
            results.append(obj)
            pos += json_len
        except json.JSONDecodeError:
            break
            
    return results

def extract_context(data):
    """Extracts relevant security fields from a single alert dict."""
    if '_source' in data and isinstance(data['_source'], dict):
        ecs_data = data['_source']
    else:
        ecs_data = data

    FIELD_MAP = {
        'event.code': 'event.code',
        'event.action': 'event.action',
        'process.name': 'process.name',
        'process.executable': 'process.executable',
        'process.pe.original_file_name': 'process.pe.original_file_name',
        'process.command_line': 'process.command_line',
        'process.args': 'process.args',
        'process.working_directory': 'process.working_directory',
        'process.parent.name': 'process.parent.name',
        'process.parent.executable': 'process.parent.executable',
        'process.parent.executable.text': 'process.parent.executable.text',
        'process.parent.command_line': 'process.parent.command_line',
        'process.parent.args': 'process.parent.args',
        'process.parent.working_directory': 'process.parent.working_directory',
        'process.code_signature.subject_name': 'process.code_signature.subject_name',
        'process.code_signature.trusted': 'process.code_signature.trusted',
        'process.hash.sha256': 'process.hash.sha256',
        'process.hash.sha1': 'process.hash.sha1',
        'process.hash.md5': 'process.hash.md5',
        'file.name': 'file.name',
        'file.path': 'file.path',
        'file.code_signature.subject_name': 'file.code_signature.subject_name',
        'file.code_signature.trusted': 'file.code_signature.trusted',
        'file.hash.sha256': 'file.hash.sha256',
        'file.hash.sha1': 'file.hash.sha1',
        'file.hash.md5': 'file.hash.md5',
        'rule.id': 'rule.id',
        'rule.uuid': 'rule.uuid',
        'kibana.alert.rule.uuid': 'kibana.alert.rule.uuid',
        'user.name': 'user.name', # Extracted for context only
    }
    
    context = {}
    for eql_field, json_path in FIELD_MAP.items():
        value = get_nested_value(ecs_data, json_path)
        if value is not None and value != '':
            context[eql_field] = value

    # --- Additional Context for Observation Statement ---
    # Map to keys expected by generate_observation_statement
    
    # Hostname
    context['hostname'] = (
        get_nested_value(ecs_data, 'host.name') or 
        get_nested_value(ecs_data, 'host.hostname') or 
        get_nested_value(ecs_data, 'observer.hostname') or 
        get_nested_value(ecs_data, 'agent.hostname') or 
        "N/A"
    )
    
    # Domains
    context['user_domain'] = get_nested_value(ecs_data, 'user.domain') or "N/A"
    context['host_domain'] = get_nested_value(ecs_data, 'host.domain') or "N/A"
    
    # Rule Name
    context['rule_name'] = (
        get_nested_value(ecs_data, 'kibana.alert.rule.name') or 
        get_nested_value(ecs_data, 'rule.name') or 
        "N/A"
    )
    context['rule.name'] = context['rule_name']
    
    # Process/File Names (already in context but with dot notation, map to underscore for compatibility)
    context['proc_name'] = context.get('process.name', "N/A")
    context['parent_proc_name'] = context.get('process.parent.name', "N/A")
    
    # If parent.name is missing, extract from parent.executable or parent.executable.text
    if context['parent_proc_name'] == "N/A":
        parent_exec = context.get('process.parent.executable') or context.get('process.parent.executable.text')
        if parent_exec and parent_exec != "N/A":
            # Extract basename from full path
            context['parent_proc_name'] = os.path.basename(parent_exec)
    
    context['file_name'] = context.get('file.name', "N/A")
    context['user_name'] = context.get('user.name', "N/A")
    
    # Unique Arg Filename (simplified extraction)
    context['unique_arg_filename'] = "N/A"
    if context['rule_name'] == "Suspicious MS Office Child Process" and context['proc_name'] == 'explorer.exe':
        # Try to extract from args or command line
        cmd = get_nested_value(ecs_data, 'process.command_line')
        target_arg = None
        
        if cmd and "/select," in str(cmd).lower():
             parts = str(cmd).split()
             for i, part in enumerate(parts):
                if part.lower().startswith("/select,"):
                    target_arg = part
                    if part.lower() == "/select," and i + 1 < len(parts):
                        target_arg = "/select," + parts[i+1]
                    break
        
        if target_arg:
            try:
                full_path = target_arg[len("/select,"):].strip().strip('"')
                if full_path:
                    context['unique_arg_filename'] = os.path.basename(full_path)
            except:
                pass

    return context

def _build_fallback_exception_list(alerts=None, contexts=None, min_conditions=3):
    """
    Build a stronger EQL exception list without LLM by intersecting or voting on stable fields across alerts.
    Uses tiered approach: signer+trusted+name > hashes+name > process+parent+patterns > behavioral.
    Automatically generalizes paths (strips versions, detects WindowsApps), pattern-matches versioned scripts.
    Uses frequency (>=60% of alerts, min 2) instead of strict equality, then fills from the first alert if needed.
    """
    if not alerts and not contexts:
        return None

    # Reuse already-extracted contexts when provided to avoid duplicate work
    ctx_list = contexts if contexts is not None else []
    if not ctx_list and alerts:
        for alert in alerts:
            ctx = extract_context(alert)
            if ctx:
                ctx_list.append(ctx)

    if not ctx_list:
        return None

    # --- Helper Functions ---
    
    def strip_version_from_path(path):
        """Strip version numbers and hashes from WindowsApps/versioned paths."""
        if not path or path in (None, '', 'N/A'):
            return None
        # Match WindowsApps pattern: CompanyName.AppName_version_arch__hash
        match = re.search(r'WindowsApps[/\\]([^/\\]+?)_[0-9.]+_[^/\\]+__[^/\\]+[/\\](.+)$', path, re.IGNORECASE)
        if match:
            return match.group(2)  # Return just the filename
        # Match other versioned patterns: tool-1.2.3.exe or tool_v1.2.exe
        match = re.search(r'([^/\\]+?)[-_]v?[0-9]+\.[0-9.]+', path, re.IGNORECASE)
        if match:
            return os.path.basename(path)
        return None
    
    def is_windows_app_path(path):
        """Check if path is from WindowsApps (versioned store apps)."""
        return bool(path and 'WindowsApps' in str(path))
    
    def extract_script_pattern(text):
        """Extract generalized script pattern from command/file (e.g., deleteusers1.4.ps1 -> deleteusers1.[0-9]+.ps1)."""
        if not text:
            return None
        # Match script.1.2.ps1 or tool-1.2.py patterns
        match = re.search(r'([a-zA-Z_-]+[0-9]*)\.[0-9]+(?:\.[0-9]+)*\.(ps1|py|vbs|bat|cmd|js)', str(text), re.IGNORECASE)
        if match:
            base = match.group(1)
            ext = match.group(2)
            return f"{base}\\.[0-9]+(?:\\.[0-9]+)*\\.{ext}"
        return None

    def extract_executable_from_command(cmd):
        """Best-effort extraction of the leading executable path from a command line."""
        if not cmd:
            return None
        txt = str(cmd).strip()
        m = re.match(r'^"([^"]+)"', txt)
        if m:
            return m.group(1)
        parts = txt.split()
        return parts[0] if parts else None

    def generalize_path_pattern(path):
        """Generalize a path to a MATCHES-friendly pattern (wildcards for versions/roots) while keeping filename."""
        if not path:
            return None
        p = str(path)
        # Remove drive letter
        p = re.sub(r'^[A-Za-z]:', '', p)
        # Normalize slashes
        p = p.replace('\\', '/')
        # Generalize user profile folder
        p = re.sub(r'/Users/[^/]+/', r'/Users/[^/]+/', p, flags=re.IGNORECASE)
        # WindowsApps version blobs
        p = re.sub(r'WindowsApps/([^/]+?)_[0-9.]+_[^/]+__[^/]+/', r'WindowsApps/\1_*/', p, flags=re.IGNORECASE)
        # Replace version numbers with wildcard class
        p = re.sub(r'[0-9]+(?:\.[0-9]+)+', r'[0-9.]+', p)
        # Restore escaped backslashes for EQL MATCHES
        p = p.replace('/', r'\\')
        # Ensure we anchor loosely but keep filename
        if not p.startswith('.*'):
            p = '.*' + p
        return p
    
    def frequent_value(key):
        """Find a representative value across contexts.

        - If there is only a single context, just return its value (if present).
        - Otherwise, return a high-frequency value present in >=60% of alerts with at least 2 occurrences.
        """
        # Single-alert fast path: treat the lone value as authoritative
        if len(ctx_list) == 1:
            val = ctx_list[0].get(key)
            return val if val not in (None, '', 'N/A') else None

        freq = {}
        for ctx in ctx_list:
            val = ctx.get(key)
            if val in (None, '', 'N/A'):
                continue
            freq[val] = freq.get(val, 0) + 1
        if not freq:
            return None
        max_count = max(freq.values())
        threshold = max(2, int(len(ctx_list) * 0.6 + 0.5))
        if max_count < threshold:
            return None
        # Return the most frequent value
        for v, c in freq.items():
            if c == max_count:
                return v
        return None

    conditions = []
    seen = set()
    
    # --- TIER 1: Code Signature (Strongest - works across versions/hosts) ---
    signer = frequent_value('process.code_signature.subject_name')
    trusted = frequent_value('process.code_signature.trusted')
    proc_name = frequent_value('process.name')
    parent_name = frequent_value('process.parent.name')
    pe_original = frequent_value('process.pe.original_file_name')
    
    if signer and proc_name:
        conditions.append(f"process.code_signature.subject_name IS \"{signer}\"")
        seen.add(('process.code_signature.subject_name', signer))
        if trusted:
            conditions.append(f"process.code_signature.trusted IS \"{trusted}\"")
            seen.add(('process.code_signature.trusted', trusted))
        if pe_original:
            conditions.append(f"process.pe.original_file_name IS \"{pe_original}\"")
            seen.add(('process.pe.original_file_name', pe_original))
        conditions.append(f"process.name IS \"{proc_name}\"")
        seen.add(('process.name', proc_name))
        # ALWAYS add parent if available - critical for preventing false positives
        if parent_name:
            conditions.append(f"process.parent.name IS \"{parent_name}\"")
            seen.add(('process.parent.name', parent_name))
    
    # --- TIER 2: Hash + Name (Precise for unsigned binaries) ---
    elif frequent_value('process.hash.sha256') and proc_name:
        sha256 = frequent_value('process.hash.sha256')
        conditions.append(f"process.hash.sha256 IS \"{sha256}\"")
        seen.add(('process.hash.sha256', sha256))
        if pe_original:
            conditions.append(f"process.pe.original_file_name IS \"{pe_original}\"")
            seen.add(('process.pe.original_file_name', pe_original))
        conditions.append(f"process.name IS \"{proc_name}\"")
        seen.add(('process.name', proc_name))
        # ALWAYS add parent if available
        if parent_name:
            conditions.append(f"process.parent.name IS \"{parent_name}\"")
            seen.add(('process.parent.name', parent_name))
    
    # --- TIER 3: Process + Parent + Pattern Matching ---
    else:
        # Add process name if available
        if proc_name:
            conditions.append(f"process.name IS \"{proc_name}\"")
            seen.add(('process.name', proc_name))
        
        # ALWAYS add parent process if available
        if parent_name:
            conditions.append(f"process.parent.name IS \"{parent_name}\"")
            seen.add(('process.parent.name', parent_name))
        
        # Detect script patterns in command line or file name
        script_pattern = None
        for ctx in ctx_list:
            cmdl = ctx.get('process.command_line') or ctx.get('process.args') or ''
            fname = ctx.get('file.name') or ''
            
            # Try command line first
            pattern = extract_script_pattern(cmdl)
            if pattern and ('process.command_line', pattern) not in seen:
                conditions.append(f"process.command_line MATCHES \"(?i).*{pattern}.*\"")
                seen.add(('process.command_line', pattern))
                script_pattern = pattern
                break
            
            # Fall back to file name
            pattern = extract_script_pattern(fname)
            if pattern and ('file.name', pattern) not in seen:
                conditions.append(f"file.name MATCHES \"(?i){pattern}\"")
                seen.add(('file.name', pattern))
                script_pattern = pattern
                break
        
        # If no pattern detected but we have command line, check for WindowsApps paths
        if not script_pattern:
            for ctx in ctx_list:
                cmdl = ctx.get('process.command_line') or ctx.get('process.args') or ''
                exec_path = ctx.get('process.executable') or extract_executable_from_command(cmdl) or ''

                # Generalize executable path to a wildcard pattern if present
                pattern = generalize_path_pattern(exec_path)
                if pattern and ('process.executable', pattern) not in seen:
                    conditions.append(f"process.executable MATCHES \"(?i){pattern}\"")
                    seen.add(('process.executable', pattern))
                    break

                # WindowsApps: avoid exact paths; prefer signer already added. No extra condition here.
    # --- LoLBin-specific tightening: require command line scoping when possible ---
    lolbins = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "rundll32.exe", "mshta.exe", "msiexec.exe", "regsvr32.exe",
        "schtasks.exe", "wmic.exe"
    }
    if proc_name and proc_name.lower() in lolbins:
        cmd_example = None
        for ctx in ctx_list:
            name = ctx.get('process.name')
            if name and name.lower() == proc_name.lower():
                cmd_example = ctx.get('process.command_line') or ctx.get('process.args')
                if cmd_example:
                    break
        if cmd_example:
            cl_pattern = re.escape(str(cmd_example))
            if ('process.command_line', cl_pattern) not in seen:
                conditions.append(
                    f"process.command_line MATCHES \"(?i).*{cl_pattern}.*\""
                )
                seen.add(('process.command_line', cl_pattern))

    # --- Add rule name for scoping (always useful) ---
    rule_name = frequent_value('rule.name') or frequent_value('rule_name')
    if not rule_name and ctx_list:
        # Fall back to the first context if frequency voting fails
        first_ctx = ctx_list[0]
        rule_name = first_ctx.get('rule.name') or first_ctx.get('rule_name')
    if rule_name and ('rule.name', rule_name) not in seen:
        conditions.append(f"rule.name IS \"{rule_name}\"")
        seen.add(('rule.name', rule_name))


    # --- Fallback: ensure min_conditions by adding from first context ---
    if len(conditions) < min_conditions:
        first_ctx = ctx_list[0]
        fallback_keys = [
            'process.name',
            'process.parent.name',
            'file.name',
            'event.code',
            'event.action',
        ]
        for key in fallback_keys:
            val = first_ctx.get(key)
            if val not in (None, '', 'N/A') and (key, val) not in seen:
                conditions.append(f"{key} IS \"{val}\"")
                seen.add((key, val))
            if len(conditions) >= min_conditions:
                break
    # --- Safety gate: require at least one strong indicator ---
    strong_tokens = (
        "hash.sha256",
        "code_signature.",
        "executable MATCHES",
        "file.path MATCHES",
        "file.name MATCHES",
        "command_line MATCHES",
    )
    has_strong = any(
        any(tok in cond for tok in strong_tokens)
        for cond in conditions
    )
    if not has_strong:
        # Too broad to be safely automated; force the caller to handle manually
        return None

    if not conditions:
        return None

    result = conditions[0]
    for cond in conditions[1:]:
        result += f"\nAND {cond}"
    return result

def generate_llm_exception_list(alerts, api_key, model_name):
    """Generate a consolidated exception list from alert objects.

    Returns (exception_list, meta) where meta contains:
      warning: non-fatal message (e.g., fallback used)
      error: fatal message when no exception list is returned
      used_fallback: True when the deterministic builder was used
    """

    meta = {"warning": None, "error": None, "used_fallback": False}

    if not api_key:
        meta["error"] = "Error: GEMINI_API_KEY is not set."
        return None, meta

    # Extract context from ALL accumulated alerts - COMPACT FORMAT
    all_contexts = []
    context_per_alert = []
    for alert in alerts:
        ctx = extract_context(alert)
        if ctx:
            context_per_alert.append(ctx)
            # Use compact representation to save tokens and keep host/user out
            compact = {k: v for k, v in ctx.items() if v and v != "N/A"}
            for drop_key in ('hostname', 'host_domain', 'user_domain', 'user.name', 'user_name'):
                compact.pop(drop_key, None)
            all_contexts.append(json.dumps(compact))

    if not all_contexts:
        meta["error"] = "No relevant security fields found in the collected alerts."
        return None, meta

    # Compact combined context - one per line
    combined_context_str = "\n".join(all_contexts)

    system_instruction = (
        "Create Elastic EQL exception list. ONLY output EQL query. "
        "Return 3-8 lines. Every line after the first MUST start with AND. "
        "TIER 1 (preferred): process.code_signature.subject_name + trusted + process.pe.original_file_name + process.name + process.parent.name (works across versions/hosts). "
        "TIER 2: process.hash.sha256 + process.pe.original_file_name + process.name + process.parent.name (for unsigned tools). "
        "TIER 3: process.executable (generalized) + process.name + process.parent.name + MATCHES for scripts. "
        "Generalize paths: strip version numbers and WindowsApps blobs; use MATCHES \"(?i)...\" for case-insensitive regex. "
        "For LOLBins (cmd.exe, powershell.exe, etc.), YOU MUST INCLUDE process.command_line. "
        "ALWAYS include process.parent.name when available - critical for preventing false positives. "
        "ALWAYS add rule.name for scoping. Format booleans as strings: 'true' or 'false'. "
        "Do NOT include host or user fields. Avoid returning only event.action. No markdown, no prose."
    )

    prompt = (
        f"Consolidate {len(alerts)} alerts into ONE robust EQL exception for the triggered rule.\n"
        f"You MUST emit at least 3 conditions (more if available).\n"
        f"PRIORITY ORDER:\n"
        f"1. If code signer exists: process.code_signature.subject_name + trusted + process.pe.original_file_name + process.name + process.parent.name\n"
        f"2. If hash exists: process.hash.sha256 + process.pe.original_file_name + process.name + process.parent.name\n"
        f"3. Otherwise: process.executable (generalized) + process.name + process.parent.name + MATCHES pattern for scripts\n"
        f"CRITICAL: ALWAYS include process.parent.name when available - prevents false positives.\n"
        f"CRITICAL: For system tools (cmd, powershell, rundll32), you MUST include process.command_line to avoid broad exceptions.\n"
        f"Generalize paths with wildcards: use MATCHES \"(?i)...\" for case-insensitivity. Strip versions/hashes.\n"
        f"For scripts like 'tool1.4.ps1', use MATCHES '(?i)tool1\\.[0-9]+\\.ps1'.\n"
        f"ALWAYS add rule.name (not rule.id or rule.uuid) for scoping. Format booleans as strings: 'true' not true.\n"
        f"Exclude host/user fields. Target only processes directly involved in the alert (parent+child).\n"
        f"Source alerts (one per line):\n{combined_context_str}\n"
        "Output format (no prose, no markdown):\n"
        "field1 IS \"value1\"\n"
        "AND field2 IS \"value2\"\n"
        "AND field3 IS \"value3\""
    )

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(
            model_name=model_name,
            system_instruction=system_instruction
        )

        generation_config = genai.types.GenerationConfig(
            temperature=0.0,
            max_output_tokens=1024,
        )

        response = model.generate_content(
            prompt,
            generation_config=generation_config
        )

        # Robustly extract textual content from the Gemini response.
        def _extract_response_text(resp):
            try:
                txt = getattr(resp, 'text', None)
                if txt and txt.strip():
                    return txt
            except Exception:
                pass

            try:
                candidates = getattr(resp, 'candidates', None) or getattr(resp, 'candidate', None)
                if candidates:
                    parts = []
                    if not isinstance(candidates, (list, tuple)):
                        candidates = [candidates]
                    for c in candidates:
                        if isinstance(c, dict):
                            if 'content' in c:
                                cont = c['content']
                                if isinstance(cont, list):
                                    for p in cont:
                                        if isinstance(p, dict) and 'text' in p and p['text'].strip():
                                            parts.append(p['text'])
                                        elif isinstance(p, str) and p.strip():
                                            parts.append(p)
                                elif isinstance(cont, str) and cont.strip():
                                    parts.append(cont)
                            elif 'text' in c and c['text'].strip():
                                parts.append(c['text'])
                        else:
                            for attr in ('content', 'text', 'output'):
                                val = getattr(c, attr, None)
                                if val:
                                    if isinstance(val, list):
                                        for p in val:
                                            if isinstance(p, dict):
                                                if 'text' in p and p['text'].strip():
                                                    parts.append(p['text'])
                                                elif 'content' in p and p['content'].strip():
                                                    parts.append(p['content'])
                                            elif isinstance(p, str) and p.strip():
                                                parts.append(p)
                                    elif isinstance(val, str) and val.strip():
                                        parts.append(val)
                                    if parts:
                                        break
                    if parts:
                        return "\n".join(parts)
            except Exception:
                pass

            return ''

        raw_output = _extract_response_text(response).strip()

        finish_reason = None
        token_count = "unknown"
        if hasattr(response, 'candidates') and response.candidates:
            finish_reason = response.candidates[0].finish_reason.name if hasattr(response.candidates[0].finish_reason, 'name') else str(response.candidates[0].finish_reason)

        try:
            if hasattr(response, 'usage_metadata'):
                usage_meta = response.usage_metadata
                token_count = getattr(usage_meta, 'total_token_count', 'unknown')
        except Exception:
            pass

        if finish_reason == "MAX_TOKENS" and not raw_output:
            print("   Warning: API hit MAX_TOKENS with no output. Using fallback exception list...")
            fallback_eql = _build_fallback_exception_list(contexts=context_per_alert)
            if fallback_eql:
                meta["warning"] = "LLM hit MAX_TOKENS; used deterministic fallback"
                meta["used_fallback"] = True
                return fallback_eql, meta
            meta["error"] = f"API response hit MAX_TOKENS limit with no output. Fallback also failed. Token usage: {token_count}"
            return None, meta

        if not raw_output:
            print("   Warning: No text generated. Using fallback exception list...")
            fallback_eql = _build_fallback_exception_list(contexts=context_per_alert)
            if fallback_eql:
                meta["warning"] = "LLM produced empty output; used deterministic fallback"
                meta["used_fallback"] = True
                return fallback_eql, meta
            meta["error"] = f"No text generated from API response. Finish reason: {finish_reason or 'unknown'}"
            return None, meta

        match = re.search(r"```(?:\w+\n)?(.+?)```", raw_output, re.DOTALL)
        clean_text = match.group(1).strip() if match else raw_output
        if clean_text.startswith('(') and clean_text.endswith(')'):
            clean_text = clean_text[1:-1].strip()

        parts = re.split(r'\s+AND\s+', clean_text, flags=re.IGNORECASE)

        formatted_lines = []
        if parts:
            formatted_lines.append(parts[0].strip())
            for part in parts[1:]:
                formatted_lines.append(f"AND {part.strip()}")

        final_lines = [line for line in formatted_lines if line.strip()]

        sid_pattern = re.compile(r'file\.name IS "S-\d+-\d+-\d+-\d+-\d+"', re.IGNORECASE)
        final_lines = [line for line in final_lines if not sid_pattern.search(line)]

        # Basic structure checks
        has_parent = any("process.parent.name" in line for line in final_lines)
        strong_tokens = (
            "hash.sha256",
            "code_signature.",
            "executable MATCHES",
            "file.path MATCHES",
            "file.name MATCHES",
            "command_line MATCHES",
        )
        has_strong = any(
            any(tok in line for tok in strong_tokens)
            for line in final_lines
        )

        only_event_action = all(line.lower().startswith("event.action") for line in final_lines)
        if not final_lines or len(final_lines) < 3 or only_event_action or not has_parent or not has_strong:
            fallback_eql = _build_fallback_exception_list(contexts=context_per_alert)
            if fallback_eql:
                meta["warning"] = "LLM output too weak; used deterministic fallback"
                meta["used_fallback"] = True
                return fallback_eql, meta
            meta["error"] = "The LLM returned an empty or weak exception list."
            return None, meta

        final_exception_list = '\n'.join(final_lines)
        return final_exception_list, meta

    except Exception as e:
        print(f"   Warning: Gemini API call failed ({e}). Using fallback exception list...")
        fallback_eql = _build_fallback_exception_list(contexts=context_per_alert)
        if fallback_eql:
            meta["warning"] = f"Gemini API call failed; used deterministic fallback: {e}"
            meta["used_fallback"] = True
            return fallback_eql, meta
        meta["error"] = f"Gemini API call failed: {e}"
        return None, meta

# --- Interactive Main Execution ---

def main():
    try:
        if not GEMINI_API_KEY:
            print("Error: GEMINI_API_KEY is not set.")
            sys.exit(1)

        print("\n--- Elastic Exception List Generator (Multi-Alert Mode) ---")
        print("Instructions: Copy an alert JSON to your clipboard, then press [Enter] here to add it.")
        print("When you have added all alerts, type 'done' to generate the list.\n")

        collected_alerts = []
        
        while True:
            count = len(collected_alerts)
            user_input = input(f"[{count} alerts stored] Press [Enter] to grab clipboard (or type 'done'): ").strip().lower()

            if user_input == 'done':
                if count == 0:
                    print("No alerts collected! Please add at least one alert.")
                    continue
                break
            
            # Grab from clipboard
            content = pyperclip.paste()
            if not content:
                print("⚠️  Clipboard is empty.")
                continue

            new_alerts = parse_multiple_json(content)
            
            if new_alerts:
                collected_alerts.extend(new_alerts)
                print(f"✅ Added {len(new_alerts)} alert(s) from clipboard.")
            else:
                print("❌ No valid JSON found in clipboard. Please copy the raw JSON object.")

        # --- Generation Phase ---
        print(f"\nGenerating content for {len(collected_alerts)} alerts...")
        
        # 1. Generate Observation Statement (using the first alert)
        if collected_alerts:
            print("Generating Observation Statement...")
            first_alert_context = extract_context(collected_alerts[0])

            # Fold in all unique users/hosts from the batch so the statement reflects multi-alert scope
            users = []
            hosts = []
            for alert in collected_alerts:
                ctx = extract_context(alert)
                if not ctx:
                    continue
                u = ctx.get('user.name') or ctx.get('user_name')
                h = ctx.get('hostname')
                if u and u != 'N/A' and u not in users:
                    users.append(u)
                if h and h != 'N/A' and h not in hosts:
                    hosts.append(h)

            if users:
                first_alert_context['user_name'] = ', '.join(users)
            if hosts:
                first_alert_context['hostname'] = ', '.join(hosts)

            observation_statement = generate_observation_statement(first_alert_context, GEMINI_API_KEY)
            observation_output = f"{observation_statement}\n\nDuplicate of Case #"
            
            pyperclip.copy(observation_output)
            print("\n" + "="*60)
            print(f"✅ Observation Statement copied to clipboard.")
            print("="*60)
            print(f"\n{observation_output}")

        input("\nPress Enter to generate and copy the Exception List...")

        # 2. Generate Exception List
        print("Generating Exception List...")
        # For the very common single-alert case, try a deterministic, tightly-scoped exception first.
        if len(collected_alerts) == 1:
            single_ctx = extract_context(collected_alerts[0])
            exception_list = _build_fallback_exception_list(contexts=[single_ctx] if single_ctx else [])
            meta = {"warning": None, "error": None, "used_fallback": True}
            if not exception_list:
                # If we cannot safely build a deterministic exception, fall back to the LLM.
                exception_list, meta = generate_llm_exception_list(collected_alerts, GEMINI_API_KEY, GEMINI_MODEL_NAME)
        else:
            exception_list, meta = generate_llm_exception_list(collected_alerts, GEMINI_API_KEY, GEMINI_MODEL_NAME)

        if not exception_list:
            print(f"Error: {meta.get('error', 'Unknown error generating exception list.')}")
            sys.exit(1)

        if meta.get("warning"):
            print(f"Warning: {meta['warning']}")

        exception_output = f"***Recommended Exception List:***\n\n```\n{exception_list}\n```"
        pyperclip.copy(exception_output)
        
        print("\n" + "="*60)
        print(f"✅ Exception List copied to clipboard.")
        print("="*60)
        print(f"\n{exception_output}")

    except ImportError:
        print("\nFatal Error: Libraries missing. Run: pip install pyperclip python-dotenv google-genai")
    except Exception as e:
        print(f"\nUnexpected error: {e}")

if __name__ == "__main__":
    main()