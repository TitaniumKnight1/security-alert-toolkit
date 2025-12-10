import json
import pyperclip
import sys
import os
import requests
import time
import re
import traceback
import google.generativeai as genai
from datetime import datetime, timedelta
from dotenv import load_dotenv

# --- Load Environment Variables ---
load_dotenv()

# --- Configuration ---
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files/{}"
GEMINI_MODEL_NAME = "gemini-2.5-flash"
CHATGPT5_HARD_CHAR_LIMIT = 65000
CHATGPT5_SAFETY_MARGIN = 1000
CHATGPT5_MAX_PROMPT_CHARS = CHATGPT5_HARD_CHAR_LIMIT - CHATGPT5_SAFETY_MARGIN
CHATGPT5_CONTINUATION_BUFFER = 1500
CHATGPT5_LARGE_PROMPT_THRESHOLD = CHATGPT5_MAX_PROMPT_CHARS - 6000
CHATGPT5_NEAR_LIMIT_THRESHOLD = CHATGPT5_MAX_PROMPT_CHARS - 1500
# - Clear actor identification speeds up investigation and response
# ===============================================================================

# Feature note:
# - When an alert is determined to be memory- or shellcode-related (e.g., memory protection, suspicious thread/code injection,
#   shellcode execution), the script extracts call stack details from the alert payload and includes them in the Investigation Report.
#   This inclusion is conditional and occurs only when these behaviors are directly involved.

# --- Common Process List (Kept for potential future use or reference) ---
COMMON_PROCESS_FILENAMES = {
    "explorer.exe", "svchost.exe", "lsass.exe", "csrss.exe", "wininit.exe",
    "services.exe", "conhost.exe", "runtimebroker.exe", "taskhostw.exe",
    "taskhostex.exe", "dwm.exe", "winlogon.exe", "system", "smss.exe",
    "spoolsv.exe", "searchindexer.exe", "sihost.exe", "ctfmon.exe",
    "dllhost.exe", "audiodg.exe", "fontdrvhost.exe", "consent.exe",
    "applicationframehost.exe", "shellexperiencehost.exe", "systemsettings.exe",
    "wmiprvse.exe", "taskmgr.exe", "services.msc", "mmc.exe", "chrome.exe",
    "firefox.exe", "msedge.exe", "iexplore.exe", "winword.exe", "excel.exe",
    "powerpnt.exe", "outlook.exe", "onedrive.exe", "teams.exe", "mstsc.exe",
    "cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe", "regsvr32.exe",
    "7zg.exe", "7zfm.exe", "7z.exe",
}

# --- Helper Functions (general) ---
def condense_alert_json(alert_data):
    """
    Aggressively condense alert JSON by removing verbose/redundant fields
    while preserving ALL investigation-critical data.
    
    REMOVES (to save space):
    - Elastic metadata (index, shard, sort, version)
    - Verbose kibana.alert.* metadata (keeps core fields only)
    - Policy configuration details (Endpoint.policy.applied.artifacts)
    - Massive DLL lists (process.Ext.dll, Target.process.Ext.dll) - keeps count only
    - Duplicate nested copies of same data
    - Flattened field duplicates (e.g., host.name vs host.hostname)
    - Large code signature arrays (keeps summary only)
    - Empty/null nested objects
    
    PRESERVES (for investigation):
    - Core process, file, user, host information
    - All SHA256/SHA1/MD5 hashes
    - Critical threat indicators
    - Command lines and arguments
    - Parent-child process relationships
    - Timestamps and event metadata
    - Rule details (name, description, reason)
    - Memory/thread information (call stacks, memory regions)
    - Network indicators
    - Target process information
    """
    import copy
    condensed = copy.deepcopy(alert_data)
    
    # Fields to remove (non-critical metadata)
    removable_top_level = [
        '_index', '_type', '_id', '_score', '_version', 
        'sort', 'fields', '_ignored', 'highlight', '_explanation'
    ]
    
    for field in removable_top_level:
        condensed.pop(field, None)
    
    # Work with _source if it exists, otherwise work with root
    source = condensed.get('_source', condensed)
    
    # === AGGRESSIVE KIBANA.ALERT CLEANUP ===
    if 'kibana' in source and 'alert' in source['kibana']:
        kibana_alert = source['kibana']['alert']
        
        # Keep ONLY these essential fields
        essential_kibana_fields = {
            'rule': {'name', 'description', 'severity', 'risk_score', 'uuid', 'rule_id'},
            'reason': True,
            'severity': True,
            'risk_score': True,
            'workflow_status': True,
            'original_time': True,
            'url': True,
        }
        
        # Keep minimal rule info
        if 'rule' in kibana_alert and isinstance(kibana_alert['rule'], dict):
            rule_essential = essential_kibana_fields['rule']
            rule_keys = list(kibana_alert['rule'].keys())
            for key in rule_keys:
                if key not in rule_essential:
                    kibana_alert['rule'].pop(key, None)
        
        # Remove all other kibana.alert.* bloat
        keys_to_remove = [k for k in list(kibana_alert.keys()) if k not in essential_kibana_fields]
        for key in keys_to_remove:
            kibana_alert.pop(key, None)
    
    # === AGGRESSIVE ENDPOINT POLICY CLEANUP ===
    # The Endpoint.policy.applied.artifacts object is MASSIVE and not needed for investigation
    if 'Endpoint' in source and isinstance(source['Endpoint'], dict):
        if 'policy' in source['Endpoint'] and isinstance(source['Endpoint']['policy'], dict):
            if 'applied' in source['Endpoint']['policy']:
                applied = source['Endpoint']['policy']['applied']
                # Keep only name and ID
                source['Endpoint']['policy']['applied'] = {
                    'name': applied.get('name', 'N/A'),
                    'id': applied.get('id', 'N/A'),
                    '_note': 'Policy artifacts removed to save space'
                }
    
    # === AGGRESSIVE DLL LIST CLEANUP ===
    # DLL lists can be 100+ entries - we only need count for investigation
    def condense_dll_list(dll_array):
        """Replace massive DLL arrays with summary"""
        if not isinstance(dll_array, list):
            return dll_array
        
        if len(dll_array) <= 5:
            return dll_array  # Keep small lists
        
        # For large lists, keep first 2 and last 2, add summary
        return [
            dll_array[0],
            dll_array[1],
            {
                '_summary': f'{len(dll_array) - 4} DLLs omitted (total: {len(dll_array)})',
                '_note': 'Full DLL list removed to save space'
            },
            dll_array[-2],
            dll_array[-1]
        ]
    
    # Clean process DLL list
    if 'process' in source and isinstance(source['process'], dict):
        if 'Ext' in source['process'] and isinstance(source['process']['Ext'], dict):
            if 'dll' in source['process']['Ext']:
                source['process']['Ext']['dll'] = condense_dll_list(source['process']['Ext']['dll'])
    
    # Clean Target.process DLL list
    if 'Target' in source and isinstance(source['Target'], dict):
        if 'process' in source['Target'] and isinstance(source['Target']['process'], dict):
            if 'Ext' in source['Target']['process'] and isinstance(source['Target']['process']['Ext'], dict):
                if 'dll' in source['Target']['process']['Ext']:
                    source['Target']['process']['Ext']['dll'] = condense_dll_list(source['Target']['process']['Ext']['dll'])
    
    # === REMOVE REDUNDANT FIELDS ===
    # Remove agent.* verbose fields (keep minimal info)
    if 'agent' in source:
        agent_essential = {'id', 'type', 'version'}
        agent_keys = list(source['agent'].keys())
        for key in agent_keys:
            if key not in agent_essential:
                source['agent'].pop(key, None)
    
    # Remove ecs metadata
    source.pop('ecs', None)
    
    # Remove observer verbose metadata
    if 'observer' in source:
        source.pop('observer', None)  # Usually duplicates host/agent
    
    # Remove data_stream metadata
    source.pop('data_stream', None)
    
    # Remove elastic metadata
    source.pop('elastic', None)
    
    # === CONDENSE LARGE ARRAYS ===
    # Condense large Events array
    if 'Events' in source and isinstance(source['Events'], list):
        if len(source['Events']) > 2:
            events_count = len(source['Events'])
            source['Events'] = [
                source['Events'][0],
                {'_summary': f'{events_count - 2} events omitted'},
                source['Events'][-1]
            ]
    
    # === CONDENSE CODE SIGNATURES ===
    def condense_code_signature_array(sig_array):
        """Keep only first signature from array"""
        if not isinstance(sig_array, list):
            return sig_array
        if len(sig_array) == 0:
            return sig_array
        # Keep only first signature (most relevant)
        return [sig_array[0]]
    
    # Condense process code signatures
    if 'process' in source and isinstance(source['process'], dict):
        if 'Ext' in source['process'] and isinstance(source['process']['Ext'], dict):
            if 'code_signature' in source['process']['Ext']:
                source['process']['Ext']['code_signature'] = condense_code_signature_array(
                    source['process']['Ext']['code_signature']
                )
        if 'parent' in source['process'] and isinstance(source['process']['parent'], dict):
            if 'Ext' in source['process']['parent'] and isinstance(source['process']['parent']['Ext'], dict):
                if 'code_signature' in source['process']['parent']['Ext']:
                    source['process']['parent']['Ext']['code_signature'] = condense_code_signature_array(
                        source['process']['parent']['Ext']['code_signature']
                    )
    
    # === REMOVE DUPLICATIVE NESTED FIELDS ===
    # Remove kibana.alert.original_event if it duplicates the root event
    if 'kibana' in source and 'alert' in source['kibana']:
        if 'original_event' in source['kibana']['alert']:
            # Keep only if it has unique data not in root event
            original_evt = source['kibana']['alert']['original_event']
            root_evt = source.get('event', {})
            if isinstance(original_evt, dict) and isinstance(root_evt, dict):
                # If they look similar, remove original_event
                if original_evt.get('code') == root_evt.get('code'):
                    source['kibana']['alert'].pop('original_event', None)
    
    # === CONDENSE HOST INFO ===
    # Remove excessive IP arrays (keep first 3)
    if 'host' in source and isinstance(source['host'], dict):
        if 'ip' in source['host'] and isinstance(source['host']['ip'], list):
            if len(source['host']['ip']) > 3:
                ip_count = len(source['host']['ip'])
                source['host']['ip'] = source['host']['ip'][:3] + [f'... {ip_count - 3} more IPs']
        if 'mac' in source['host'] and isinstance(source['host']['mac'], list):
            if len(source['host']['mac']) > 2:
                mac_count = len(source['host']['mac'])
                source['host']['mac'] = source['host']['mac'][:2] + [f'... {mac_count - 2} more MACs']
    
    # === REMOVE LARGE TEXT FIELDS ===
    # Remove/truncate message field if long (usually duplicates reason)
    if 'message' in source:
        if isinstance(source['message'], str) and len(source['message']) > 500:
            source['message'] = source['message'][:200] + "... [truncated]"
    
    # Remove event.original if huge
    if 'event' in source and 'original' in source['event']:
        if isinstance(source['event']['original'], str) and len(source['event']['original']) > 2000:
            source['event'].pop('original', None)
    
    # === CONDENSE RELATED.* ARRAYS ===
    if 'related' in source:
        for key in list(source['related'].keys()):
            if isinstance(source['related'][key], list) and len(source['related'][key]) > 10:
                count = len(source['related'][key])
                source['related'][key] = source['related'][key][:10] + [f'... {count - 10} more']
    
    # === REMOVE MEMORY_PROTECTION VERBOSE FIELDS ===
    if 'Memory_protection' in source and isinstance(source['Memory_protection'], dict):
        # Keep only essential memory protection indicators
        essential_memory_fields = {'feature', 'self_injection', 'cross_session'}
        mem_keys = list(source['Memory_protection'].keys())
        for key in mem_keys:
            if key not in essential_memory_fields:
                source['Memory_protection'].pop(key, None)
    
    # === REMOVE RULE METADATA ===
    if 'rule' in source and isinstance(source['rule'], dict):
        # Usually just contains "ruleset": "production" - not useful
        source.pop('rule', None)
    
    # Update _source if we were working with it
    if '_source' in condensed:
        condensed['_source'] = source
    
    return condensed


def _take_chunk_portion(text, capacity):
    """Return a tuple of (chunk, remainder) using soft newline boundaries."""
    if capacity <= 0:
        raise ValueError("capacity must be positive")
    if not isinstance(text, str):
        text = str(text)
    if len(text) <= capacity:
        return text, ""

    split_idx = capacity
    newline_idx = text.rfind('\n', 0, capacity)
    # Prefer to split on a newline that is reasonably close to the limit for readability
    if newline_idx != -1 and capacity - newline_idx <= 1000:
        split_idx = max(newline_idx + 1, 1)

    chunk = text[:split_idx]
    remainder = text[split_idx:]
    if not chunk:
        chunk = text[:capacity]
        remainder = text[capacity:]
    return chunk, remainder


def split_json_into_prompt_chunks(json_text, instructions, max_prompt_chars, continuation_buffer=1500):
    """
    Split JSON payload into multiple prompt-safe chunks while keeping instructions in the first chunk.
    Returns a list of prompt strings, each smaller than max_prompt_chars.
    """
    if not isinstance(json_text, str):
        json_text = str(json_text)
    if not isinstance(instructions, str):
        instructions = str(instructions)
    if max_prompt_chars <= 0:
        raise ValueError("max_prompt_chars must be positive")

    # We'll try to construct chunks such that each final prompt (header + chunk)
    # does not exceed `max_prompt_chars`. Because header length depends on
    # the total number of chunks, we may need to iteratively shrink the
    # continuation payload size until all constructed prompts fit.
    if continuation_buffer < 0:
        raise ValueError("continuation_buffer must be non-negative")

    # Starting conservative continuation capacity (will be reduced if needed)
    continuation_capacity = max_prompt_chars - continuation_buffer
    if continuation_capacity <= 0:
        raise ValueError("Continuation buffer too large for remaining prompt space.")

    # Iteratively attempt chunking, shrinking continuation_capacity when headers+chunks overflow
    attempt = 0
    max_attempts = 12
    chunk_texts = None
    while True:
        attempt += 1

        # Make a reasonable first-chunk capacity that leaves room for the instructions
        first_capacity = max(256, continuation_capacity - len(instructions) - 2)
        if first_capacity <= 0:
            raise ValueError("Instructions exceed available prompt capacity.")

        # Perform chunking using the current capacities
        remaining = json_text
        first_chunk, remaining = _take_chunk_portion(remaining, first_capacity)
        tmp_chunks = [first_chunk]
        too_many = False
        while remaining:
            chunk, remaining = _take_chunk_portion(remaining, continuation_capacity)
            if not chunk:
                break
            tmp_chunks.append(chunk)
            if len(tmp_chunks) > 800:
                too_many = True
                break

        if too_many:
            # Shrink and retry
            if attempt >= max_attempts or continuation_capacity <= 256:
                raise ValueError("Too many chunks required to satisfy prompt limits.")
            continuation_capacity = max(256, int(continuation_capacity * 0.7))
            continue

        # Now build prompts with headers and validate sizes
        prompts_try = []
        total_chunks = len(tmp_chunks)
        for idx, chunk_text in enumerate(tmp_chunks, start=1):
            if idx == 1:
                header = (
                    f"[CHUNK {idx}/{total_chunks}] BEGIN ALERT JSON - DO NOT RESPOND OR ANALYZE UNTIL ALL CHUNKS ARE RECEIVED.\n"
                    f"The final chunk will include the exact marker: END_OF_ALERT_JSON_CHUNKS\n"
                    "When you receive the final chunk containing that marker, then process all chunks together and reply.\n\n"
                    f"INSTRUCTIONS (do not alter):\n{instructions}\n\n"
                )
            else:
                final_note = " This is the FINAL CHUNK; after this chunk the sender will provide the marker: END_OF_ALERT_JSON_CHUNKS." if idx == total_chunks else ""
                header = (
                    f"[CHUNK {idx}/{total_chunks}] CONTINUATION - DO NOT RESPOND. Paste this immediately after the previous chunk so the assistant retains context.{final_note}\n\n"
                )

            # If this is the last chunk, append the explicit end marker so remote assistant knows all chunks arrived
            if idx == total_chunks:
                prompts_try.append(header + chunk_text + "\nEND_OF_ALERT_JSON_CHUNKS\n")
            else:
                prompts_try.append(header + chunk_text)

        # Verify all prompts fit within max_prompt_chars
        oversized = [p for p in prompts_try if len(p) > max_prompt_chars]
        if not oversized:
            chunk_texts = tmp_chunks
            break

        # If oversized, shrink continuation_capacity and retry
        if attempt >= max_attempts or continuation_capacity <= 256:
            raise ValueError("Chunked prompt still exceeds configured limit.")
        # Reduce by 20% and retry
        continuation_capacity = max(256, int(continuation_capacity * 0.8))
        # loop to retry

    # Build final prompts (we already validated sizes in the loop above)
    prompts = []
    total_chunks = len(chunk_texts)
    for idx, chunk_text in enumerate(chunk_texts, start=1):
        if idx == 1:
            header = (
                f"[CHUNK {idx}/{total_chunks}] BEGIN ALERT JSON - DO NOT RESPOND OR ANALYZE UNTIL ALL CHUNKS ARE RECEIVED.\n"
                f"The final chunk will include the exact marker: END_OF_ALERT_JSON_CHUNKS\n"
                "When you receive the final chunk containing that marker, then process all chunks together and reply.\n\n"
                f"INSTRUCTIONS (do not alter):\n{instructions}\n\n"
            )
        else:
            final_note = " This is the FINAL CHUNK; after this chunk the sender will provide the marker: END_OF_ALERT_JSON_CHUNKS." if idx == total_chunks else ""
            header = (
                f"[CHUNK {idx}/{total_chunks}] CONTINUATION - DO NOT RESPOND. Paste this immediately after the previous chunk so the assistant retains context.{final_note}\n\n"
            )

        # Ensure final chunk contains the explicit end marker required by cooperating assistants
        if idx == total_chunks:
            prompts.append(header + chunk_text + "\nEND_OF_ALERT_JSON_CHUNKS\n")
        else:
            prompts.append(header + chunk_text)

    return prompts


def print_prompt_size_guidance(char_count):
    if char_count >= CHATGPT5_NEAR_LIMIT_THRESHOLD:
        print(f"⚠️  CAUTION: Prompt is very close to the current ChatGPT-5.1 cap (~{CHATGPT5_HARD_CHAR_LIMIT:,} chars).")
    elif char_count >= max(CHATGPT5_LARGE_PROMPT_THRESHOLD, 0):
        print("ℹ️  INFO: Prompt is large but still within the reduced limit.")
    else:
        print("✓ Prompt size is within safe limits for ChatGPT-5 extended thinking.")


def _get_nested_dict(data_dict, keys):
    current = data_dict
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current if isinstance(current, dict) else None


def _contains_npm_token(text):
    if not text:
        return False
    lowered = text.lower()
    if 'npm-cli.js' in lowered:
        return True
    return bool(re.search(r'(^|[\s"\'/\\])npm(\.cmd|\.exe)?([\s"\'/\\]|$)', lowered))


def is_npm_related_process(name, command_line, args):
    name_lower = (name or '').lower()
    if name_lower in {'npm', 'npm.exe', 'npm.cmd'}:
        return True
    iterable_args = []
    if isinstance(args, list):
        iterable_args = [str(a) for a in args if a]
    if _contains_npm_token(command_line or ''):
        return True
    for arg in iterable_args:
        if _contains_npm_token(arg):
            return True
    return False


def summarize_npm_command(command_line, args):
    tokens = []
    if isinstance(args, list) and args:
        tokens = [str(a) for a in args if a]
    elif isinstance(command_line, str) and command_line.strip():
        tokens = [t for t in re.split(r'\s+', command_line.strip()) if t]
    if not tokens:
        return "Unable to parse npm command (no arguments provided)."

    lowered = [t.lower() for t in tokens]
    npm_idx = None
    for idx, tok in enumerate(lowered):
        if 'npm' == tok or tok.endswith('npm') or 'npm-cli.js' in tok or tok.endswith('npm.cmd') or tok.endswith('npm.exe'):
            npm_idx = idx
            break
    relevant = tokens[npm_idx + 1:] if npm_idx is not None and npm_idx + 1 < len(tokens) else tokens
    if not relevant:
        return "NPM invoked without additional arguments."

    primary = relevant[0].lower()
    extra = relevant[1:]

    def _join(values, limit=6):
        display = values[:limit]
        tail = " ..." if len(values) > limit else ""
        return " ".join(display) + tail if display else ""

    if primary == 'run':
        script = extra[0] if extra else None
        if script:
            extras = _join(extra[1:])
            return f"npm run `{script}`" + (f" with extras: {extras}" if extras else "")
        return "npm run executed without a script target."
    elif primary in {'install', 'i', 'ci', 'update', 'upgrade', 'uninstall', 'remove', 'exec', 'audit', 'start', 'test', 'build'}:
        joined = _join(extra)
        return f"npm {primary}" + (f" {joined}" if joined else " (no additional arguments).")

    joined_generic = _join(relevant)
    return "npm " + joined_generic if joined_generic else "npm executed without arguments."


def detect_npm_activity(alert_data):
    activity = []
    candidates = [
        (['process'], "Alerted Process"),
        (['process', 'parent'], "Parent Process"),
        (['Target', 'process'], "Target Process"),
    ]
    for path, label in candidates:
        proc_dict = _get_nested_dict(alert_data, path)
        if not proc_dict:
            continue
        name = proc_dict.get('name') or _basename(proc_dict.get('executable', ''))
        command_line = proc_dict.get('command_line')
        args = proc_dict.get('args') if isinstance(proc_dict.get('args'), list) else None
        if not is_npm_related_process(name, command_line, args):
            continue
        activity.append({
            'label': label,
            'name': name or 'npm',
            'command_line': command_line,
            'args': args,
            'working_directory': proc_dict.get('working_directory'),
            'summary': summarize_npm_command(command_line, args)
        })
    return activity

def get_nested_value(data_dict, keys, default="N/A"):
    """Safely retrieves a nested value from a dictionary."""
    current_value = data_dict
    try:
        for i, key in enumerate(keys):
            if isinstance(current_value, dict):
                current_value = current_value.get(key)
            elif isinstance(current_value, list):
                try:
                    idx = int(key)
                    if 0 <= idx < len(current_value):
                        current_value = current_value[idx]
                    else:
                        current_value = None
                except (ValueError, TypeError):
                    if i == len(keys) - 1:
                        pass
                    else:
                        current_value = None
            else:
                current_value = None
            if current_value is None:
                break
        if current_value in [None, "", []]:
            return default
        return current_value
    except (TypeError, KeyError, IndexError):
        return default

def format_timestamp(ts_string, default="N/A"):
    """Formats an ISO 8601 timestamp string."""
    if not ts_string or ts_string == default:
        return default
    try:
        if isinstance(ts_string, str) and ts_string.endswith('Z'):
            ts_string = ts_string[:-1] + '+00:00'
        dt_obj = datetime.fromisoformat(ts_string)
        return dt_obj.strftime('%Y-%m-%d %H:%M:%S %Z%z')
    except ValueError:
        return ts_string

def format_list(data_list, default="N/A"):
    """Formats a list into a comma-separated string."""
    if not isinstance(data_list, list) or not data_list:
        return default
    return ", ".join(map(str, data_list))

def _zone_from_path(path):
    if not isinstance(path, str) or not path:
        return "Unknown"
    p = path.lower()
    if p.startswith("\\\\"): return "UNC/Network"
    if ":\\windows\\system32" in p: return "System32"
    if ":\\windows\\" in p: return "Windows"
    if ":\\program files" in p: return "Program Files"
    if "\\appdata\\local\\temp\\" in p or p.endswith("\\temp") or "\\temp\\" in p: return "Temp"
    if "\\downloads\\" in p: return "Downloads"
    if "\\users\\" in p: return "User Profile"
    return "Other"

# --- Signature status helper ---
def get_signature_status_string(sig_info_dict):
    if not isinstance(sig_info_dict, dict) or not sig_info_dict:
        return "Unsigned or Info Unavailable"
    verified_status_raw = sig_info_dict.get('verified', None)
    if verified_status_raw is None:
        return "Unsigned"
    verified_status = str(verified_status_raw).lower().strip()
    if "revoked" in verified_status: return "Revoked"
    if "expired" in verified_status: return "Expired"
    if "invalid" in verified_status: return "Invalid"
    if "cannot verify" in verified_status: return "Cannot Verify"
    if "file is not signed" in verified_status or verified_status == "not signed": return "Unsigned"
    if "unsigned" in verified_status: return "Unsigned"
    if "signed and valid" in verified_status or verified_status in ("valid", "signed"): return "Valid"
    return str(verified_status_raw).capitalize() if verified_status_raw else "Status Unknown"

def _drive_letter(path):
    if isinstance(path, str) and len(path) >= 2 and path[1] == ":":
        return path[0].upper()
    return "?"

def _is_lolbin(name):
    if not name: return False
    lolbins = {
        "rundll32.exe","regsvr32.exe","mshta.exe","powershell.exe","cmd.exe","wscript.exe","cscript.exe",
        "wmic.exe","msiexec.exe","certutil.exe","bitsadmin.exe","installutil.exe","msbuild.exe",
        "forfiles.exe","schtasks.exe","curl.exe","ftp.exe","vssadmin.exe","bcdedit.exe","wbadmin.exe"
    }
    return name.lower() in lolbins

def _suspicious_parent_child(p_name, c_name):
    p = (p_name or "").lower()
    c = (c_name or "").lower()
    combos = {
        "winword.exe": {"powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","msiexec.exe"},
        "excel.exe":   {"powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","msiexec.exe"},
        "powerpnt.exe":{"powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","msiexec.exe"},
        "outlook.exe": {"powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","msiexec.exe"},
        "explorer.exe":{"powershell.exe","wscript.exe","cscript.exe","cmd.exe","mshta.exe","rundll32.exe"},
        "chrome.exe":  {"powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","msiexec.exe"},
        "msedge.exe":  {"powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","msiexec.exe"},
        "firefox.exe": {"powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","msiexec.exe"},
        "svchost.exe": {"powershell.exe","cmd.exe"}
    }
    return c in combos.get(p, set())

def _has_suspicious_flags(cmd):
    if not isinstance(cmd, str): return False
    s = cmd.lower()
    flags = [" -enc", "-encodedcommand", " -nop", "-w hidden", "/bypass", " -nologo", " -exec bypass"]
    return any(flag in s for flag in flags)

def _file_ext(path_or_name):
    if not isinstance(path_or_name, str): return ""
    base = path_or_name.rsplit("\\",1)[-1]
    if "." in base: return base.rsplit(".",1)[1].lower()
    return ""

def _suspicious_file_ext(ext):
    return ext in {"js","vbs","vbe","jse","wsf","wsh","hta","ps1","bat","cmd","scr","dll"}

def extract_username_from_paths(data):
    """
    Attempts to extract username from file paths when user.name is not provided.
    Looks for patterns like C:\\Users\\username\\ in various path fields.
    Returns the extracted username or None if not found.
    """
    import re
    
    # Common path fields to check
    path_fields = [
        ['file', 'path'],
        ['process', 'executable'],
        ['process', 'path'],
        ['process', 'parent', 'executable'],
        ['process', 'parent', 'path'],
        ['process', 'working_directory'],
        ['process', 'args'],
    ]
    
    # Pattern to match Windows user paths: C:\Users\username\...
    # Captures username between \Users\ and the next backslash
    user_path_pattern = re.compile(r'[A-Z]:\\Users\\([^\\]+)\\', re.IGNORECASE)
    
    for field_path in path_fields:
        value = get_nested_value(data, field_path, default=None)
        
        # Handle both string and list values (like process.args)
        values_to_check = []
        if isinstance(value, str):
            values_to_check = [value]
        elif isinstance(value, list):
            values_to_check = [str(v) for v in value if v]
        
        for path_str in values_to_check:
            if not path_str:
                continue
                
            match = user_path_pattern.search(path_str)
            if match:
                username = match.group(1)
                # Filter out common system accounts
                system_accounts = {'public', 'default', 'defaultuser0', 'administrator', 'guest', 'all users'}
                if username.lower() not in system_accounts:
                    return username
    
    return None

def _get_pid_ppid(data):
    pid  = get_nested_value(data, ['process','pid'], default="N/A")
    ppid = get_nested_value(data, ['process','parent','pid'], default="N/A")
    return pid, ppid

def _get_start_times(data):
    child_start  = format_timestamp(get_nested_value(data, ['process','start'], default="N/A"))
    parent_start = format_timestamp(get_nested_value(data, ['process','parent','start'], default="N/A"))
    return child_start, parent_start

# --- Memory alert helpers ---
def is_memory_related(context, data):
    """Heuristically determine if this alert directly involves memory (e.g., memory protection, code injection, suspicious thread).
    Uses rule name, reason text, and presence of Endgame suspicious_thread_info.
    """
    try:
        rule_name = (context.get('rule_name') or '').lower()
        reason = (context.get('reason') or '').lower()
        if 'memory' in rule_name or 'memory' in reason:
            return True

        # Endgame module or data hints
        endgame_module = get_nested_value(data, ['endgame', 'module'], default="N/A")
        if isinstance(endgame_module, str) and 'memory' in endgame_module.lower():
            return True

        suspicious_thread = get_nested_value(data, ['endgame', 'data', 'suspicious_thread_info', '0'], default="N/A")
        if isinstance(suspicious_thread, dict) and suspicious_thread:
            return True

        # Other common hints in tags or event.action
        tags = get_nested_value(data, ['tags'], default=[])
        if isinstance(tags, list) and any(isinstance(t, str) and 'memory' in t.lower() for t in tags):
            return True

        event_action = get_nested_value(data, ['event', 'action'], default="N/A")
        if isinstance(event_action, str) and any(k in event_action.lower() for k in ['suspicious_thread', 'code_injection', 'create_remote_thread']):
            return True
    except Exception:
        pass
    return False


def is_shellcode_related(context, data):
    """Detect whether alert references shellcode execution or injection."""
    try:
        keywords = ('shellcode', 'shell code', 'shell-code', 'shell_code')

        def _contains_keywords(value):
            if not isinstance(value, str):
                return False
            lowered = value.lower()
            return any(keyword in lowered for keyword in keywords)

        rule_name = context.get('rule_name') or ''
        reason = context.get('reason') or ''
        if _contains_keywords(rule_name) or _contains_keywords(reason):
            return True

        event_action = get_nested_value(data, ['event', 'action'], default='')
        if _contains_keywords(event_action):
            return True

        tags = get_nested_value(data, ['tags'], default=[])
        if isinstance(tags, list) and any(_contains_keywords(str(tag)) for tag in tags):
            return True

        threat_desc = get_nested_value(data, ['threat', 'indicator', 'description'], default='')
        if _contains_keywords(threat_desc):
            return True

        detection = get_nested_value(data, ['Detection', 'message'], default='')
        if _contains_keywords(detection):
            return True
    except Exception:
        pass
    return False

def _format_stack_frames(frames):
    """Format a list of frames that may be strings or dicts."""
    out = []
    for fr in frames:
        try:
            if isinstance(fr, str):
                line = fr.strip('\n')
            elif isinstance(fr, dict):
                module = fr.get('module') or fr.get('image') or fr.get('dll') or ''
                symbol = fr.get('symbol_info') or fr.get('symbol') or fr.get('function') or ''
                addr = fr.get('address') or fr.get('addr') or ''
                offset = fr.get('offset') or ''
                headline = []
                if module:
                    headline.append(str(module))
                if symbol:
                    headline.append(str(symbol))
                if offset:
                    headline.append(f"+{offset}")
                head = ' | '.join(headline)
                detail_pairs = []
                preferred_order = [
                    ('protection_provenance_path', 'path'),
                    ('protection_provenance', 'provenance'),
                    ('allocation_private_bytes', 'bytes'),
                    ('callsite_trailing_bytes', 'trailing'),
                    ('callsite_leading_bytes', 'leading'),
                ]
                for key, label in preferred_order:
                    value = fr.get(key)
                    if value:
                        trimmed = str(value)
                        if len(trimmed) > 140:
                            trimmed = trimmed[:137] + '...'
                        detail_pairs.append(f"{label}: {trimmed}")
                residual = {
                    k: v for k, v in fr.items()
                    if k not in {pair[0] for pair in preferred_order}
                    and k not in {'module', 'image', 'dll', 'symbol_info', 'symbol', 'function', 'sym', 'address', 'addr', 'offset'}
                }
                for key, value in residual.items():
                    if value is None or isinstance(value, (list, dict)):
                        continue
                    detail_pairs.append(f"{key}: {value}")
                pieces = []
                if head:
                    pieces.append(head)
                if addr:
                    pieces.append(f"addr: {addr}")
                if detail_pairs:
                    pieces.append(" | ".join(detail_pairs))
                line = " | ".join(pieces) if pieces else json.dumps(fr, ensure_ascii=False)
            else:
                line = str(fr)
        except Exception:
            line = str(fr)
        out.append(line)
    return out

def extract_call_stack(data):
    """Attempt to extract a call stack from multiple possible fields in the alert payload.
    Returns a normalized multi-line string or "N/A" if not found.
    """
    # Primary suspected location (Elastic Endgame suspicious thread info)
    suspicious_thread = get_nested_value(data, ['endgame', 'data', 'suspicious_thread_info', '0'], default=None)
    candidate_values = []
    if isinstance(suspicious_thread, dict):
        # Look for explicit stack fields first
        for key in ['call_stack', 'stack_trace', 'stack', 'stack_buffer']:
            val = suspicious_thread.get(key)
            if val:
                candidate_values.append(val)
        # If none explicit, try any field that looks like stack-ish
        if not candidate_values:
            for k, v in suspicious_thread.items():
                if isinstance(k, str) and any(s in k.lower() for s in ['stack', 'trace']):
                    if v:
                        candidate_values.append(v)

    # Other possible locations
    other_paths = [
        ['endgame','data','call_stack'],
        ['kibana','alert','original_event','call_stack'],
        ['kibana','alert','original_event','stack_trace'],
        ['event','call_stack'],
        ['event','stacktrace'],
        ['process','thread','stack'],
        ['process','thread','Ext','call_stack'],
        ['process','thread','Ext','call_stack_summary'],
    ]
    for p in other_paths:
        v = get_nested_value(data, p, default=None)
        if v:
            candidate_values.append(v)

    # Also check common flattened keys used by Elastic _source
    flat_keys = [
        'process.thread.Ext.call_stack',
        'process.thread.Ext.call_stack_summary',
        'kibana.alert.original_event.process.thread.Ext.call_stack',
        'kibana.alert.original_event.process.thread.Ext.call_stack_summary',
        'winlog.event_data.CallTrace',
        'event.original',
        'message',
        'kibana.alert.reason',
    ]
    for k in flat_keys:
        try:
            v = data.get(k)
            if v:
                candidate_values.append(v)
        except Exception:
            pass

    if not candidate_values:
        return "N/A"

    # Normalize: prefer the first non-empty candidate
    value = candidate_values[0]
    lines = []
    if isinstance(value, str):
        # Split on common delimiters while keeping readability
        raw_lines = [l for l in value.replace('\r','').split('\n') if l.strip()]
        lines = raw_lines
    elif isinstance(value, list):
        lines = _format_stack_frames(value)
    elif isinstance(value, dict):
        # Some payloads use a dict with frames
        frames = value.get('frames') or value.get('stack') or value.get('trace') or []
        if isinstance(frames, list):
            lines = _format_stack_frames(frames)
        else:
            # Fallback to stringified dict
            return json.dumps(value, ensure_ascii=False)
    else:
        lines = [str(value)]

    # Cap excessively long stacks but keep informative content
    MAX_LINES = 60
    if len(lines) > MAX_LINES:
        head = lines[:MAX_LINES]
        head.append(f"... (truncated, {len(lines)} total frames)")
        lines = head

    return "\n".join(lines) if lines else "N/A"

def extract_call_stack_summary(data):
    """Extract the call stack summary only from common Elastic Endpoint fields.
    Returns a list of pretty lines or an empty list if not found.
    Preferred fields: process.thread.Ext.call_stack_summary and its original_event variant.
    """
    candidates = []

    # Try nested forms first
    nested_paths = [
        ['process','thread','Ext','call_stack_summary'],
        ['kibana','alert','original_event','process','thread','Ext','call_stack_summary'],
    ]
    for p in nested_paths:
        v = get_nested_value(data, p, default=None)
        if v:
            candidates.append(v)

    # Also check flattened keys directly on the top-level doc
    for k in (
        'process.thread.Ext.call_stack_summary',
        'kibana.alert.original_event.process.thread.Ext.call_stack_summary',
    ):
        try:
            v = data.get(k)
            if v:
                candidates.append(v)
        except Exception:
            pass

    if not candidates:
        return []

    value = candidates[0]
    lines = []
    # Normalize different shapes
    if isinstance(value, str):
        txt = value.replace('\r','').strip()
        # Split on newlines or semicolons commonly used in summaries
        if '\n' in txt:
            lines = [l.strip() for l in txt.split('\n') if l.strip()]
        else:
            parts = [p.strip() for p in txt.split(';') if p.strip()]
            lines = parts if parts else ([txt] if txt else [])
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                s = item.strip()
                if s:
                    lines.append(s)
            elif isinstance(item, dict):
                si = item.get('symbol_info') or item.get('summary') or item.get('symbol') or ''
                if si:
                    lines.append(str(si).strip())
    elif isinstance(value, dict):
        # Some implementations put summary under a key
        si = value.get('summary') or value.get('text') or value.get('symbol_info')
        if isinstance(si, str):
            txt = si.replace('\r','').strip()
            if '\n' in txt:
                lines = [l.strip() for l in txt.split('\n') if l.strip()]
            else:
                parts = [p.strip() for p in txt.split(';') if p.strip()]
                lines = parts if parts else ([txt] if txt else [])

    # Basic prettifying: collapse excessive spaces
    pretty = []
    for l in lines:
        s = ' '.join(str(l).split())
        if s:
            pretty.append(s)

    MAX_LINES = 60
    if len(pretty) > MAX_LINES:
        pretty = pretty[:MAX_LINES] + [f"... (truncated, {len(lines)} total frames)"]

    return pretty

# --- Call Stack Context Summarizer ---
INJECTION_API_HINTS = {
    "writeprocessmemory",
    "createremotethread",
    "ntcreatethreadex",
    "queueuserapc",
    "setthreadcontext",
    "virtualalloc",
    "virtualallocex",
    "virtualprotect",
    "ntmapviewofsection",
    "rtlcreateuserthread",
}

NETWORK_MODULE_HINTS = {"ws2_32", "wininet", "winhttp"}

SYSTEM_MODULE_HINTS = {
    "ntdll", "kernel32", "kernelbase", "user32", "gdi32", "advapi32",
    "rpcrt4", "sechost", "ucrtbase", "combase", "ole32", "shell32",
    "shcore", "ws2_32", "wininet", "winhttp"
}

def _parse_module_from_summary_line(line: str) -> str:
    """Best-effort extraction of a module name from a call stack summary line."""
    if not isinstance(line, str) or not line:
        return ""
    s = line.strip()
    # Common shapes: module.dll!Func, C:\Path\module.dll!Func, module.dll, module.exe
    m = re.search(r"([A-Za-z0-9._-]+)\.(dll|exe)\b", s, flags=re.IGNORECASE)
    if not m:
        return ""
    return (m.group(1) or "").lower()

def summarize_call_stack_context(summary_lines, data):
    """
    Produce a concise, actionable one-liner context from call stack summary:
    - top=<first non-system module>
    - apis=<up to 3 suspicious APIs>
    - non-sys=X/Y
    - network=yes (if networking modules present)
    - target=<target process name> (if present)
    """
    try:
        lines = summary_lines or []
        total = len(lines)

        modules = []
        suspicious_apis = set()
        network_present = False

        for ln in lines:
            mod = _parse_module_from_summary_line(ln)
            if mod:
                modules.append(mod)
                if mod in NETWORK_MODULE_HINTS:
                    network_present = True
            low = ln.lower()
            for api in INJECTION_API_HINTS:
                if api in low:
                    suspicious_apis.add(api)

        # First non-system module if any
        top_non_system = None
        for mname in modules:
            if mname not in SYSTEM_MODULE_HINTS:
                top_non_system = mname
                break

        non_system_count = sum(1 for mname in modules if mname and mname not in SYSTEM_MODULE_HINTS)

        # Target process (Elastic Endgame suspicious thread target)
        target_proc = get_nested_value(data, ['endgame','data','suspicious_thread_info','0','target_process_name'], default='N/A')
        target_disp = _basename(target_proc) if isinstance(target_proc, str) else 'N/A'

        parts = []
        if top_non_system:
            parts.append(f"top={top_non_system}")
        if suspicious_apis:
            apis_sorted = sorted(suspicious_apis)
            parts.append("apis=" + ", ".join(apis_sorted[:3]))
        if total:
            parts.append(f"non-sys={non_system_count}/{total}")
        if network_present:
            parts.append("network=yes")
        if target_disp and target_disp != 'N/A':
            parts.append(f"target={target_disp}")

        return ", ".join(parts) if parts else None
    except Exception:
        return None

# --- Execution Chain (Option 1: relationship-only) ---

def _basename(path_or_name):
    if not isinstance(path_or_name, str) or not path_or_name:
        return "N/A"
    # strip quotes and split on backslashes
    s = path_or_name.strip().strip('"').strip("'")
    return s.rsplit("\\", 1)[-1] if "\\" in s else s

def build_execution_chain(context, data):
    """
    Build a minimal relationship-only chain:
      ParentName ➜ ChildName [➜ TargetName or FileName (if distinct)]
    No zones, PIDs, signatures, times, or highlights.
    """
    # Parent / child from Elastic common fields
    parent_name = _basename(get_nested_value(data, ['process','parent','name'], default="N/A"))
    child_name  = _basename(get_nested_value(data, ['process','name'], default="N/A"))

    # Optional injection target (Endgame)
    # endgame.data.suspicious_thread_info[].target_process_name often holds a full path
    target_proc_path = get_nested_value(
        data,
        ['endgame','data','suspicious_thread_info', '0', 'target_process_name'],
        default="N/A"
    )
    target_name = _basename(target_proc_path)

    # Optional file node from context (only if distinct from child)
    file_name = _basename(context.get('file_name', 'N/A'))
    add_file = file_name not in ("N/A", child_name)

    # Prefer showing an injection target if present
    nodes = []
    if parent_name != "N/A": nodes.append(f"`{parent_name}`")
    if child_name  != "N/A": nodes.append(f"`{child_name}`")

    if target_name not in ("N/A", "", child_name):
        nodes.append(f"`{target_name}`")
    elif add_file:
        nodes.append(f"`{file_name}`")

    chain_str = " ➜ ".join(nodes) if nodes else "N/A"
    return {"summary": chain_str}

def format_execution_chain(chain):
    """
    Render only the one-line chain, nothing else.
    """
    lines = []
    lines.append("\n**Process / File Execution Chain:**")
    if chain and chain.get("summary") and chain["summary"] != "N/A":
        lines.append("> Chain:")
        lines.append(f">> {chain['summary']}")
    else:
        lines.append("> Chain:")
        lines.append(">> N/A")
    return lines


# --- VT check ---
def check_virustotal(hash_value, api_key):
    """
    Performs a passive check against VT API v3.
    Returns: dict: {'summary': str, 'attributes': dict | None, 'signature_info': dict | None, 'error': bool}
    """
    results = {
        'summary': "No VT Result",
        'attributes': None,
        'signature_info': None,
        'error': True
    }
    if not api_key:
        results['summary'] = "VT Skipped: No API Key"
        results['error'] = False
        return results
    if not hash_value or hash_value == "N/A":
        results['summary'] = "No Hash Value Provided"
        results['error'] = False
        return results

    headers = {"accept": "application/json", "x-apikey": api_key}
    url = VIRUSTOTAL_API_URL.format(hash_value)
    vt_link = f"https://www.virustotal.com/gui/file/{hash_value}"

    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 429:
            print("   VT Rate limit hit, waiting 5s...")
            time.sleep(5)
            response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            raw_data = response.json()
            attributes = raw_data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            meaningful_name = attributes.get("meaningful_name", "N/A")
            summary = f"VT Found: M:{malicious} S:{suspicious} H:{harmless} U:{undetected}"
            if meaningful_name != "N/A":
                summary += f" | Name: {meaningful_name}"
            summary += f" | [VirusTotal]({vt_link})"
            signature_info = attributes.get("signature_info")

            results = {
                'summary': summary,
                'attributes': attributes,
                'signature_info': signature_info,
                'error': False
            }
        elif response.status_code == 404:
            results = {
                'summary': f"VT Not Found | [Link:]({vt_link})",
                'attributes': None,
                'signature_info': None,
                'error': False
            }
        elif response.status_code == 401:
            results['summary'] = "VT Error: Invalid API Key"
            results['signature_info'] = None
        elif response.status_code == 429:
            results['summary'] = "VT Error: Rate limit exceeded after retry."
            results['signature_info'] = None
        else:
            results['summary'] = f"VT Error: Status Code {response.status_code} - {response.text[:100]}"
            results['signature_info'] = None

    except requests.exceptions.Timeout:
        results['summary'] = "VT Network Error: Request timed out."
        results['signature_info'] = None
    except requests.exceptions.RequestException as e:
        results['summary'] = f"VT Network Error: {e}"
        results['signature_info'] = None
    except Exception as e:
        results['summary'] = f"VT Parsing/Other Error: {e}"
        results['signature_info'] = None

    if 'signature_info' not in results:
        results['signature_info'] = None

    return results

# --- Customer Mapping Helper ---
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

# --- Observation Statement Generation Function ---
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
    subject_is_file = 'file' in rule_name_val.lower() or \
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

    # If the action is generic, the deterministic sentence is already clean and natural.
    if action_phrase == "triggered alert involving":
        return f"***Observation Statement***\n\n{fallback_sentence}"

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
        print(f"   DEBUG: Prompt length: {len(final_prompt)} chars")
        response = model.generate_content(final_prompt, generation_config=generation_config, safety_settings=safety_settings)
        print("   Received response from Gemini API.")
        print(f"   DEBUG: Response has parts: {hasattr(response, 'parts')}")
        if hasattr(response, 'candidates') and response.candidates:
            print(f"   DEBUG: Finish reason: {response.candidates[0].finish_reason.name}")
        
        # Try to extract text even if finish_reason is MAX_TOKENS
        # The model may have produced valid output before hitting the limit
        generated_sentence = None
        try:
            if hasattr(response, 'text') and response.text:
                generated_sentence = response.text.strip()
                print(f"   DEBUG: Extracted text length: {len(generated_sentence)} chars")
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
            print(f"   INFO: MAX_TOKENS reached, but extracted text: '{generated_sentence[:100]}...'")
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

# --- NEW: KQL Generation Function ---
def generate_kql_discover_query(context, data):
    """
    Generates a context-aware KQL Discover query based on alert type.
    Determines if alert is process-focused or file-focused and creates appropriate query.
    Pairs PIDs with process names for precise targeting and forces all values to lowercase.
    When available, adds a timestamp filter using event.ingested (the actual searchable event time field).
    """
    rule_name = context.get('rule_name', '').lower()
    
    # Extract event timestamp for time window filtering
    # Use actual event occurrence time, not alert creation time
    event_timestamp = None
    # Priority order: kibana.alert.original_time > event.ingested > Events[0]['@timestamp']
    # These represent when the event actually occurred, not when the alert was created
    
    event_timestamp = get_nested_value(data, ['kibana', 'alert', 'original_time'], default=None)
    
    if not event_timestamp:
        event_timestamp = get_nested_value(data, ['event', 'ingested'], default=None)
    
    if not event_timestamp:
        events_list = get_nested_value(data, ['Events'], default=[])
        if isinstance(events_list, list) and len(events_list) > 0:
            event_timestamp = get_nested_value(events_list[0], ['@timestamp'], default=None)
    
    # Parse timestamp and create window (±2 hours for broad search due to potential timezone/field mismatches)
    # Note: Time filtering is DISABLED by default due to timestamp field inconsistencies
    # Uncomment the time_filter line below to enable with a 4-hour window
    time_filter = None
    if event_timestamp:
        try:
            # Handle both ISO formats with and without 'Z'
            ts_str = event_timestamp
            if isinstance(ts_str, str):
                if ts_str.endswith('Z'):
                    ts_str = ts_str[:-1] + '+00:00'
                dt_obj = datetime.fromisoformat(ts_str)
                
                # Create ±2 hour window around the event (wide window to account for timezone issues)
                start_time = dt_obj - timedelta(hours=2)
                end_time = dt_obj + timedelta(hours=2)
                
                # Format for KQL (ISO 8601 format) - use @timestamp which is most reliable
                start_str = start_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                end_str = end_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
                
                # DISABLED: Uncomment the line below to enable time filtering
                # time_filter = f'@timestamp >= "{start_str}" AND @timestamp <= "{end_str}"'
                print(f"   Time filter available but DISABLED (would be: {start_str} to {end_str})")
                print(f"   Reason: Timestamp field mismatches often cause no results. Relying on host+process matching.")
        except Exception as e:
            print(f"   Warning: Could not parse event timestamp '{event_timestamp}': {e}")

    # Extract core fields - preserve original case for process/file names and hostname
    hostname = context.get('hostname', 'N/A')
    proc_name = context.get('proc_name', 'N/A')
    proc_pid = get_nested_value(data, ['process', 'pid'], default="N/A")
    parent_proc_name = context.get('parent_proc_name', 'N/A')
    parent_proc_pid = get_nested_value(data, ['process', 'parent', 'pid'], default="N/A")

    # Build process relationship query respecting actual parent-child hierarchy
    # This is more precise than searching for each process in both positions
    
    # Coerce PID to int where possible to avoid quotes
    def coerce_pid(pid_val):
        try:
            if pid_val is None or pid_val == "N/A":
                return None
            if isinstance(pid_val, str) and pid_val.isdigit():
                return int(pid_val)
            if isinstance(pid_val, (int, float)):
                return int(pid_val)
        except Exception:
            return None
        return None
    
    # Convert PIDs
    proc_pid = coerce_pid(proc_pid)
    parent_proc_pid = coerce_pid(parent_proc_pid)
    
    # Build the process query based on what's available
    # Strategy: Search for the exact parent-child relationship from the alert
    process_conditions = []
    
    # Primary: child process (the main subject of the alert)
    if proc_name != "N/A":
        if proc_pid is not None:
            process_conditions.append(f'process.name: "{proc_name}" AND process.pid: {proc_pid}')
        else:
            process_conditions.append(f'process.name: "{proc_name}"')
    
    # Parent process (provides context for the relationship)
    if parent_proc_name != "N/A":
        if parent_proc_pid is not None:
            process_conditions.append(f'process.parent.name: "{parent_proc_name}" AND process.parent.pid: {parent_proc_pid}')
        else:
            process_conditions.append(f'process.parent.name: "{parent_proc_name}"')
    
    # If we have both child and parent, search for the relationship
    # If we only have one, search for just that process
    parts = []
    if hostname != "N/A":
        parts.append(f'host.name: "{hostname}"')
    
    # Add time filter if available
    if time_filter:
        parts.append(time_filter)
    
    # Add process conditions
    if process_conditions:
        # Join all process conditions with OR (child OR parent = either process match)
        process_query = " OR ".join(process_conditions)
        parts.append(f'({process_query})')
    
    return " AND ".join(parts) if parts else ""

# --- Main Script Logic ---
def main():
    if not VIRUSTOTAL_API_KEY:
        print("Warning: VIRUSTOTAL_API_KEY environment variable not set. VirusTotal checks will be skipped.")
    if not GEMINI_API_KEY:
        print("Warning: GEMINI_API_KEY environment variable not set. AI observation statement generation will be skipped or use fallback.")

    print("--- Stage 1: Parsing Alert Data ---")
    print("Attempting to read JSON from clipboard...")

    try:
        clipboard_content = pyperclip.paste()
        if not clipboard_content:
            print("Error: Clipboard is empty.")
            sys.exit(1)

        try:
            alert_data = json.loads(clipboard_content)
            data = alert_data.get('_source', alert_data)
            print("JSON successfully parsed.")
        except json.JSONDecodeError:
            print("Error: Clipboard content is not valid JSON.")
            sys.exit(1)

        print("Extracting data fields...")
        context = {}
        # Core Alert Info
        context['rule_name'] = get_nested_value(data, ['kibana.alert.rule.name'], default=get_nested_value(data, ['rule', 'name']))
        context['reason'] = get_nested_value(data, ['kibana.alert.reason'], default="N/A")

        # User Info
        context['user_name'] = get_nested_value(data, ['user', 'name'], default=get_nested_value(data, ['endgame', 'user_name'], default=get_nested_value(data, ['winlog', 'user', 'name'])))
        context['user_domain'] = get_nested_value(data, ['user', 'domain'], default=get_nested_value(data, ['endgame', 'user_domain'], default=get_nested_value(data, ['winlog', 'user', 'domain'])))
        
        # Extract username from file paths if user.name is not provided
        if context['user_name'] in ["N/A", None, ""]:
            print("   User name not found in standard fields. Attempting to extract from file paths...")
            username_from_path = extract_username_from_paths(data)
            if username_from_path:
                context['user_name'] = username_from_path
                print(f"   Successfully extracted username from path: `{username_from_path}`")

        # Host Info
        # Prefer host.name (canonical), then fallback to host.hostname/observer/agent
        context['hostname'] = (
            get_nested_value(data, ['host', 'name'], default=None)
            or get_nested_value(data, ['host', 'hostname'], default=None)
            or get_nested_value(data, ['observer', 'hostname'], default=None)
            or get_nested_value(data, ['agent', 'hostname'], default="N/A")
        )
        context['host_domain'] = get_nested_value(data, ['host', 'domain'], default="N/A")
        context['host_os'] = get_nested_value(data, ['host', 'os', 'full'], default=get_nested_value(data, ['observer', 'os', 'full'], default=get_nested_value(data, ['agent', 'os', 'full'])))

        # Process Info
        context['proc_name'] = get_nested_value(data, ['process', 'name'])
        context['proc_path'] = get_nested_value(data, ['process', 'executable'])
        context['proc_cmd'] = get_nested_value(data, ['process', 'command_line'])
        proc_hash_sha256 = get_nested_value(data, ['process', 'hash', 'sha256'])
        proc_hash_sha1 = get_nested_value(data, ['process', 'hash', 'sha1'])
        proc_hash_md5 = get_nested_value(data, ['process', 'hash', 'md5'])
        context['proc_hash_sha256'] = proc_hash_sha256
        context['proc_hash_md5'] = proc_hash_md5
        proc_hash_to_check = proc_hash_sha256 if proc_hash_sha256 != "N/A" else (proc_hash_sha1 if proc_hash_sha1 != "N/A" else proc_hash_md5)
        print(f"   Checking VT for Primary Process Hash: {proc_hash_to_check}")
        context['proc_vt_details'] = check_virustotal(proc_hash_to_check, VIRUSTOTAL_API_KEY)

        # Parent Process Info
        context['parent_proc_name'] = get_nested_value(data, ['process', 'parent', 'name'])
        context['parent_proc_path'] = get_nested_value(data, ['process', 'parent', 'executable'])
        parent_proc_hash_sha256 = get_nested_value(data, ['process', 'parent', 'hash', 'sha256'])
        parent_proc_hash_sha1 = get_nested_value(data, ['process', 'parent', 'hash', 'sha1'])
        parent_proc_hash_md5 = get_nested_value(data, ['process', 'parent', 'hash', 'md5'])

        if context['parent_proc_name'] in (None, "", "N/A") and context['parent_proc_path'] not in (None, "", "N/A"):
            derived_parent_name = _basename(context['parent_proc_path'])
            if derived_parent_name and derived_parent_name != "N/A":
                context['parent_proc_name'] = derived_parent_name
                print(f"   Parent process name missing; derived from path: `{derived_parent_name}`")

        context['parent_proc_hash_sha256'] = parent_proc_hash_sha256
        context['parent_proc_hash_md5'] = parent_proc_hash_md5
        parent_hash_to_check = parent_proc_hash_sha256 if parent_proc_hash_sha256 != "N/A" else (parent_proc_hash_sha1 if parent_proc_hash_sha1 != "N/A" else parent_proc_hash_md5)
        print(f"   Checking VT for Parent Process Hash: {parent_hash_to_check}")
        context['parent_proc_vt_details'] = check_virustotal(parent_hash_to_check, VIRUSTOTAL_API_KEY)

        # File Info
        context['file_name'] = get_nested_value(data, ['file', 'name'])
        context['file_path'] = get_nested_value(data, ['file', 'path'])
        file_hash_sha256 = get_nested_value(data, ['file', 'hash', 'sha256'])
        file_hash_sha1 = get_nested_value(data, ['file', 'hash', 'sha1'])
        file_hash_md5 = get_nested_value(data, ['file', 'hash', 'md5'])
        context['file_hash_sha256'] = file_hash_sha256
        context['file_hash_md5'] = file_hash_md5
        
        # PE Info
        context['file_pe_company'] = get_nested_value(data, ['file', 'pe', 'company'], default="N/A")
        context['file_pe_description'] = get_nested_value(data, ['file', 'pe', 'description'], default="N/A")
        context['file_pe_product'] = get_nested_value(data, ['file', 'pe', 'product'], default="N/A")

        file_hash_to_check = file_hash_sha256 if file_hash_sha256 != "N/A" else (file_hash_sha1 if file_hash_sha1 != "N/A" else file_hash_md5)

        should_check_file_vt = file_hash_to_check != "N/A" and \
                               (file_hash_to_check != proc_hash_to_check or proc_hash_to_check == "N/A")

        if should_check_file_vt:
            print(f"   Checking VT for Associated File Hash: {file_hash_to_check}")
            context['file_vt_details'] = check_virustotal(file_hash_to_check, VIRUSTOTAL_API_KEY)
        else:
            context['file_vt_details'] = {
                'summary': 'VT Skipped (Same as Process or No Hash)',
                'attributes': None,
                'signature_info': None,
                'error': False
            }

        # Extract unique filename for specific rule patterns
        context['unique_arg_filename'] = "N/A"
        if context['rule_name'] == "Suspicious MS Office Child Process" and context['proc_name'] == 'explorer.exe':
            print("   Detected 'Suspicious MS Office Child Process' involving explorer.exe. Checking args for /select,")
            proc_args_list = get_nested_value(data, ['process', 'args'], default=[])
            cmd_line_str = get_nested_value(data, ['process', 'command_line'], default="N/A")
            target_arg = None
            if isinstance(proc_args_list, list):
                for arg in proc_args_list:
                    if isinstance(arg, str) and arg.lower().startswith("/select,"):
                        target_arg = arg
                        break
            elif cmd_line_str != "N/A" and "/select," in cmd_line_str.lower():
                parts = cmd_line_str.split()
                for i, part in enumerate(parts):
                    if part.lower() == "/select," and i + 1 < len(parts):
                        target_arg = "/select," + parts[i+1]
                        break
                    elif part.lower().startswith("/select,"):
                        target_arg = part
                        break

            if target_arg:
                try:
                    full_path = target_arg[len("/select,"):].strip().strip('"')
                    if full_path:
                        context['unique_arg_filename'] = os.path.basename(full_path)
                        print(f"   Successfully extracted unique filename from args: `{context['unique_arg_filename']}`")
                    else:
                        print("   Warning: Found '/select,' but path after comma was empty.")
                except Exception as e:
                    print(f"   Warning: Error extracting filename from '/select,' argument: {e}")
            else:
                print("   Info: '/select,' argument not found or could not be parsed for explorer.exe.")

        context['npm_activity'] = detect_npm_activity(data)

        # --- Stage 1.5: Observation Statement ---
        print("\n--- Stage 2: Generating Observation Statement ---")
        observation_statement = generate_observation_statement(context, GEMINI_API_KEY)
        pyperclip.copy(observation_statement)
        print("Observation Statement generated and copied to clipboard.")
        print(observation_statement)
        input("\nPress Enter to generate and copy the Investigation Report...")

        # --- Stage 3: Investigation Report ---
        print("\n--- Stage 3: Generating Investigation Report ---")
        report_lines = []
        report_lines.append("***Investigation Report***\n")
        report_lines.append("**User Information:**")
        report_lines.append(f"> Username: `{context['user_name']}`")
        report_lines.append(f"> Domain: `{context['user_domain']}`")

        # --- Execution Chain (condensed, non-redundant) ---
        chain = build_execution_chain(context, data)
        report_lines.extend(format_execution_chain(chain))

        # --- Process Info Section ---
        if context['proc_name'] != "N/A" or context['proc_path'] != "N/A":
            report_lines.append("\n**Process Information:**")
            report_lines.append(f"> Name: `{context['proc_name']}`")
            report_lines.append(f"> Path: `{context['proc_path']}`")
            if context['proc_cmd'] != "N/A":
                report_lines.append(f"> Command Line: `{context['proc_cmd']}`")
            if context['unique_arg_filename'] != "N/A" and context['proc_name'] == 'explorer.exe':
                report_lines.append(f"> Extracted Target Argument: `{context['unique_arg_filename']}`")
            if context['proc_hash_sha256'] != "N/A":
                report_lines.append(f">> SHA256: `{context['proc_hash_sha256']}`")
            if context['proc_hash_md5'] != "N/A":
                report_lines.append(f">> MD5: `{context['proc_hash_md5']}`")
            if context.get('proc_vt_details'):
                vt_info = context['proc_vt_details']
                report_lines.append(f">>> {vt_info.get('summary', 'VT Info Unavailable')}")
                if vt_info.get('attributes') is not None and not vt_info.get('error', True):
                    sig_status = get_signature_status_string(vt_info.get('signature_info'))
                    report_lines.append(f">>> Signature Status: `{sig_status}`")

        if context.get('npm_activity'):
            report_lines.append("\n**NPM Activity Details:**")
            for entry in context['npm_activity']:
                report_lines.append(f"> {entry['label']}: `{entry['name']}`")
                if entry.get('summary'):
                    report_lines.append(f">> Summary: {entry['summary']}")
                if entry.get('command_line'):
                    report_lines.append(f">> Command Line: `{entry['command_line']}`")
                if entry.get('args'):
                    arg_values = entry['args'][:10]
                    arg_line = ", ".join(arg_values)
                    if len(entry['args']) > 10:
                        arg_line += ", ..."
                    report_lines.append(f">> Args: `{arg_line}`")
                if entry.get('working_directory'):
                    report_lines.append(f">> Working Dir: `{entry['working_directory']}`")

        # --- Memory / Shellcode Call Stack ---
        try:
            reasons = []
            include_call_stack = False
            if is_memory_related(context, data):
                include_call_stack = True
                reasons.append("memory-related alert")
            if is_shellcode_related(context, data):
                include_call_stack = True
                reasons.append("shellcode-related alert")

            if include_call_stack:
                report_lines.append("\n**Call Stack Summary:**")

                summary_lines = extract_call_stack_summary(data)
                context_str = summarize_call_stack_context(summary_lines, data)

                ctx_parts = list(reasons)
                if context_str:
                    ctx_parts.append(context_str)

                if ctx_parts:
                    report_lines.append(f"> Context: {', '.join(ctx_parts)}")
                if summary_lines:
                    def _fmt_dlls(s: str) -> str:
                        pattern = r"(?i)([A-Za-z]:\\\\[^\\s!+]+?\\.dll|[A-Za-z0-9._-]+?\\.dll)"
                        return re.sub(pattern, lambda m: f"`{m.group(0)}`", s)

                    for line in summary_lines:
                        report_lines.append(f">> {_fmt_dlls(line)}")
                else:
                    report_lines.append("> No call stack summary provided by alert.")

                full_stack = extract_call_stack(data)
                if full_stack and full_stack != "N/A":
                    report_lines.append("\n**Call Stack:**")
                    for stack_line in full_stack.splitlines():
                        trimmed = stack_line.strip()
                        if trimmed:
                            report_lines.append(f">> {trimmed}")
                else:
                    report_lines.append("> No detailed call stack provided by alert.")
        except Exception:
            report_lines.append("\n**Call Stack Summary:**")
            report_lines.append("> No call stack summary provided by alert (parsing error).")

        # --- Parent Process Info Section ---
        if context['parent_proc_name'] != "N/A" or context['parent_proc_path'] != "N/A":
            report_lines.append("\n**Parent Process Information:**")
            report_lines.append(f"> Name: `{context['parent_proc_name']}`")
            report_lines.append(f"> Path: `{context['parent_proc_path']}`")
            if context['parent_proc_hash_sha256'] != "N/A":
                report_lines.append(f">> SHA256: `{context['parent_proc_hash_sha256']}`")
            if context['parent_proc_hash_md5'] != "N/A":
                report_lines.append(f">> MD5: `{context['parent_proc_hash_md5']}`")
            if context.get('parent_proc_vt_details'):
                vt_info = context['parent_proc_vt_details']
                report_lines.append(f">>> {vt_info.get('summary', 'VT Info Unavailable')}")
                if vt_info.get('attributes') is not None and not vt_info.get('error', True):
                    sig_status = get_signature_status_string(vt_info.get('signature_info'))
                    report_lines.append(f">>> Signature Status: `{sig_status}`")

        # --- File Info Section (only if distinct or adds hashes) ---
        is_different_file_name = context['file_name'] != "N/A" and context['file_name'] != context['proc_name']
        is_different_file_path = context['file_path'] != "N/A" and context['file_path'] != context['proc_path']
        provides_missing_hash = (context['file_hash_sha256'] != "N/A" and context['proc_hash_sha256'] == "N/A") or \
                                (context['file_hash_md5'] != "N/A" and context['proc_hash_md5'] == "N/A")

        if is_different_file_name or is_different_file_path or provides_missing_hash:
            if context['file_name'] != "N/A" or context['file_path'] != "N/A" or context['file_hash_sha256'] != "N/A" or context['file_hash_md5'] != "N/A":
                report_lines.append("\n**Associated File Information:**")
                if context['file_name'] != "N/A":
                    report_lines.append(f"> Name: `{context['file_name']}`")
                if context['file_path'] != "N/A":
                    report_lines.append(f"> Path: `{context['file_path']}`")
                if context['file_pe_company'] != "N/A":
                    report_lines.append(f"> Company: `{context['file_pe_company']}`")
                if context['file_pe_description'] != "N/A":
                    report_lines.append(f"> Description: `{context['file_pe_description']}`")
                if context['file_pe_product'] != "N/A":
                    report_lines.append(f"> Product: `{context['file_pe_product']}`")
                if context['file_hash_sha256'] != "N/A":
                    report_lines.append(f">> SHA256: `{context['file_hash_sha256']}`")
                if context['file_hash_md5'] != "N/A":
                    report_lines.append(f">> MD5: `{context['file_hash_md5']}`")
                if context.get('file_vt_details') and "skipped" not in context['file_vt_details'].get('summary', '').lower():
                    vt_info = context['file_vt_details']
                    report_lines.append(f">>> {vt_info.get('summary', 'VT Info Unavailable')}")
                    if vt_info.get('attributes') is not None and not vt_info.get('error', True):
                        sig_status = get_signature_status_string(vt_info.get('signature_info'))
                        report_lines.append(f">>> Signature Status: `{sig_status}`")

        # --- Finalize Report ---
        investigation_report_full = "\n".join(report_lines)
        pyperclip.copy(investigation_report_full)
        print("\nFull Investigation Report generated and copied to clipboard.")
        # print(investigation_report_full)

        # --- NEW: Stage 4: KQL Discover Query Generation ---
        print("\n--- Stage 4: KQL Discover Query Generation ---")
        input("Press Enter after pasting the Investigation Report to generate a KQL Discover query...")
        
        print("Generating KQL Discover query for alert context...")
        kql_query = generate_kql_discover_query(context, data)
        
        if kql_query:
            pyperclip.copy(kql_query)
            print("\nKQL Discover Query generated and copied to clipboard:")
            print("\n" + "="*80)
            print(kql_query)
            print("="*80)
        else:
            print("\nWarning: Unable to generate KQL query - insufficient data")


        print("\n--- Script Finished ---")

    except Exception as e:
        print(f"\nAn unexpected error occurred in main execution: {e}")
        traceback.print_exc()
        sys.exit(1)

# --- Run the main function ---
if __name__ == "__main__":
    main()
