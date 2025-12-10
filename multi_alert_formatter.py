# -*- coding: utf-8 -*-

"""
auto_format_alert_multi.py — Multi-Alert Consolidator (Test Version)

Changes (2025-10-09):
- Removed "Highlights" and "Context" output from execution chains.
- Each section (Chain / Process / Parent / File) now auto-hides if it has no
  meaningful alert-derived data (no names/paths/cmd/hashes/etc.).
"""

import json
import re
import pyperclip
import sys
import os
import requests
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv
import traceback

# ===================== Load Env =====================
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
GEMINI_API_KEY     = os.getenv('GEMINI_API_KEY')

# Optional Gemini usage (kept behind import guard)
USE_GEMINI = bool(GEMINI_API_KEY)
if USE_GEMINI:
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        GEMINI_MODEL_NAME = "gemini-2.5-flash"
    except Exception:
        USE_GEMINI = False

# ===================== Constants =====================
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files/{}"
CHATGPT5_LIMIT = 118000

# ===================== Helpers (from v2; trimmed/organized) =====================
def get_nested_value(data_dict, keys, default="N/A"):
    cur = data_dict
    try:
        for i, key in enumerate(keys):
            if isinstance(cur, dict):
                cur = cur.get(key)
            elif isinstance(cur, list):
                try:
                    idx = int(key)
                    cur = cur[idx] if 0 <= idx < len(cur) else None
                except (ValueError, TypeError):
                    cur = None if i < len(keys) - 1 else cur
            else:
                cur = None
            if cur is None:
                break
        if cur in [None, "", []]:
            return default
        return cur
    except Exception:
        return default

def format_timestamp(ts_string, default="N/A"):
    if not ts_string or ts_string == default:
        return default
    try:
        if isinstance(ts_string, str) and ts_string.endswith('Z'):
            ts_string = ts_string[:-1] + '+00:00'
        dt = datetime.fromisoformat(ts_string)
        return dt.strftime('%Y-%m-%d %H:%M:%S %Z%z').strip()
    except ValueError:
        return ts_string

def get_signature_status_string(sig_info_dict):
    if not isinstance(sig_info_dict, dict) or not sig_info_dict:
        return "Unsigned or Info Unavailable"
    raw = sig_info_dict.get('verified', None)
    if raw is None:
        return "Unsigned"
    v = str(raw).lower().strip()
    if "revoked" in v: return "Revoked"
    if "expired" in v: return "Expired"
    if "invalid" in v: return "Invalid"
    if "cannot verify" in v: return "Cannot Verify"
    if "file is not signed" in v or v == "not signed": return "Unsigned"
    if "unsigned" in v: return "Unsigned"
    if "signed and valid" in v or v in ("valid", "signed"): return "Valid"
    return str(raw).capitalize() if raw else "Status Unknown"

def _first_valid(vals, default="N/A"):
    for v in vals:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return default

def _join_args(args):
    if isinstance(args, list):
        try:
            return " ".join(str(a) for a in args if str(a).strip())
        except Exception:
            return " ".join([str(a) for a in args])
    return args if isinstance(args, str) else "N/A"

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

def _drive_letter(path):
    if isinstance(path, str) and len(path) >= 2 and path[1] == ":":
        return path[0].upper()
    return "?"

def _is_lolbin(name):
    if not name: return False
    return name.lower() in {
        "rundll32.exe","regsvr32.exe","mshta.exe","powershell.exe","cmd.exe","wscript.exe","cscript.exe",
        "wmic.exe","msiexec.exe","certutil.exe","bitsadmin.exe","installutil.exe","msbuild.exe",
        "forfiles.exe","schtasks.exe","curl.exe","ftp.exe","vssadmin.exe","bcdedit.exe","wbadmin.exe"
    }

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

def _get_pid_ppid(data):
    pid  = get_nested_value(data, ['process','pid'], default="N/A")
    ppid = get_nested_value(data, ['process','parent','pid'], default="N/A")
    return pid, ppid

def _get_start_times(data):
    child_start  = format_timestamp(get_nested_value(data, ['process','start'], default="N/A"))
    parent_start = format_timestamp(get_nested_value(data, ['process','parent','start'], default="N/A"))
    return child_start, parent_start

# ===================== VT (with cache) =====================
_vt_cache = {}  # hash -> vt_details dict (or None)

def _vt_lookup(hash_value):
    if not hash_value or hash_value == "N/A":
        return {
            'summary': "No Hash Value Provided",
            'attributes': None,
            'signature_info': None,
            'error': False
        }
    if hash_value in _vt_cache:
        return _vt_cache[hash_value]

    if not VIRUSTOTAL_API_KEY:
        res = {'summary': "VT Skipped: No API Key", 'attributes': None, 'signature_info': None, 'error': False}
        _vt_cache[hash_value] = res
        return res

    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
    url = VIRUSTOTAL_API_URL.format(hash_value)
    vt_link = f"https://www.virustotal.com/gui/file/{hash_value}"

    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 429:
            print("   VT rate limit hit, waiting 5s...")
            time.sleep(5)
            r = requests.get(url, headers=headers, timeout=15)

        if r.status_code == 200:
            raw = r.json()
            attrs = raw.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            summary = f"VT Found: M:{stats.get('malicious',0)} S:{stats.get('suspicious',0)} H:{stats.get('harmless',0)} U:{stats.get('undetected',0)}"
            meaningful = attrs.get("meaningful_name", "N/A")
            if meaningful != "N/A":
                summary += f" | Name: {meaningful}"
            summary += f" | [VirusTotal]({vt_link})"
            res = {'summary': summary, 'attributes': attrs, 'signature_info': attrs.get('signature_info'), 'error': False}
        elif r.status_code == 404:
            res = {'summary': f"VT Not Found | [Link:]({vt_link})", 'attributes': None, 'signature_info': None, 'error': False}
        elif r.status_code == 401:
            res = {'summary': "VT Error: Invalid API Key", 'attributes': None, 'signature_info': None, 'error': True}
        elif r.status_code == 429:
            res = {'summary': "VT Error: Rate limit exceeded after retry.", 'attributes': None, 'signature_info': None, 'error': True}
        else:
            res = {'summary': f"VT Error: Status {r.status_code} - {r.text[:100]}", 'attributes': None, 'signature_info': None, 'error': True}
    except requests.exceptions.Timeout:
        res = {'summary': "VT Network Error: Request timed out.", 'attributes': None, 'signature_info': None, 'error': True}
    except requests.exceptions.RequestException as e:
        res = {'summary': f"VT Network Error: {e}", 'attributes': None, 'signature_info': None, 'error': True}
    except Exception as e:
        res = {'summary': f"VT Parsing/Other Error: {e}", 'attributes': None, 'signature_info': None, 'error': True}

    _vt_cache[hash_value] = res
    return res

# ===================== Chain Builder (condensed, high-signal) =====================
def build_execution_chain(context, data):
    parent_name = _first_valid([
        get_nested_value(data, ['process','parent','name']),
        context.get('parent_proc_name','N/A')
    ])
    parent_path = _first_valid([
        get_nested_value(data, ['process','parent','executable']),
        context.get('parent_proc_path','N/A')
    ])
    parent_cmd = _first_valid([
        _join_args(get_nested_value(data, ['process','parent','args'], default=[])),
        get_nested_value(data, ['process','parent','command_line'])
    ])

    proc_name = _first_valid([
        context.get('proc_name','N/A'),
        get_nested_value(data, ['Target','process','name'])
    ])
    proc_path = _first_valid([
        context.get('proc_path','N/A'),
        get_nested_value(data, ['process','executable'])
    ])
    proc_cmd = _first_valid([
        context.get('proc_cmd','N/A'),
        get_nested_value(data, ['process','command_line'])
    ])

    file_name = context.get('file_name','N/A')
    file_path = context.get('file_path','N/A')
    add_file_node = (file_name not in ("N/A", proc_name)) or (file_path not in ("N/A", proc_path))

    mp_feature = _first_valid([
        get_nested_value(data, ['Memory_protection','feature']),
        get_nested_value(data, ['Memory_protection.feature'])
    ], default="")
    mp_self_injection = bool(get_nested_value(data, ['Memory_protection','self_injection'], default=False))
    relation_note = None
    if isinstance(mp_feature, str) and mp_feature.lower() == "shellcode_thread":
        relation_note = "self-injection denied" if mp_self_injection else "remote injection denied"

    parent_zone = _zone_from_path(parent_path)
    proc_zone   = _zone_from_path(proc_path)

    parent_sig = None
    if isinstance(context.get('parent_proc_vt_details'), dict):
        parent_sig = get_signature_status_string(context['parent_proc_vt_details'].get('signature_info'))

    proc_sig = None
    if isinstance(context.get('proc_vt_details'), dict):
        proc_sig = get_signature_status_string(context['proc_vt_details'].get('signature_info'))

    pid, ppid = _get_pid_ppid(data)
    child_start, parent_start = _get_start_times(data)

    f_ext = _file_ext(file_name or file_path)
    file_zone = _zone_from_path(file_path) if file_path != "N/A" else "Unknown"

    # Keep computing highlights internally if you want later, but they won't be printed.
    highlights = []
    if _suspicious_parent_child(parent_name, proc_name):
        highlights.append(f"Unusual parent→child: `{parent_name}` → `{proc_name}`")
    if _is_lolbin(proc_name):
        highlights.append(f"LOLBIN child: `{proc_name}`")
    if parent_zone in {"System32","Program Files","Windows"} and proc_zone in {"User Profile","Temp","Downloads","Other"}:
        highlights.append(f"Trust-zone hop: `{parent_zone}` → `{proc_zone}`")
    if _has_suspicious_flags(proc_cmd):
        highlights.append("Suspicious command-line flags observed")
    if relation_note:
        highlights.append(f"Memory protection: {relation_note}")
    if add_file_node and (file_zone in {"Temp","Downloads","User Profile","UNC/Network"} or _suspicious_file_ext(f_ext)):
        tag = f", .{f_ext}" if f_ext else ""
        highlights.append(f"Target file location: `{file_zone}`{tag}")

    chain_str = ""
    if parent_name != "N/A" and proc_name != "N/A":
        chain_str = f"`{parent_name}` ➜ `{proc_name}`"
    elif proc_name != "N/A":
        chain_str = f"`{proc_name}`"
    if add_file_node and file_name != "N/A":
        chain_str += f" ➜ `{file_name}`"

    return {
        "summary": chain_str or "N/A",
        "parent": {"name": parent_name, "path": parent_path, "cmd": parent_cmd, "zone": parent_zone, "sig": parent_sig},
        "process": {"name": proc_name, "path": proc_path, "cmd": proc_cmd, "zone": proc_zone, "sig": proc_sig},
        "file": {"name": file_name, "path": file_path, "zone": file_zone, "ext": f_ext} if add_file_node else None,
        "pids": {"parent_pid": ppid, "child_pid": pid},
        "times": {"parent_start": parent_start, "child_start": child_start},
        "highlights": highlights[:6]
    }

def format_execution_chain(chain, count=1, hosts=None):
    """Only prints the chain line + Seen In / Hosts. Hides entirely if no chain summary."""
    hosts = sorted(set(hosts or []))
    if not chain.get("summary") or chain["summary"] == "N/A":
        return []  # hide empty chain sections

    lines = []
    lines.append("\n**Process / File Execution Chain:**")
    lines.append("> Chain:")
    lines.append(f">> {chain['summary']}")
    lines.append(f">> Seen In: `{count}` alert(s)")
    # Only list hosts when there are multiple to avoid repetition
    if hosts and len(hosts) > 1:
        lines.append(f">> Hosts: {', '.join(f'`{h}`' for h in hosts)}")
    lines.append("")
    return lines

# ===================== Context Extraction (single alert) =====================
def extract_context(data):
    ctx = {}
    # Core
    ctx['rule_name'] = get_nested_value(data, ['kibana.alert.rule.name'], default=get_nested_value(data, ['rule','name']))
    ctx['reason']    = get_nested_value(data, ['kibana.alert.reason'], default="N/A")
    # User
    ctx['user_name']   = get_nested_value(data, ['user','name'], default=get_nested_value(data, ['endgame','user_name'], default=get_nested_value(data, ['winlog','user','name'])))
    ctx['user_domain'] = get_nested_value(data, ['user','domain'], default=get_nested_value(data, ['endgame','user_domain'], default=get_nested_value(data, ['winlog','user','domain'])))
    # Host
    # Some data sources use host.hostname while others use host.name (and similarly for observer/agent)
    ctx['hostname'] = _first_valid([
        get_nested_value(data, ['host','hostname']),
        get_nested_value(data, ['host','name']),
        get_nested_value(data, ['observer','hostname']),
        get_nested_value(data, ['observer','name']),
        get_nested_value(data, ['agent','hostname']),
        get_nested_value(data, ['agent','name']),
    ], default="N/A")
    ctx['host_os']  = get_nested_value(data, ['host','os','full'], default=get_nested_value(data, ['observer','os','full'], default=get_nested_value(data, ['agent','os','full'])))
    # Process
    ctx['proc_name'] = get_nested_value(data, ['process','name'])
    ctx['proc_path'] = get_nested_value(data, ['process','executable'])
    ctx['proc_cmd']  = get_nested_value(data, ['process','command_line'])
    p_sha256 = get_nested_value(data, ['process','hash','sha256'])
    p_sha1   = get_nested_value(data, ['process','hash','sha1'])
    p_md5    = get_nested_value(data, ['process','hash','md5'])
    ctx['proc_hash_sha256'] = p_sha256
    ctx['proc_hash_md5']    = p_md5
    p_hash = p_sha256 if p_sha256 != "N/A" else (p_sha1 if p_sha1 != "N/A" else p_md5)
    ctx['proc_vt_details'] = _vt_lookup(p_hash)

    # Parent
    ctx['parent_proc_name'] = get_nested_value(data, ['process','parent','name'])
    ctx['parent_proc_path'] = get_nested_value(data, ['process','parent','executable'])
    pp_sha256 = get_nested_value(data, ['process','parent','hash','sha256'])
    pp_sha1   = get_nested_value(data, ['process','parent','hash','sha1'])
    pp_md5    = get_nested_value(data, ['process','parent','hash','md5'])
    ctx['parent_proc_hash_sha256'] = pp_sha256
    ctx['parent_proc_hash_md5']    = pp_md5
    pp_hash = pp_sha256 if pp_sha256 != "N/A" else (pp_sha1 if pp_sha1 != "N/A" else pp_md5)
    ctx['parent_proc_vt_details'] = _vt_lookup(pp_hash)

    # File
    ctx['file_name'] = get_nested_value(data, ['file','name'])
    ctx['file_path'] = get_nested_value(data, ['file','path'])
    ctx['file_pe_company'] = get_nested_value(data, ['file','pe','company'], default="N/A")
    ctx['file_pe_description'] = get_nested_value(data, ['file','pe','description'], default="N/A")
    ctx['file_pe_product'] = get_nested_value(data, ['file','pe','product'], default="N/A")
    f_sha256 = get_nested_value(data, ['file','hash','sha256'])
    f_sha1   = get_nested_value(data, ['file','hash','sha1'])
    f_md5    = get_nested_value(data, ['file','hash','md5'])
    ctx['file_hash_sha256'] = f_sha256
    ctx['file_hash_md5']    = f_md5
    f_hash = f_sha256 if f_sha256 != "N/A" else (f_sha1 if f_sha1 != "N/A" else f_md5)

    # Skip file VT if it's the same as process hash or missing
    if f_hash != "N/A" and f_hash != p_hash:
        ctx['file_vt_details'] = _vt_lookup(f_hash)
    else:
        ctx['file_vt_details'] = {'summary': 'VT Skipped (Same as Process or No Hash)', 'attributes': None, 'signature_info': None, 'error': False}

    # Rule-specific arg extraction (Office -> explorer /select,)
    ctx['unique_arg_filename'] = "N/A"
    if ctx['rule_name'] == "Suspicious MS Office Child Process" and ctx['proc_name'] == 'explorer.exe':
        proc_args_list = get_nested_value(data, ['process','args'], default=[])
        cmd_line_str   = get_nested_value(data, ['process','command_line'], default="N/A")
        target_arg = None
        if isinstance(proc_args_list, list):
            for arg in proc_args_list:
                if isinstance(arg, str) and arg.lower().startswith("/select,"):
                    target_arg = arg; break
        elif cmd_line_str != "N/A" and "/select," in cmd_line_str.lower():
            parts = cmd_line_str.split()
            for i, part in enumerate(parts):
                if part.lower() == "/select," and i + 1 < len(parts):
                    target_arg = "/select," + parts[i+1]; break
                elif part.lower().startswith("/select,"):
                    target_arg = part; break
        if target_arg:
            full_path = target_arg[len("/select,"):].strip().strip('"')
            if full_path:
                ctx['unique_arg_filename'] = os.path.basename(full_path)

    return ctx

# ===================== Identity Keys for Deduping =====================
def _proc_key(ctx):
    return (
        ctx.get('proc_name','N/A').lower(),
        (ctx.get('proc_path','N/A') or '').lower(),
        (ctx.get('proc_cmd','N/A') or '').lower(),
        ctx.get('proc_hash_sha256','N/A') or ctx.get('proc_hash_md5','N/A') or "N/A",
    )

def _parent_key(ctx):
    return (
        ctx.get('parent_proc_name','N/A').lower(),
        (ctx.get('parent_proc_path','N/A') or '').lower(),
        ctx.get('parent_proc_hash_sha256','N/A') or ctx.get('parent_proc_hash_md5','N/A') or "N/A",
    )

def _file_key(ctx):
    return (
        ctx.get('file_name','N/A').lower(),
        (ctx.get('file_path','N/A') or '').lower(),
        ctx.get('file_hash_sha256','N/A') or ctx.get('file_hash_md5','N/A') or "N/A",
    )

def _chain_key(chain):
    fn = chain['file']['name'].lower() if chain.get('file') else ''
    return (
        (chain['parent']['name'] or 'N/A').lower(),
        (chain['process']['name'] or 'N/A').lower(),
        fn
    )

# ===================== Observation (combined) =====================
def _classify_rule(rule_name: str):
    """Return a coarse category for an alert rule name."""
    if not rule_name:
        return "other"
    n = rule_name.lower()
    if any(k in n for k in ["credential", "browser credentials", "lsass", "mimikatz", "password"]):
        return "credential"
    if ("office" in n or any(k in n for k in ["winword", "excel", "powerpoint", "powerpnt"])) and "child" in n:
        return "office_child"
    if any(k in n for k in ["injection", "shellcode", "memory protection", "remote thread", "reflective"]):
        return "injection"
    if any(k in n for k in ["lolbin", "living off the land", "rundll32", "regsvr32", "mshta", "certutil", "wscript", "cscript", "powershell"]):
        return "lolbin"
    if any(k in n for k in ["persistence", "autorun", "run key", "schtasks", "startup", "scheduled task"]):
        return "persistence"
    if any(k in n for k in ["lateral", "psexec", "wmic", "winrm", "remote execution", "pass-the-hash"]):
        return "lateral"
    if any(k in n for k in ["exfil", "c2", "command and control", "beacon", "dns tunneling", "data transfer"]):
        return "c2"
    return "other"

def _choose_primary_rule(rule_names):
    """Pick a primary rule and its category using simple priority scoring."""
    if not rule_names:
        return ("Unknown Rule", "other")
    priority = {
        "credential": 90,
        "office_child": 80,
        "injection": 70,
        "lolbin": 60,
        "persistence": 50,
        "lateral": 40,
        "c2": 30,
        "other": 10,
    }
    best = None
    for rn in sorted(rule_names):  # stable deterministic
        cat = _classify_rule(rn)
        score = priority.get(cat, 0)
        if best is None or score > best[0]:
            best = (score, rn, cat)
    return (best[1], best[2]) if best else (sorted(rule_names)[0], "other")

def _tailored_observation_sentence(rule_names, users, hosts, proc_names, file_names):
    def bt(items):
        return ", ".join(f"`{x}`" for x in sorted(items)) if items else "`N/A`"

    primary_rule, category = _choose_primary_rule(rule_names)

    # Prefer subject by category
    if category == "office_child":
        subject = bt(proc_names) if proc_names else bt(file_names)
    else:
        subject = bt(file_names) if file_names else bt(proc_names)

    u = bt(users)
    h = bt(hosts)

    if category == "credential":
        return (
            f"Credential access behavior was detected under `{primary_rule}` involving {subject} "
            f"across {u} on {h}."
        )
    if category == "office_child":
        return (
            f"An Office application spawned a suspicious child process under `{primary_rule}`: {subject} "
            f"across {u} on {h}."
        )
    if category == "injection":
        return (
            f"Possible code injection was observed under `{primary_rule}` involving {subject} "
            f"across {u} on {h}."
        )
    if category == "lolbin":
        return (
            f"Potential LOLBIN usage was detected under `{primary_rule}` with {subject} "
            f"across {u} on {h}."
        )
    if category == "persistence":
        return (
            f"Persistence-related activity was noted under `{primary_rule}` involving {subject} "
            f"across {u} on {h}."
        )
    if category == "lateral":
        return (
            f"Lateral movement behavior was detected under `{primary_rule}` involving {subject} "
            f"across {u} on {h}."
        )
    if category == "c2":
        return (
            f"Potential C2 or data exfiltration activity was observed under `{primary_rule}` involving {subject} "
            f"across {u} on {h}."
        )
    # Default
    return (
        f"Activity associated with `{primary_rule}` involving {subject} across {u} on {h}."
    )
def generate_combined_observation(rule_names, users, hosts, proc_names, parent_names, file_names):
    # Tailored local sentence (used when Gemini is off or as fallback)
    local_sentence = _tailored_observation_sentence(rule_names, users, hosts, proc_names, file_names)

    if not USE_GEMINI:
        return f"***Observation Statement***\n\n{local_sentence}\n(Combined observation generated locally)"

    try:
        primary_rule, category = _choose_primary_rule(rule_names)
        
        # Build context counts to emphasize multi-alert nature
        num_rules = len(rule_names) if rule_names else 0
        num_users = len(users) if users else 0
        num_hosts = len(hosts) if hosts else 0
        num_procs = len(proc_names) if proc_names else 0
        num_parents = len(parent_names) if parent_names else 0
        num_files = len(file_names) if file_names else 0
        
        prompt = (
            "Generate ONE concise, natural-sounding sentence summarizing these security alerts. "
            "Focus on the key security action/behavior, the actors (users/hosts), and the artifacts (files/processes). "
            "Use natural language and enclose specific entity values in backticks. "
            "Do NOT use labels like 'User:', 'Host:', 'Process:', 'File:' before backticked values. "
            "If multiple alerts share the same user/host/file, mention them once. If they differ, include all distinct values naturally. "
            "Prefer describing the parent-child process relationship when relevant (e.g., 'spawned by' or 'launched by'). "
            "Return only the observation sentence.\n\n"
            f"Alert Summary:\n"
            f"- Rule: {primary_rule}\n"
            f"- Users: {', '.join(sorted(users)) if users else 'N/A'}\n"
            f"- Hosts: {', '.join(sorted(hosts)) if hosts else 'N/A'}\n"
            f"- Child processes: {', '.join(sorted(proc_names)) if proc_names else 'N/A'}\n"
            f"- Parent processes: {', '.join(sorted(parent_names)) if parent_names else 'N/A'}\n"
            f"- Files: {', '.join(sorted(file_names)) if file_names else 'N/A'}\n"
        )
        model = genai.GenerativeModel(GEMINI_MODEL_NAME)
        conf = genai.types.GenerationConfig(temperature=0.3, max_output_tokens=500)
        safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ]
        resp = model.generate_content(prompt, generation_config=conf, safety_settings=safety_settings)
        
        text = ""
        try:
            # Check candidates existence first
            if not resp.candidates:
                return f"***Observation Statement***\n\n{local_sentence}\n(Combined observation fallback: No candidates returned)"
            
            cand = resp.candidates[0]
            # If we have parts, get text
            if cand.content and cand.content.parts:
                text = resp.text
            else:
                # No parts - check finish reason
                reason = getattr(cand.finish_reason, 'name', str(cand.finish_reason))
                return f"***Observation Statement***\n\n{local_sentence}\n(Combined observation fallback: No content parts. Finish Reason: {reason})"
        except Exception as e:
            return f"***Observation Statement***\n\n{local_sentence}\n(Combined observation fallback: Error extracting text - {str(e)})"
            
        text = (text or "").strip()
        if not text:
             return f"***Observation Statement***\n\n{local_sentence}"
        
        # Detect incomplete/truncated responses (ends with open backtick, incomplete sentence, etc.)
        backtick_count = text.count('`')
        if backtick_count % 2 != 0:
            # Odd number of backticks means unclosed backtick - truncated response, use local fallback
            return f"***Observation Statement***\n\n{local_sentence}"
        
        # Check if response ends abruptly (ends with words that indicate truncation, not normal punctuation)
        # Only check for truly incomplete markers (avoid false positives from normal sentence endings)
        if text.rstrip().endswith((' where', ' and', ' involving', ' with')) or (text.endswith(',') and not text.endswith('`,')):
            # Likely truncated, use local fallback
            return f"***Observation Statement***\n\n{local_sentence}"
             
        # Clean newlines instead of rejecting
        if "\n" in text:
            text = text.replace("\n", " ").strip()
            
        return f"***Observation Statement***\n\n{text}"
    except Exception as e:
        return f"***Observation Statement***\n\n{local_sentence}\n(Combined observation API error: {e})"

# ===================== Report Builders (auto-hide when empty) =====================
def _format_proc_block(ctx, seen_hosts=None, count=1):
    info_lines = []

    name = ctx.get('proc_name','N/A')
    path = ctx.get('proc_path','N/A')
    cmd  = ctx.get('proc_cmd','N/A')
    sha256 = ctx.get('proc_hash_sha256','N/A')
    md5    = ctx.get('proc_hash_md5','N/A')
    vt     = ctx.get('proc_vt_details')

    if name != "N/A":   info_lines.append(f"> Name: `{name}`")
    if path != "N/A":   info_lines.append(f"> Path: `{path}`")
    if cmd  != "N/A":   info_lines.append(f"> Command Line: `{cmd}`")
    if ctx.get('unique_arg_filename','N/A') != "N/A" and name == 'explorer.exe':
        info_lines.append(f"> Extracted Target Argument: `{ctx['unique_arg_filename']}`")
    if sha256 != "N/A": info_lines.append(f">> SHA256: `{sha256}`")
    if md5    != "N/A": info_lines.append(f">> MD5: `{md5}`")
    if vt and (vt.get('attributes') is not None or "VT " in vt.get('summary','')):
        info_lines.append(f">>> {vt.get('summary','VT Info Unavailable')}")
        if vt.get('attributes') is not None and not vt.get('error', True):
            sig = get_signature_status_string(vt.get('signature_info'))
            info_lines.append(f">>> Signature Status: `{sig}`")

    # If we didn't collect any meaningful info, hide block
    if not info_lines:
        return []

    # If we do have content, append counts/hosts
    info_lines.append(f">>> Seen In: `{count}` alert(s)")
    # Only include Hosts line if there are multiple distinct hosts
    if seen_hosts and len(set(seen_hosts)) > 1:
        info_lines.append(f">>> Hosts: {', '.join(f'`{h}`' for h in sorted(set(seen_hosts)))}")

    return ["\n**Process Information:**", *info_lines]

def _format_parent_block(ctx, seen_hosts=None, count=1):
    info_lines = []

    name = ctx.get('parent_proc_name','N/A')
    path = ctx.get('parent_proc_path','N/A')
    sha256 = ctx.get('parent_proc_hash_sha256','N/A')
    md5    = ctx.get('parent_proc_hash_md5','N/A')
    vt     = ctx.get('parent_proc_vt_details')

    if name != "N/A":   info_lines.append(f"> Name: `{name}`")
    if path != "N/A":   info_lines.append(f"> Path: `{path}`")
    if sha256 != "N/A": info_lines.append(f">> SHA256: `{sha256}`")
    if md5    != "N/A": info_lines.append(f">> MD5: `{md5}`")
    if vt and (vt.get('attributes') is not None or "VT " in vt.get('summary','')):
        info_lines.append(f">>> {vt.get('summary','VT Info Unavailable')}")
        if vt.get('attributes') is not None and not vt.get('error', True):
            sig = get_signature_status_string(vt.get('signature_info'))
            info_lines.append(f">>> Signature Status: `{sig}`")

    if not info_lines:
        return []

    info_lines.append(f">>> Seen In: `{count}` alert(s)")
    if seen_hosts and len(set(seen_hosts)) > 1:
        info_lines.append(f">>> Hosts: {', '.join(f'`{h}`' for h in sorted(set(seen_hosts)))}")

    return ["\n**Parent Process Information:**", *info_lines]

def _format_file_block(ctx, seen_hosts=None, count=1):
    info_lines = []

    name = ctx.get('file_name','N/A')
    path = ctx.get('file_path','N/A')
    sha256 = ctx.get('file_hash_sha256','N/A')
    md5    = ctx.get('file_hash_md5','N/A')
    vt     = ctx.get('file_vt_details')

    if name != "N/A":   info_lines.append(f"> Name: `{name}`")
    if path != "N/A":   info_lines.append(f"> Path: `{path}`")
    if ctx.get('file_pe_company', 'N/A') != "N/A":
        info_lines.append(f"> Company: `{ctx['file_pe_company']}`")
    if ctx.get('file_pe_description', 'N/A') != "N/A":
        info_lines.append(f"> Description: `{ctx['file_pe_description']}`")
    if ctx.get('file_pe_product', 'N/A') != "N/A":
        info_lines.append(f"> Product: `{ctx['file_pe_product']}`")
    if sha256 != "N/A": info_lines.append(f">> SHA256: `{sha256}`")
    if md5    != "N/A": info_lines.append(f">> MD5: `{md5}`")
    if vt and vt.get('attributes') is not None and not vt.get('error', True):
        info_lines.append(f">>> {vt.get('summary','VT Info Unavailable')}")
        sig = get_signature_status_string(vt.get('signature_info'))
        info_lines.append(f">>> Signature Status: `{sig}`")

    if not info_lines:
        return []

    info_lines.append(f">>> Seen In: `{count}` alert(s)")
    if seen_hosts and len(set(seen_hosts)) > 1:
        info_lines.append(f">>> Hosts: {', '.join(f'`{h}`' for h in sorted(set(seen_hosts)))}")

    return ["\n**Associated File Information:**", *info_lines]

# ===================== Discover KQL (multi-alert) =====================
def _extract_event_center_timestamp(data):
    """Pick the best event time to center the window for a single alert.
    Priority: kibana.alert.original_time > event.ingested > Events[0]['@timestamp'].
    Returns a datetime (UTC) or None.
    """
    ts = get_nested_value(data, ['kibana','alert','original_time'], default=None)
    if not ts:
        ts = get_nested_value(data, ['event','ingested'], default=None)
    if not ts:
        events_list = get_nested_value(data, ['Events'], default=None)
        if isinstance(events_list, list) and events_list:
            ts = get_nested_value(events_list[0], ['@timestamp'], default=None)
    if not ts or not isinstance(ts, str):
        return None
    try:
        if ts.endswith('Z'):
            ts = ts[:-1] + '+00:00'
        return datetime.fromisoformat(ts)
    except Exception:
        return None

def generate_kql_discover_query_multi(alerts):
    """Generate a consolidated Discover KQL for multiple alerts.
    - Time window: from min(center-5m) to max(center+5m) across alerts.
    - Field to search: event.ingested (searchable, indexed timestamp field).
    - Host filter: if multiple hosts, OR them; if one, a single equality; if none, omit.
    - Process relationship: OR of exact parent->child relationships (with PIDs when available).
    """
    if not alerts:
        return ""

    # Collect time bounds
    starts, ends = [], []
    rel_clauses = set()
    hosts = set()

    for ctx, data in alerts:
        # Hosts
        h = ctx.get('hostname') or get_nested_value(data, ['host','hostname'], default=None) or get_nested_value(data, ['host','name'], default=None)
        if isinstance(h, str) and h.strip():
            hosts.add(h.strip())

        # Time
        center = _extract_event_center_timestamp(data)
        if center is not None:
            starts.append(center - timedelta(minutes=5))
            ends.append(center + timedelta(minutes=5))

        # Relationship
        child = (ctx.get('proc_name') or get_nested_value(data, ['process','name'], default="N/A")) or "N/A"
        parent = (ctx.get('parent_proc_name') or get_nested_value(data, ['process','parent','name'], default="N/A")) or "N/A"
        cpid = get_nested_value(data, ['process','pid'], default="N/A")
        ppid = get_nested_value(data, ['process','parent','pid'], default="N/A")

        def _coerce_int(v):
            try:
                if v is None or v == "N/A":
                    return None
                if isinstance(v, (int, float)):
                    return int(v)
                s = str(v)
                return int(s) if s.isdigit() else None
            except Exception:
                return None

        cpid = _coerce_int(cpid)
        ppid = _coerce_int(ppid)
        child_l = (child or "").lower()
        parent_l = (parent or "").lower()

        parts = []
        if child_l and child_l != "n/a":
            parts.append(f'process.name: "{child}"')
            if cpid is not None:
                parts.append(f'process.pid: {cpid}')
        if parent_l and parent_l != "n/a":
            parts.append(f'process.parent.name: "{parent}"')
            if ppid is not None:
                parts.append(f'process.parent.pid: {ppid}')
        if parts:
            rel_clauses.add("(" + " AND ".join(parts) + ")")

    # Time filter
    time_clause = ""
    if starts and ends:
        start = min(starts)
        end = max(ends)
        start_s = start.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        end_s = end.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
        time_clause = f'(@timestamp >= "{start_s}" AND @timestamp <= "{end_s}")'

    # Host filter
    host_clause = ""
    if len(hosts) == 1:
        only = next(iter(hosts))
        host_clause = f'(host.name: "{only}")'
    elif len(hosts) > 1:
        ors = " OR ".join(f'host.name: "{h}"' for h in sorted(hosts))
        host_clause = f'({ors})'

    # Relationship filter
    rel_clause = ""
    if rel_clauses:
        rel_clause = "(" + " OR ".join(sorted(rel_clauses)) + ")"

    # Join all
    filters = [c for c in [host_clause, time_clause, rel_clause] if c]
    return " AND ".join(filters)

# ===================== Main =====================
def main():
    if not VIRUSTOTAL_API_KEY:
        print("Warning: VIRUSTOTAL_API_KEY not set — VirusTotal checks will be skipped or limited to 'No API Key'.")
    if not USE_GEMINI:
        print("Info: GEMINI_API_KEY not set/usable — using a local combined observation sentence.")

    all_alerts = []  # list of (context, data)
    print("\n--- Multi-Alert Ingestion ---")
    print("Instructions:")
    print("  1) Copy ONE alert batch to clipboard (object, list, or JSONL).")
    print("  2) Press ENTER to ingest it, or type 'done' then ENTER to finish.\n")

    try:
        while True:
            user = input("Press ENTER to ingest clipboard (or type 'done' to finish): ").strip().lower()
            if user in {"done","d","q","quit","exit"}:
                break
            payload = pyperclip.paste()
            if not payload:
                print("  - Clipboard is empty. Try again.")
                continue
            records = _parse_clipboard_payload(payload)
            if not records:
                print("  - Clipboard did not contain valid JSON object/list/JSONL. Try again.")
                continue

            added = 0
            for obj in records:
                data = obj.get('_source', obj)
                ctx  = extract_context(data)
                all_alerts.append((ctx, data))
                added += 1
            print(f"  + Ingested {added} alert(s). Total so far: {len(all_alerts)}")

        if not all_alerts:
            print("\nNo alerts ingested. Exiting.")
            sys.exit(0)

        # ===================== Aggregate & Deduplicate =====================
        users  = set()
        hosts  = set()
        rules  = set()
        procs  = {}   # key -> {'ctx': reference, 'count': int, 'hosts': set()}
        parents= {}
        files  = {}
        chains = {}   # key -> {'sample': chain, 'count': int, 'hosts': set()}

        for ctx, data in all_alerts:
            if ctx.get('user_name'): users.add(ctx['user_name'])
            if ctx.get('hostname'):  hosts.add(ctx['hostname'])
            if ctx.get('rule_name'): rules.add(ctx['rule_name'])

            # Process
            pk = _proc_key(ctx)
            procs.setdefault(pk, {'ctx': ctx, 'count': 0, 'hosts': set()})
            procs[pk]['count'] += 1
            if ctx.get('hostname'): procs[pk]['hosts'].add(ctx['hostname'])

            # Parent
            par_k = _parent_key(ctx)
            parents.setdefault(par_k, {'ctx': ctx, 'count': 0, 'hosts': set()})
            parents[par_k]['count'] += 1
            if ctx.get('hostname'): parents[par_k]['hosts'].add(ctx['hostname'])

            # File
            file_k = _file_key(ctx)
            if any(file_k):
                files.setdefault(file_k, {'ctx': ctx, 'count': 0, 'hosts': set()})
                files[file_k]['count'] += 1
                if ctx.get('hostname'): files[file_k]['hosts'].add(ctx['hostname'])

            # Chain
            chain = build_execution_chain(ctx, data)
            ck = _chain_key(chain)
            if ck not in chains:
                chains[ck] = {'sample': chain, 'count': 0, 'hosts': set()}
            chains[ck]['count'] += 1
            if ctx.get('hostname'): chains[ck]['hosts'].add(ctx['hostname'])

        proc_names = {v['ctx'].get('proc_name','N/A') for v in procs.values() if v['ctx'].get('proc_name','N/A') != "N/A"}
        parent_names = {v['ctx'].get('parent_proc_name','N/A') for v in parents.values() if v['ctx'].get('parent_proc_name','N/A') != "N/A"}
        file_names = {v['ctx'].get('file_name','N/A') for v in files.values() if v['ctx'].get('file_name','N/A') != "N/A"}

        # ===================== Build Outputs =====================
        observation = generate_combined_observation(rules, users, hosts, proc_names, parent_names, file_names)

        report_lines = []
        report_lines.append("***Investigation Report***\n")

        # Users section (each user on its own line)
        report_lines.append("**Users:**")
        if users:
            for u in sorted(users):
                report_lines.append(f"> `{u}`")
        else:
            report_lines.append("> `N/A`")
        report_lines.append("")

        # Chains (each unique once; auto-hide inside formatter if empty)
        for ck, info in sorted(chains.items(), key=lambda x: (-x[1]['count'], x[0])):
            block = format_execution_chain(info['sample'], count=info['count'], hosts=info['hosts'])
            if block:
                report_lines.extend(block)

        # Processes (auto-hide if no fields)
        for pk, info in sorted(procs.items(), key=lambda x: (-x[1]['count'], x[0])):
            block = _format_proc_block(info['ctx'], seen_hosts=info['hosts'], count=info['count'])
            if block:
                report_lines.extend(block)

        # Parents (auto-hide if no fields)
        for par_k, info in sorted(parents.items(), key=lambda x: (-x[1]['count'], x[0])):
            block = _format_parent_block(info['ctx'], seen_hosts=info['hosts'], count=info['count'])
            if block:
                report_lines.extend(block)

        # Files (auto-hide if no fields)
        for fk, info in sorted(files.items(), key=lambda x: (-x[1]['count'], x[0])):
            block = _format_file_block(info['ctx'], seen_hosts=info['hosts'], count=info['count'])
            if block:
                report_lines.extend(block)

        # ===================== Two-Stage Clipboard Copy =====================
        observation_text = observation
        investigation_report_text = "\n".join(report_lines)

        # 1) Copy Observation Statement first
        pyperclip.copy(observation_text)
        print("\n--- Output ---")
        print(observation_text)
        print("\n(Observation Statement copied to clipboard.)")

        # 2) Wait for user confirmation, then copy Investigation Report
        try:
            input("Press ENTER to copy the Investigation Report to clipboard...")
        except EOFError:
            pass

        pyperclip.copy(investigation_report_text)
        print("(Investigation Report copied to clipboard.)")

        # 3) Generate combined Discover KQL and copy
        print("\n--- KQL Discover Query (Combined) ---")
        try:
            input("Press ENTER to generate a Discover KQL query for these alerts...")
        except EOFError:
            pass

        kql_query = generate_kql_discover_query_multi(all_alerts)
        if kql_query:
            pyperclip.copy(kql_query)
            print("KQL Discover Query generated and copied to clipboard:")
            print("\n" + "="*80)
            print(kql_query)
            print("="*80)
        else:
            print("Warning: Unable to generate KQL query - insufficient data")


    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        traceback.print_exc()
        sys.exit(1)

# ===================== Ingest (clipboard-driven) =====================
def _parse_clipboard_payload(payload):
    """Accepts single JSON object, list of objects, or JSONL text."""
    records = []
    try:
        obj = json.loads(payload)
        if isinstance(obj, dict):
            records.append(obj)
        elif isinstance(obj, list):
            for it in obj:
                if isinstance(it, dict):
                    records.append(it)
    except json.JSONDecodeError:
        # try JSONL
        for line in payload.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append(obj)
            except json.JSONDecodeError:
                continue
    return records

if __name__ == "__main__":
    main()
