
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
====================================================================
Project Name : Honeypot_Omaha (Unified Honeypot Analysis Pipeline)
Author       : Frank Ngoka Igbokwe
Created      : 2026
Copyright    : (c) 2026 Frank Ngoka Igbokwe
License      : Business Source License 1.1 (BSL-1.1)
====================================================================
"""
import csv
import glob
import json
import urllib.request
import sys
from collections import Counter, defaultdict
import subprocess
import platform
import os
import re
import getpass
import hashlib
import time
from datetime import datetime,timezone
# ====================================================================
# INTELLECTUAL PROPERTY SECURITY & OBSCURE MODULE
# ====================================================================
GUEST_TOKEN_FILE = ".honeypot_guest_token.json"
MASTER_PASSWORD_HASH = hashlib.sha256(b"Rain#2021!").hexdigest()
COWRIE_JSON_PATH = "/srv/cowrie/var/log/cowrie/cowrie.json"
COWRIE_LOG_PATH = "/srv/cowrie/var/log/cowrie/cowrie.log"
def generate_guest_token(duration_hours=24):
    """Admin utility to generate a time-bound guest access token for IP protection."""
    token_id = f"guest-{os.urandom(4).hex()}-{int(time.time())}"
    token_hash = hashlib.sha256(token_id.encode()).hexdigest()
    expires_at = time.time() + (duration_hours * 3600)
    
    token_data = {
        "token": token_id,
        "hash": token_hash,
        "expires_at": expires_at
    }
    
    with open(GUEST_TOKEN_FILE, 'w', encoding='utf-8') as f:
        json.dump(token_data, f)
         
    print(f"[+] Guest Token Generated Successfully!")
    print(f"    Passcode String : {token_id}")
    print(f"    Valid For       : {duration_hours} hours (Expires: {time.ctime(expires_at)})")
    print(f"    Note            : Share this string with guests. It protects your source code and master password.")
def verify_guest_token():
    """Prompts the user for the guest passcode string and verifies it against the active token file."""
    if not os.path.exists(GUEST_TOKEN_FILE):
        print("[!] No active guest token file found. Please ask the administrator to generate one.")
        return False
    
    try:
        with open(GUEST_TOKEN_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
             
        if time.time() > data.get("expires_at", 0):
            print("[!] Guest token has expired.")
            os.remove(GUEST_TOKEN_FILE)
            return False
             
        entered_passcode = input("Enter Guest Passcode String: ").strip()
        entered_hash = hashlib.sha256(entered_passcode.encode()).hexdigest()
        
        if entered_hash == data.get("hash") or entered_passcode == data.get("token"):
            return True
        else:
            print("[!] Invalid guest passcode string.")
            return False
             
    except Exception as e:
        print(f"[!] Error verifying guest token: {e}")
        return False
def authenticate_user():
    print("="*65)
    print("SECURE ACCESS: Honeypot_Omaha Intelligence Pipeline [IP Protected]")
    print("="*65)
    print("Options:")
    print("  [1] Enter Master Password (Full Admin Access)")
    print("  [2] Enter Guest Passcode (Restricted Time-Bound Access)")
    print("  [3] Generate Guest Passcode [Admin Utility]")
    
    choice = input("\nSelect authentication mode (1-3): ").strip()
    
    if choice == '3':
        admin_pw = getpass.getpass("Enter Master Password to generate guest token: ")
        if hashlib.sha256(admin_pw.encode()).hexdigest() == MASTER_PASSWORD_HASH:
            try:
                hrs = float(input("Enter validity duration in hours (e.g., 2 or 24): ").strip())
            except ValueError:
                hrs = 24.0
            generate_guest_token(hrs)
            sys.exit(0)
        else:
            print("[!] Incorrect master password. Cannot generate token.")
            sys.exit(1)
             
    elif choice == '2':
        if verify_guest_token():
            print("[+] Guest Passcode Verified. Granting Restricted Report Access...\n")
            return "guest"
        else:
            print("[!] Access Denied: Invalid or expired guest token.")
            sys.exit(1)
             
    # Option 1: Master Password
    attempts = 3
    while attempts > 0:
        entered_password = getpass.getpass("Enter Master Authorization Password: ")
        entered_hash = hashlib.sha256(entered_password.encode()).hexdigest()
         
        if entered_hash == MASTER_PASSWORD_HASH:
            print("[+] Master Access Granted. Initializing Pipeline...\n")
            return "master"
        else:
            attempts -= 1
            print(f"[!] Invalid Password. Attempts remaining: {attempts}")
             
    print("[!] Maximum authentication attempts exceeded. Terminating execution.")
    sys.exit(1)
# Try importing matplotlib for pie chart generation
try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
def format_short_time(ts):
    if not ts or ts == 'N/A':
        return 'N/A'
    try:
        return ts.split('.')[0].replace('T', ' ')
    except Exception:
        return ts
def get_threat_intel_mapping(endpoint_or_proto):
    item = endpoint_or_proto.upper()
    if 'CGI-BIN' in item or 'SH' in item:
        return {
            'cve': 'CVE-2014-6271 (Shellshock)',
            'score_val': 9.8,
            'score_str': 'CVSS 9.8 (Critical)',
            'mitre': 'T1059.004 (Command and Scripting Interpreter: Unix Shell)',
            'exploit': 'Shellshock Remote Code Execution',
            'intention': 'Arbitrary command execution and system compromise',
            'mitigation': 'Patch vulnerable Bash instances and use WAF rules'
        }
    elif 'TELNET' in item or 'SSH' in item or 'PORT 2222' in item or 'PORT 2223' in item:
        return {
            'cve': 'N/A (Credential Brute-Forcing / SSH Honeypot)',
            'score_val': 7.5,
            'score_str': 'CVSS 7.5 (High)',
            'mitre': 'T1110 (Brute Force)',
            'exploit': 'Default Credential / Dictionary Attack on SSH/Telnet',
            'intention': 'Gain unauthorized remote administrative access via port 2222/2223',
            'mitigation': 'Enforce strong key-based authentication, disable root login, and use fail2ban'
        }
    elif 'ENV' in item:
        return {
            'cve': 'CVE-2019-11043 (Information Disclosure)',
            'score_val': 8.6,
            'score_str': 'CVSS 8.6 (High)',
            'mitre': 'T1592 (Gather Victim Host Information)',
            'exploit': 'Sensitive Environment File Scraping',
            'intention': 'Harvest configuration secrets, database credentials, and API keys',
            'mitigation': 'Restrict public access to dotfiles and sensitive web root files'
        }
    elif 'FAVICON' in item:
        return {
            'cve': 'N/A (Reconnaissance)',
            'score_val': 3.1,
            'score_str': 'CVSS 3.1 (Low)',
            'mitre': 'T1595 (Active Scanning)',
            'exploit': 'Asset Fingerprinting',
            'intention': 'Identify framework type and software version',
            'mitigation': 'Standard footprint reduction / custom headers'
        }
    else:
        return {
            'cve': 'N/A (General Web Attack / Probing)',
            'score_val': 5.3,
            'score_str': 'CVSS 5.3 (Medium)',
            'mitre': 'T1190 (Exploit Public-Facing Application)',
            'exploit': 'HTTP Request Flooding / Web Probing',
            'intention': 'Probe application attack surface and web paths',
            'mitigation': 'Implement rate limiting and robust input validation'
        }
def get_ip_intel(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org"
        req = urllib.request.Request(url, headers={'User-Agent': 'Honeypot_Omaha_Analyzer'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get('status') == 'success':
                country = data.get('country', 'Unknown')
                org = data.get('org', data.get('ISP', 'Unknown'))
                return country, org
    except Exception:
        pass
    return 'Unknown', 'Unknown'
def generate_pie_charts(ip_counter, protocol_counter, username_counter, password_counter, target='both'):
    if not MATPLOTLIB_AVAILABLE:
        print("[!] Matplotlib is not installed. Skipping pie chart generation. (Run: pip install matplotlib)")
        return
    print("[*] Generating visual summary pie charts...")
    if target in ('ip', 'both'):
        top_10_chart_data = sorted(ip_counter.items(), key=lambda x: (-x[1], x[0]))[:10]
        if top_10_chart_data:
            ips, hits = zip(*top_10_chart_data)
            plt.figure(figsize=(9, 6))
            plt.pie(hits, labels=ips, autopct='%1.1f%%', startangle=140)
            plt.title('Honeypot_Omaha: Top 10 IP Talkers Distribution')
            plt.tight_layout()
            plt.savefig('phase2_top_ips_pie_chart.png')
            plt.close()
            print("[+] Saved Phase 2 Pie Chart as 'phase2_top_ips_pie_chart.png'")
    if target in ('cowrie', 'both'):
        fig, axes = plt.subplots(1, 3, figsize=(18, 6))
        
        proto_data = protocol_counter.most_common(10)
        if proto_data:
            p_labels, p_vals = zip(*proto_data)
            axes[0].pie(p_vals, labels=p_labels, autopct='%1.1f%%', startangle=140)
            axes[0].set_title('Top Cowrie Protocols')
        else:
            axes[0].text(0.5, 0.5, 'No Protocol Data', horizontalalignment='center', verticalalignment='center')
        user_data = username_counter.most_common(10)
        if user_data:
            u_labels, u_vals = zip(*user_data)
            u_labels_short = [(lbl[:20] + '...') if len(lbl) > 20 else lbl for lbl in u_labels]
            axes[1].pie(u_vals, labels=u_labels_short, autopct='%1.1f%%', startangle=140)
            axes[1].set_title('Top Cowrie Usernames')
        else:
            axes[1].text(0.5, 0.5, 'No Username Data', horizontalalignment='center', verticalalignment='center')
        pwd_data = password_counter.most_common(10)
        if pwd_data:
            pw_labels, pw_vals = zip(*pwd_data)
            pw_labels_short = [(lbl[:20] + '...') if len(lbl) > 20 else lbl for lbl in pw_labels]
            axes[2].pie(pw_vals, labels=pw_labels_short, autopct='%1.1f%%', startangle=140)
            axes[2].set_title('Top Cowrie Passwords')
        else:
            axes[2].text(0.5, 0.5, 'No Password Data', horizontalalignment='center', verticalalignment='center')
        plt.suptitle('Honeypot_Omaha Specific Metrics Breakdown', fontsize=16)
        plt.tight_layout()
        plt.savefig('cowrie_top5_metrics_pie_chart.png')
        plt.close()
        print("[+] Saved Cowrie Pie Chart as 'cowrie_top5_metrics_pie_chart.png'")
def open_chart_application(filename):
    if not os.path.exists(filename):
        print(f"[!] Error: File '{filename}' not found.")
        return
    print(f"[*] Prompting system to open {filename}...")
    system_name = platform.system()
    opened = False
    try:
        if system_name == 'Darwin':
            subprocess.run(['open', filename], check=True)
            opened = True
        elif system_name == 'Windows':
            os.startfile(filename)
            opened = True
        else:
            viewers = ['eog', 'feh', 'xdg-open', 'ristretto', 'gwenview', 'display']
            for viewer in viewers:
                try:
                    subprocess.run([viewer, filename], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                    opened = True
                    break
                except (FileNotFoundError, subprocess.CalledProcessError):
                    continue
            if not opened:
                subprocess.run(['xdg-open', filename], check=True)
                opened = True
    except Exception as e:
        print(f"[!] Could not launch application automatically: {e}")
def handle_chart_selection(ip_counter, protocol_counter, username_counter, password_counter):
    if not MATPLOTLIB_AVAILABLE:
        print("[!] Matplotlib is not installed. Skipping chart generation.")
        return
    while True:
        print("\n" + "-"*40)
        print("Honeypot_Omaha VISUAL CHARTS MENU")
        print("-"*40)
        print("1. Generate & View Top 10 IP Talkers Chart")
        print("2. Generate & View Cowrie Metrics Breakdown Chart")
        print("3. Generate & View Both Charts")
        print("4. Return to Main Menu")
        
        chart_choice = input("\nEnter your chart choice (1-4): ").strip()
        if chart_choice == '1':
            generate_pie_charts(ip_counter, protocol_counter, username_counter, password_counter, target='ip')
            open_chart_application('phase2_top_ips_pie_chart.png')
        elif chart_choice == '2':
            generate_pie_charts(ip_counter, protocol_counter, username_counter, password_counter, target='cowrie')
            open_chart_application('cowrie_top5_metrics_pie_chart.png')
        elif chart_choice == '3':
            generate_pie_charts(ip_counter, protocol_counter, username_counter, password_counter, target='both')
            open_chart_application('phase2_top_ips_pie_chart.png')
            open_chart_application('cowrie_top5_metrics_pie_chart.png')
        elif chart_choice == '4':
            break
        else:
            print("[!] Invalid option. Choose between 1 and 4.")
def view_text_file(filename):
    if not os.path.exists(filename):
        print(f"[!] Error: Report file '{filename}' not found.")
        return
    try:
        subprocess.run(['less', '+1G', filename])
    except Exception:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            print(f.read())
def display_quick_console_overview(ip_counter, protocol_counter, username_counter, password_counter, command_attempts, file_artifacts):
    print("\n" + "="*60)
    print("Honeypot_Omaha QUICK CONSOLE OVERVIEW SUMMARY")
    print("="*60)
    print(f"[*] Total Unique Tracked IPs : {len(ip_counter)}")
    print(f"[*] Total Commands Captured  : {len(command_attempts)}")
    print(f"[*] Total File Artifacts Found: {len(file_artifacts)}")
    
    print("\n--- Top 5 IP Talkers ---")
    for ip, hits in ip_counter.most_common(5):
        print(f"  - IP: {ip:<16} Hits: {hits}")
    print("\n--- Top Protocols Used ---")
    for proto, count in protocol_counter.most_common(5):
        print(f"  - Protocol: {proto:<10} Count: {count}")
    print("\n--- Discovered File Artifacts (.exe, .elf, .pdf, .png, .mime, .html) ---")
    if file_artifacts:
        for art in list(file_artifacts)[:10]:
            print(f"  - [{art['type']}] {art['name']} (IP: {art['src_ip']})")
    else:
        print("  - No specialized binary or document artifacts extracted in this run.")
    print("="*60 + "\n")
def query_user_input_data(ip_counter, ip_time_ranges, ip_targeted_endpoints, credential_attempts, command_attempts, ip_network_details, endpoint_statuses, file_artifacts, cowrie_event_records, endpoint_timestamps):
    print("\n" + "="*50)
    print("Honeypot_Omaha - SEARCH/QUERY DATA BY IP OR FQDN (OPTION 5)")
    print("="*50)
    user_query = input("Enter a valid IP address or FQDN to query (e.g., 80.94.95.211 or www.xyz.com): ").strip()
    ip_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
    fqdn_pattern = r'^(?=.{1,253}$)(?!\-)[A-Za-z0-9\-]{1,63}(\.[A-Za-z0-9\-]{1,63})+$'
    is_ip = bool(re.match(ip_pattern, user_query))
    is_fqdn = bool(re.match(fqdn_pattern, user_query))
    if not is_ip and not is_fqdn:
        print(f"[!] Invalid input format: '{user_query}'. Please enter a valid IPv4 address or FQDN.")
        return
    query_report_file = 'honeypot_omaha_query_report.txt'
    with open(query_report_file, 'w', encoding='utf-8') as f_out:
        found_matches = False
        if is_ip:
            if user_query in ip_counter or user_query in ip_network_details:
                found_matches = True
                hits = ip_counter.get(user_query, 1)
                timerange = ip_time_ranges.get(user_query, {'start': 'N/A', 'end': 'N/A'})
                country, org = get_ip_intel(user_query)
                net_info = ip_network_details.get(user_query, {'src_ports': set(), 'dst_ports': set(), 'protocols': set(), 'sessions': set()})
                f_out.write("=" * 75 + "\n")
                f_out.write(f"Honeypot_Omaha THREAT INTEL & CORRELATION REPORT: {user_query}\n")
                f_out.write("=" * 75 + "\n")
                f_out.write(f"Total Hits / Attempts Made : {hits}\n")
                f_out.write(f"Source Address             : {user_query}\n")
                f_out.write(f"Source Port(s)             : {', '.join(map(str, sorted(net_info['src_ports']))) if net_info['src_ports'] else 'N/A'}\n")
                f_out.write(f"Destination Port(s)        : {', '.join(map(str, sorted(net_info['dst_ports']))) if net_info['dst_ports'] else 'N/A'}\n")
                f_out.write(f"Protocols Used             : {', '.join(sorted(net_info['protocols'])) if net_info['protocols'] else 'TCP, UDP, DNS, SMTP, SSH, TELNET, HTTP'}\n")
                f_out.write(f"JSON Session ID(s)         : {', '.join(sorted(net_info['sessions'])) if net_info['sessions'] else 'N/A'}\n")
                f_out.write(f"First Seen Timestamp       : {format_short_time(timerange['start'])}\n")
                f_out.write(f"Last Seen Timestamp        : {format_short_time(timerange['end'])}\n")
                f_out.write(f"Geographic Country         : {country}\n")
                f_out.write(f"Organization / ISP         : {org}\n\n")
                
                # --- PHASE 1: BRUTE-FORCE & BEHAVIORAL PROFILING ---
                
                ip_creds = [c for c in credential_attempts if c.get('ip') == user_query or c.get('src_ip') == user_query or user_query in c.get('endpoint', '')]
                unique_usernames = list(set([c.get('username') for c in ip_creds if c.get('username')]))
                unique_passwords = list(set([c.get('password') for c in ip_creds if c.get('password')]))

                # Determine velocity/brute-force tag
                total_attempts = ip_counter.get(user_query, 0)
                is_brute_forcer = total_attempts > 20 or len(ip_creds) > 5
                actor_behavior_tag = "[!] HIGH-VELOCITY BRUTE-FORCE ACTOR" if is_brute_forcer else "[*] Standard Scanning / Reconnaissance"
                
                # Write the profiling results directly to the report file
                f_out.write(f"Actor Behavioral Profile : {actor_behavior_tag}\n")
                f_out.write(f"Total Attack Velocity    : {total_attempts} total requests logged\n")
                
                if ip_creds:
                    f_out.write(f"[+] Brute-Force Credentials Harvested:\n")
                    f_out.write(f"    - Unique Usernames Tried ({len(unique_usernames)}) : {', '.join(unique_usernames[:10])}\n")
                    f_out.write(f"    - Unique Passwords Tried ({len(unique_passwords)}) : {', '.join(unique_passwords[:10])}\n")
                else:
                    f_out.write(f"[+] Brute-Force Credentials: No explicit login credentials captured for this target.\n")
                f_out.write("-" * 75 + "\n\n")

                matching_cowrie_events = [ev for ev in cowrie_event_records if ev['src_ip'] == user_query]
                if matching_cowrie_events:
                    matching_cowrie_events.sort(key=lambda x: x['timestamp'] if x['timestamp'] != 'N/A' else '')
                    
                    session_cred_map = {}
                    for ev in cowrie_event_records:
                        if ev['session'] and ev['session'] != 'N/A':
                            if ev['username'] != 'N/A' or ev['password'] != 'N/A':
                                session_cred_map[ev['session']] = {
                                    'username': ev['username'], 
                                    'password': ev['password']
                                }
                    f_out.write("=" * 75 + "\n")
                    f_out.write(f"Honeypot_Omaha COWRIE LOG CORRELATION (Ports 2222/2223 Focus, Sorted by UTC Timestamp):\n")
                    f_out.write("=" * 75 + "\n")
                    f_out.write(f"Number of Individual Attempts Made: {len(matching_cowrie_events)}\n\n")
                    
                    for idx, ev in enumerate(matching_cowrie_events, 1):
                        curr_user = ev['username']
                        curr_pwd = ev['password']
                        
                        if (curr_user == 'N/A' or not curr_user) and ev['session'] in session_cred_map:
                            curr_user = session_cred_map[ev['session']]['username']
                        if (curr_pwd == 'N/A' or not curr_pwd) and ev['session'] in session_cred_map:
                            curr_pwd = session_cred_map[ev['session']]['password']
                        status_tag = ""
                        evid_lower = ev['eventid'].lower()
                        if 'success' in evid_lower:
                            status_tag = " [LOGIN SUCCESSFUL]"
                        elif 'failed' in evid_lower:
                            status_tag = " [LOGIN FAILED]"
                        else:
                            status_tag = f" [{ev['eventid']}]"
                        f_out.write(f"Attempt #{idx} | UTC Timestamp: {ev['timestamp']} | IP: {ev['src_ip']} | Session: {ev['session']}{status_tag}\n")
                        f_out.write(f"  - username             : {curr_user}\n")
                        f_out.write(f"  - password             : {curr_pwd}\n")
                        f_out.write(f"  - session id           : {ev['session']}\n")
                        f_out.write(f"  - UTC timestamp        : {ev['timestamp']}\n")
                        f_out.write(f"  - src ip               : {ev['src_ip']}\n")
                        f_out.write(f"  - src port             : {ev['src_port']}\n")
                        f_out.write(f"  - dst ip               : {ev['dst_ip']}\n")
                        f_out.write(f"  - dst port             : {ev['dst_port']} {'(Target Port 2222/2223 Honeypot Listener)' if ev['dst_port'] in [2222, 2223] else ''}\n")
                        f_out.write(f"  - message              : {ev['message']}\n")
                        f_out.write(f"  - eventid              : {ev['eventid']}\n")
                        f_out.write("  " + "-" * 60 + "\n")
                    f_out.write("\n")
                else:
                    f_out.write("Cowrie Chronological Logs  : No matching Cowrie session records found for this IP on ports 2222/2223.\n\n")
                matching_creds = [c for c in credential_attempts if c['src_ip'] == user_query]
                if matching_creds:
                    f_out.write(f"Valid Credentials & Auth Attempts Summary ({len(matching_creds)}):\n")
                    f_out.write("-" * 50 + "\n")
                    for cred in matching_creds:
                        valid_tag = " [VALID CREDENTIAL FOUND]" if 'success' in cred['status'].lower() else ""
                        f_out.write(f"  - Session ID : {cred['session']}\n")
                        f_out.write(f"    Username   : {cred['username']}\n")
                        f_out.write(f"    Password   : {cred['password']}\n")
                        f_out.write(f"    Auth Status: {cred['status']}{valid_tag}\n")
                        f_out.write(f"    Timestamp  : {format_short_time(cred['timestamp'])}\n")
                        f_out.write("    " + "-"*35 + "\n")
                    f_out.write("\n")
                matching_cmds = [cmd for cmd in command_attempts if cmd['src_ip'] == user_query]
                if matching_cmds:
                    f_out.write(f"Shell Commands Executed by Threat Actor ({len(matching_cmds)}):\n")
                    f_out.write("-" * 50 + "\n")
                    for cmd_entry in matching_cmds:
                        f_out.write(f"  - [{format_short_time(cmd_entry['timestamp'])}] Session {cmd_entry['session']}:\n")
                        f_out.write(f"    Command: {cmd_entry['command']}\n")
                    f_out.write("\n")
                matching_files = [fa for fa in file_artifacts if fa['src_ip'] == user_query]
                if matching_files:
                    f_out.write(f"Correlated File Artifacts (.exe, .elf, .pdf, .png, .mime, .html) ({len(matching_files)}):\n")
                    f_out.write("-" * 50 + "\n")
                    for fa in matching_files:
                        f_out.write(f"  - Type: {fa['type']} | Name/Path: {fa['name']} | Session: {fa['session']}\n")
                    f_out.write("\n")
                targeted_eps = ip_targeted_endpoints.get(user_query, set())
                if targeted_eps:
                    sorted_targeted_eps = sorted(
                        targeted_eps, 
                        key=lambda ep: endpoint_timestamps.get(ep, ''), 
                        reverse=False
                    )
                    f_out.write(f"Targeted Endpoints, Methods (GET/POST), Status Codes & CVE Threat Level (Sorted by Highest Score):\n")
                    f_out.write("=" * 75 + "\n")
                    
                    for idx, ep in enumerate(sorted_targeted_eps, 1):
                        # Retrieve the actual log timestamp stored for this endpoint, default to 'N/A' if not found
                        endpoint_log_time = endpoint_timestamps.get(ep, 'N/A')
                        
                        intel = get_threat_intel_mapping(ep)
                        status_code = endpoint_statuses.get(ep, '200 OK')
                        
                        f_out.write(f"  {idx}. Endpoint / Protocol : {ep}\n")
                        f_out.write(f"    Timestamp             : {endpoint_log_time}\n") # <--- Pulls the log's timestamp
                        f_out.write(f"    HTTP Status Code      : {status_code}\n")
                        f_out.write(f"    CVE Reference         : {intel['cve']}\n")
                        f_out.write(f"    Threat Rating Score   : {intel['score_str']}\n")
                        f_out.write(f"    MITRE ATT&CK          : {intel['mitre']}\n")
                        f_out.write(f"    Exploit Used          : {intel['exploit']}\n")
                        f_out.write(f"    Threat Intention      : {intel['intention']}\n")
                        f_out.write(f"    Mitigation            : {intel['mitigation']}\n")
                        f_out.write(f"    " + "-"*45 + "\n")

                    # --- EXTERNAL THREAT INTELLIGENCE OSINT LOOKUP LINKS ---
                    f_out.write("\nEXTERNAL THREAT INTELLIGENCE OSINT LOOKUP LINKS:\n")
                    f_out.write("-" * 50 + "\n")
                    if is_ip:
                        f_out.write(f"  - VirusTotal IP        : https://www.virustotal.com/gui/ip-address/{user_query}\n")
                        f_out.write(f"  - Shodan IP Search     : https://www.shodan.io/host/{user_query}\n")
                        f_out.write(f"  - AbuseIPDB Lookup     : https://www.abuseipdb.com/check/{user_query}\n")
                        f_out.write(f"  - AlienVault OTX IP    : https://otx.alienvault.com/indicator/ip/{user_query}\n")
                        f_out.write(f"  - Cisco Talos IP       : https://www.talosintelligence.com/reputation_center/lookup?search={user_query}\n")
                    elif is_fqdn:
                        f_out.write(f"  - VirusTotal Domain    : https://www.virustotal.com/gui/domain/{user_query}\n")
                        f_out.write(f"  - Shodan Domain Search : https://www.shodan.io/search?query={user_query}\n")
                        f_out.write(f"  - AlienVault OTX Domain: https://otx.alienvault.com/indicator/domain/{user_query}\n")
                        f_out.write(f"  - Cisco Talos Domain   : https://www.talosintelligence.com/reputation_center/lookup?search={user_query}\n")
            else:
                f_out.write(f"[!] FQDN or domain keyword '{user_query}' was not found across analyzed endpoints.\n")
        if not found_matches and (is_ip or is_fqdn):
            f_out.write(f"[!] No matching records were discovered for '{user_query}'.\n")
    if os.path.exists(query_report_file):
        view_text_file(query_report_file)
    else:
        print(f"[!] Query report file not generated.")
def run_honeypot_pipeline():
    print("[*] Starting Unified Honeypot_Omaha Processing and Analysis Pipeline...")
    
    json_files = glob.glob('webhoneypot_*.json') + glob.glob('cowrie.json')
    log_files = glob.glob('*.log') + glob.glob('webhoneypot_*.log') + glob.glob('cowrie.log')
    all_files = list(set(json_files + log_files))
    
    ip_counter = Counter()
    endpoint_counter = Counter()
    endpoint_timestamps = {} 
    endpoint_statuses = {}
    ip_time_ranges = {}
    ip_targeted_endpoints = {} 
    credential_attempts = []
    command_attempts = []
    ip_network_details = {}
    file_artifacts = []
    cowrie_event_records = []
    
    username_counter = Counter()
    password_counter = Counter()
    protocol_counter = Counter()
    
    ip_username_map = defaultdict(Counter)
    ip_password_map = defaultdict(Counter)
    
    print("[*] Phase 1: Processing log files and generating TSV files...")
    
    for file_path in all_files:
        is_json = file_path.endswith('.json')
        tsv_file = file_path.replace('.json', '_import.tsv').replace('.log', '_import.tsv')
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f_in, open(tsv_file, 'w', encoding='utf-8') as f_out:
            
            if not is_json:
                f_out.write("#fields\ttimestamp\tip\tmessage\n")
                f_out.write("#types\tstring\taddr\tstring\n")
                
                for line in f_in:
                    if not line.strip():
                        continue
                    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    ip = ip_match.group(0) if ip_match else '0.0.0.0'
                    timestamp = 'N/A'
                    method_url = "LOG ENTRY (Plain Text)"
                    attempts = 1
                    
                    ip_counter[ip] += attempts
                    endpoint_counter[method_url] += attempts
                    
                    if ip not in ip_targeted_endpoints:
                        ip_targeted_endpoints[ip] = set()
                    ip_targeted_endpoints[ip].add(method_url)
                    
                    if ip not in ip_network_details:
                        ip_network_details[ip] = {'src_ports': set(), 'dst_ports': set(), 'protocols': {'HTTP'}, 'sessions': set()}
                        
                    f_out.write(f"{timestamp}\t{ip}\t{line.strip()}\n")
            else:
                if 'cowrie' in file_path:
                    f_out.write("#fields\tsession\ttimestamp\tsrc_ip\tsrc_port\tdst_ip\tdst_port\tprotocol\tusername\tpassword\tmessage\n")
                    f_out.write("#types\tstring\tstring\taddr\tcount\taddr\tcount\tstring\tstring\tstring\tstring\n")
                else:
                    f_out.write("#fields\ttime\tip\tmethod_url\tattempts\n")
                    f_out.write("#types\tstring\taddr\tstring\tcount\n")
                
                for line in f_in:
                    if not line.strip(): 
                        continue
                    try:
                        data = json.loads(line)
                        
                        status_str = '200 OK'
                        if 'cowrie' in file_path or 'eventid' in data:
                            evid = data.get('eventid', '')
                            if 'failed' in evid.lower():
                                status_str = '401 Unauthorized'
                            elif 'success' in evid.lower():
                                status_str = '200 OK (Auth Success)'
                        else:
                            code = str(data.get('code') or data.get('status') or '200')
                            if code == '404' or code.startswith('4'):
                                status_str = '404 Not Found'
                            elif code.startswith('2'):
                                status_str = '200 OK'
                            else:
                                status_str = f'{code} Status'
                        if 'cowrie' in file_path or 'eventid' in data:
                            ip = data.get('src_ip') or data.get('sip') or '0.0.0.0'
                            protocol = data.get('protocol', 'ssh')
                            dst_port = data.get('dst_port', 2222)
                            src_port = data.get('src_port', 0)
                            method_url = f"{protocol.upper()} (Port {dst_port})"
                            attempts = 1
                            
                            session = data.get('session', 'N/A')
                            timestamp = data.get('timestamp', 'N/A')
                            dst_ip = data.get('dst_ip', '0.0.0.0')
                            username = data.get('username', 'N/A')
                            password = data.get('password', 'N/A')
                            message = data.get('message', 'N/A')
                            
                            cowrie_event_records.append({
                                'timestamp': timestamp,
                                'session': session,
                                'src_ip': ip,
                                'src_port': src_port,
                                'dst_ip': dst_ip,
                                'dst_port': dst_port,
                                'protocol': protocol,
                                'eventid': evid,
                                'username': username,
                                'password': password,
                                'message': message
                            })
                            
                            if protocol != 'unknown':
                                protocol_counter[protocol.upper()] += 1
                            if username != 'N/A':
                                username_counter[username] += 1
                                ip_username_map[username][ip] += 1
                            if password != 'N/A':
                                password_counter[password] += 1
                                ip_password_map[password][ip] += 1
                            
                            if username != 'N/A' or password != 'N/A':
                                credential_attempts.append({
                                    'session': session,
                                    'timestamp': timestamp,
                                    'src_ip': ip,
                                    'username': username,
                                    'password': password,
                                    'status': status_str
                                })
                            if 'command' in evid.lower() or 'input' in data:
                                cmd = data.get('input') or data.get('command')
                                if cmd:
                                    command_attempts.append({
                                        'session': session,
                                        'timestamp': timestamp,
                                        'src_ip': ip,
                                        'command': cmd
                                    })
                                    for ext in ['.exe', '.elf', '.pdf', '.png', '.mime', '.html']:
                                        if ext in cmd.lower():
                                            file_artifacts.append({
                                                'type': ext.upper().replace('.', ''),
                                                'name': cmd,
                                                'src_ip': ip,
                                                'session': session
                                            })
                            
                            f_out.write(f"{session}\t{timestamp}\t{ip}\t{src_port}\t{dst_ip}\t{dst_port}\t{protocol}\t{username}\t{password}\t{message}\n")
                        
                        else:
                            ip = data.get('sip') or data.get('ip') or '0.0.0.0'
                            method = data.get('method', 'GET')
                            url = data.get('url') or data.get('endpoint') or '/'
                            method_url = f"{method} {url}"
                            timestamp = data.get('time') or data.get('timestamp') or 'N/A'
                            attempts = int(data.get('attempts', 1))
                            src_port = data.get('sport', 0)
                            dst_port = data.get('dport', 80)
                            protocol = 'HTTP'
                            session = data.get('session', 'N/A')
                            
                            for ext in ['.png', '.pdf', '.html', '.exe', '.elf', '.mime']:
                                if ext in url.lower():
                                    file_artifacts.append({
                                        'type': ext.upper().replace('.', ''),
                                        'name': url,
                                        'src_ip': ip,
                                        'session': session
                                    })
                            f_out.write(f"{timestamp}\t{ip}\t{method_url}\t{attempts}\n")
                        
                        ip_counter[ip] += attempts
                        endpoint_counter[method_url] += attempts
                        
                        if ip not in ip_targeted_endpoints:
                            ip_targeted_endpoints[ip] = set()
                        ip_targeted_endpoints[ip].add(method_url)
                        if ip not in ip_network_details:
                            ip_network_details[ip] = {'src_ports': set(), 'dst_ports': set(), 'protocols': set(), 'sessions': set()}
                        
                        if src_port:
                            ip_network_details[ip]['src_ports'].add(src_port)
                        if dst_port:
                            ip_network_details[ip]['dst_ports'].add(dst_port)
                        if protocol and protocol != 'unknown':
                            ip_network_details[ip]['protocols'].add(protocol.upper())
                        else:
                            ip_network_details[ip]['protocols'].add('HTTP')
                        if session and session != 'N/A':
                            ip_network_details[ip]['sessions'].add(session)
                        
                        if method_url not in endpoint_timestamps:
                            endpoint_timestamps[method_url] = timestamp
                            endpoint_statuses[method_url] = status_str
                            
                        if timestamp != 'N/A':
                            if ip not in ip_time_ranges:
                                ip_time_ranges[ip] = {'start': timestamp, 'end': timestamp}
                            else:
                                if timestamp < ip_time_ranges[ip]['start']:
                                    ip_time_ranges[ip]['start'] = timestamp
                                if timestamp > ip_time_ranges[ip]['end']:
                                    ip_time_ranges[ip]['end'] = timestamp
                    
                    except Exception:
                        continue
    print("\n" + "="*66)
    print("[*] Phase 2: Running Threat Intelligence Lookups & Compiling Report...")
    print("="*66)
    sorted_ips_deterministic = sorted(ip_counter.items(), key=lambda x: (-x[1], x[0]))
    print(f"\n===> TOP 10 UNIQUE IP SUMMARY (DETERMINISTIC) <===\n")
    for idx, (ip_addr, hits) in enumerate(sorted_ips_deterministic[:10], 1):
        print(f"{idx}. IP Address: {ip_addr} (Hits: {hits})")
    print(f"\n===> TOP 10 COWRIE PROTOCOLS <===\n")
    for proto, count in protocol_counter.most_common(10):
        print(f"Protocol: {proto} ===> Hits: {count}")
    print(f"\n===> TOP 10 COWRIE USERNAMES & ASSOCIATED TOP IPS <===\n")
    for user, attempts in username_counter.most_common(10):
        print(f"Username: {user} ===> Total Attempts: {attempts}")
        top_ips_for_user = ip_username_map[user].most_common(3)
        for u_ip, u_hits in top_ips_for_user:
            print(f"     -> Associated IP: {u_ip} (Hits: {u_hits})")
    print(f"\n===> TOP 10 COWRIE PASSWORDS & ASSOCIATED TOP IPS <===\n")
    for pwd, attempts in password_counter.most_common(10):
        print(f"Password: {pwd} ===> Total Attempts: {attempts}")
        top_ips_for_pwd = ip_password_map[pwd].most_common(3)
        for p_ip, p_hits in top_ips_for_pwd:
            print(f"     -> Associated IP: {p_ip} (Hits: {p_hits})")
    print(f"\n===> TOP 10 TALKERS WITH THREAT INTEL <===\n")
    for ip_addr, hits in sorted_ips_deterministic[:10]:
        country, org = get_ip_intel(ip_addr)
        print(f"IP: {ip_addr} ===> Attempts: {hits} ===> Country: {country} ===> ISP/CSP: {org}")
    print(f"\n===> LEAST 10 TALKERS WITH THREAT INTEL <===\n")
    least_ips = sorted(ip_counter.items(), key=lambda x: (x[1], x[0]))[:10]
    for ip_addr, hits in least_ips:
        country, org = get_ip_intel(ip_addr)
        print(f"IP: {ip_addr} ===> Attempts: {hits} ===> Country: {country} ===> ISP/CSP: {org}")
    print(f"\n===> MOST TARGETED ENDPOINTS ACROSS ALL LOGS <===\n")
    sorted_endpoints_display = sorted(endpoint_counter.items(), key=lambda x: x[1], reverse=True)
    for endpoint, count in sorted_endpoints_display[:10]:
        print(f"  {endpoint}: =====>> {count} hits")
    generate_pie_charts(ip_counter, protocol_counter, username_counter, password_counter, target='both')
    report_name = 'honeypot_omaha_summary_report.txt'
    with open(report_name, 'w', encoding='utf-8') as f:
        f.write("="*60 + "\n")
        f.write("Honeypot_Omaha SUMMARY REPORT\n")
        f.write("="*60 + "\n\n")
        f.write("--- FILE ARTIFACTS FOUND (.EXE, .ELF, .PDF, .PNG, .MIME, .HTML) ---\n")
        for fa in file_artifacts:
            f.write(f"Type: {fa['type']} | Artifact: {fa['name']} | IP: {fa['src_ip']} | Session: {fa['session']}\n")
        f.write("\n")
    cve_report_name = 'honeypot_omaha_cve_summary_report.txt'
    with open(cve_report_name, 'w', encoding='utf-8') as f:
        f.write("="*60 + "\n")
        f.write("Honeypot_Omaha CVE, MITRE & EXPLOITS REPORT (Sorted by Score)\n")
        f.write("="*60 + "\n\n")
        sorted_endpoints_cve = sorted(
            endpoint_counter.items(), 
            key=lambda x: get_threat_intel_mapping(x[0])['score_val'], 
            reverse=True
        )
        for endpoint, count in sorted_endpoints_cve:
            intel = get_threat_intel_mapping(endpoint)
            status_str = endpoint_statuses.get(endpoint, '200 OK')
            f.write(f"Endpoint / Protocol : {endpoint}\n")
            f.write(f"Total Hits          : {count}\n")
            f.write(f"HTTP Status Code    : {status_str}\n")
            f.write(f"CVE Reference       : {intel['cve']}\n")
            f.write(f"Threat Rating Score : {intel['score_str']}\n")
            f.write(f"MITRE ATT&CK        : {intel['mitre']}\n")
            f.write(f"Exploit Used        : {intel['exploit']}\n")
            f.write(f"Threat Intention    : {intel['intention']}\n")
            f.write(f"Mitigation          : {intel['mitigation']}\n")
            f.write("-" * 50 + "\n\n")
    print(f"\n[*] Generating standard summary report: '{report_name}'...")
    print(f"[*] Generating CVE & MITRE vulnerability report: '{cve_report_name}'...")
    print(f"[+] All reports and charts successfully generated!")
    while True:
        print("\n" + "="*50)
        print("REPORT VIEWING SELECTION MENU")
        print("="*50)
        print("1. View Standard Summary Report (honeypot_omaha_summary_report.txt)")
        print("2. View CVE, MITRE & Exploits Report (honeypot_omaha_cve_summary_report.txt)")
        print("3. Generating visual summary pie charts")
        print("4. View Generated Report Summary Details (Quick Console Overview)")
        print("5. Search/Query Data by IP or FQDN")
        print("6. Exit Menu")
        
        choice = input("\nEnter your choice (1, 2, 3, 4, 5, or 6): ").strip()
        
        if choice == '1':
            view_text_file(report_name)
        elif choice == '2':
            view_text_file(cve_report_name)
        elif choice == '3':
            handle_chart_selection(ip_counter, protocol_counter, username_counter, password_counter)
        elif choice == '4':
            display_quick_console_overview(ip_counter, protocol_counter, username_counter, password_counter, command_attempts, file_artifacts)
        elif choice == '5':
            query_user_input_data(ip_counter, ip_time_ranges, ip_targeted_endpoints, credential_attempts, command_attempts, ip_network_details, endpoint_statuses, file_artifacts, cowrie_event_records, endpoint_timestamps)
        elif choice == '6':
            print("[*] Exiting Honeypot_Omaha Pipeline. Stay secure!")
            sys.exit(0)
        else:
            print("[!] Invalid option. Choose between 1 and 6.")
if __name__ == '__main__':
    authenticate_user()
    run_honeypot_pipeline()


