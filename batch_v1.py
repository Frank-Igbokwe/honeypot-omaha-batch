#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
====================================================================
Project Name : Unified Honeypot Analysis Pipeline
Author       : Your Name Here
Created      : 2026
Copyright    : (c) 2026 Your Name. All rights reserved.
License      : Proprietary / All Rights Reserved 
               (or specify an open-source license like MIT)
====================================================================
"""

import csv
import glob
import json
import urllib.request
import sys
from collections import Counter
import subprocess
import platform
import os
import re

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
            'mitre': 'T1059.004 (Command and Scripting Interpreter: Unix Shell)',
            'exploit': 'Shellshock Remote Code Execution',
            'intention': 'Arbitrary command execution and system compromise',
            'mitigation': 'Patch vulnerable Bash instances and use WAF rules'
        }
    elif 'TELNET' in item or 'SSH' in item:
        return {
            'cve': 'N/A (Credential Brute-Forcing)',
            'mitre': 'T1110 (Brute Force)',
            'exploit': 'Default Credential / Dictionary Attack',
            'intention': 'Gain unauthorized remote administrative access',
            'mitigation': 'Enforce strong key-based authentication, disable root login, and use fail2ban'
        }
    elif 'ENV' in item:
        return {
            'cve': 'CVE-2019-11043 / Information Disclosure',
            'mitre': 'T1592 (Gather Victim Host Information)',
            'exploit': 'Sensitive Environment File Scraping',
            'intention': 'Harvest configuration secrets, database credentials, and API keys',
            'mitigation': 'Restrict public access to dotfiles and sensitive web root files'
        }
    elif 'FAVICON' in item:
        return {
            'cve': 'N/A (Reconnaissance)',
            'mitre': 'T1595 (Active Scanning)',
            'exploit': 'Asset Fingerprinting',
            'intention': 'Identify framework type and software version',
            'mitigation': 'Standard footprint reduction / custom headers'
        }
    else:
        return {
            'cve': 'N/A (General Web Attack)',
            'mitre': 'T1190 (Exploit Public-Facing Application)',
            'exploit': 'HTTP Request Flooding / Web Probing',
            'intention': 'Probe application attack surface and web paths',
            'mitigation': 'Implement rate limiting and robust input validation'
        }

def get_ip_intel(ip):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org"
        req = urllib.request.Request(url, headers={'User-Agent': 'HoneypotAnalyzer'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get('status') == 'success':
                country = data.get('country', 'Unknown')
                org = data.get('org', data.get('ISP', 'Unknown'))
                return country, org
    except Exception:
        pass
    return 'Unknown', 'Unknown'

def generate_pie_charts(ip_counter, protocol_counter, username_counter, password_counter):
    if not MATPLOTLIB_AVAILABLE:
        print("[!] Matplotlib is not installed. Skipping pie chart generation. (Run: pip install matplotlib)")
        return

    print("[*] Generating visual summary pie charts...")

    top_10_chart_data = sorted(ip_counter.items(), key=lambda x: (-x[1], x[0]))[:10]
    if top_10_chart_data:
        ips, hits = zip(*top_10_chart_data)
        plt.figure(figsize=(9, 6))
        plt.pie(hits, labels=ips, autopct='%1.1f%%', startangle=140)
        plt.title('Phase 2 Summary: Top 10 IP Talkers Distribution')
        plt.tight_layout()
        plt.savefig('phase2_top_ips_pie_chart.png')
        plt.close()
        print("[+] Saved Phase 2 Pie Chart as 'phase2_top_ips_pie_chart.png'")

    fig, axes = plt.subplots(1, 3, figsize=(18, 6))
    
    proto_data = protocol_counter.most_common(5)
    if proto_data:
        p_labels, p_vals = zip(*proto_data)
        axes[0].pie(p_vals, labels=p_labels, autopct='%1.1f%%', startangle=140)
        axes[0].set_title('Top Cowrie Protocols')
    else:
        axes[0].text(0.5, 0.5, 'No Protocol Data', horizontalalignment='center', verticalalignment='center')

    user_data = username_counter.most_common(5)
    if user_data:
        u_labels, u_vals = zip(*user_data)
        u_labels_short = [(lbl[:20] + '...') if len(lbl) > 20 else lbl for lbl in u_labels]
        axes[1].pie(u_vals, labels=u_labels_short, autopct='%1.1f%%', startangle=140)
        axes[1].set_title('Top 5 Cowrie Usernames')
    else:
        axes[1].text(0.5, 0.5, 'No Username Data', horizontalalignment='center', verticalalignment='center')

    pwd_data = password_counter.most_common(5)
    if pwd_data:
        pw_labels, pw_vals = zip(*pwd_data)
        pw_labels_short = [(lbl[:20] + '...') if len(lbl) > 20 else lbl for lbl in pw_labels]
        axes[2].pie(pw_vals, labels=pw_labels_short, autopct='%1.1f%%', startangle=140)
        axes[2].set_title('Top 5 Cowrie Passwords')
    else:
        axes[2].text(0.5, 0.5, 'No Password Data', horizontalalignment='center', verticalalignment='center')

    plt.suptitle('Cowrie Honeypot Specific Metrics Breakdown', fontsize=16)
    plt.tight_layout()
    plt.savefig('cowrie_top5_metrics_pie_chart.png')
    plt.close()
    print("[+] Saved Cowrie Pie Chart as 'cowrie_top5_metrics_pie_chart.png'")

def open_chart_application():
    print("\n" + "-"*40)
    print("CHART VIEWER LAUNCHER")
    print("-"*40)
    print("Which chart would you like to open?")
    print("1. phase2_top_ips_pie_chart.png")
    print("2. cowrie_top5_metrics_pie_chart.png")
    choice = input("Enter chart choice (1 or 2): ").strip()
    
    filename = 'phase2_top_ips_pie_chart.png' if choice == '1' else 'cowrie_top5_metrics_pie_chart.png' if choice == '2' else None
    
    if not filename:
        print("[!] Invalid chart choice.")
        return

    if not os.path.exists(filename):
        print(f"[!] Error: File '{filename}' not found. Ensure the pipeline has run successfully.")
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
                    print(f"[+] Successfully opened {filename} using '{viewer}'.")
                    opened = True
                    break
                except (FileNotFoundError, subprocess.CalledProcessError):
                    continue
            
            if not opened:
                try:
                    subprocess.run(['xdg-open', filename], check=True)
                    opened = True
                except Exception:
                    pass

        if opened:
            print(f"[+] Successfully triggered viewer application for {filename}")
        else:
            print(f"[-] Warning: No default image viewer or desktop handlers were found to display '{filename}'.")

    except Exception as e:
        print(f"[!] Could not launch application automatically: {e}")

def query_user_input_data(ip_counter, ip_time_ranges, ip_targeted_endpoints, credential_attempts):
    print("\n" + "="*50)
    print("TARGETED IP OR FQDN SEARCH QUERY")
    print("="*50)
    user_query = input("Enter a valid IP address or FQDN to query: ").strip()

    ip_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
    fqdn_pattern = r'^(?=.{1,253}$)(?!\-)[A-Za-z0-9\-]{1,63}(\.[A-Za-z0-9\-]{1,63})+$'

    is_ip = bool(re.match(ip_pattern, user_query))
    is_fqdn = bool(re.match(fqdn_pattern, user_query))

    if not is_ip and not is_fqdn:
        print(f"[!] Invalid input format: '{user_query}'. Please enter a valid IPv4 address or FQDN.")
        return

    query_report_file = 'query_result_report.tsv'
    with open(query_report_file, 'w', encoding='utf-8') as f_out:
        f_out.write(f"QUERY REPORT\tTarget: {user_query}\n")
        f_out.write("="*60 + "\n")

        found_matches = False

        if is_ip:
            if user_query in ip_counter:
                found_matches = True
                hits = ip_counter[user_query]
                timerange = ip_time_ranges.get(user_query, {'start': 'N/A', 'end': 'N/A'})
                country, org = get_ip_intel(user_query)

                f_out.write(f"IP Address\t{user_query}\n")
                f_out.write(f"Total Hits/Attempts\t{hits}\n")
                f_out.write(f"First Seen\t{format_short_time(timerange['start'])}\n")
                f_out.write(f"Last Seen\t{format_short_time(timerange['end'])}\n")
                f_out.write(f"Geographic Country\t{country}\n")
                f_out.write(f"Organization / ISP\t{org}\n")
                f_out.write("-" * 60 + "\n")

                targeted_eps = ip_targeted_endpoints.get(user_query, set())
                if targeted_eps:
                    f_out.write("Endpoint / Protocol\tCVE Reference\tMITRE ATT&CK\tExploit Used\tIntention\tMitigation\n")
                    for ep in sorted(targeted_eps):
                        intel = get_threat_intel_mapping(ep)
                        f_out.write(f"{ep}\t{intel['cve']}\t{intel['mitre']}\t{intel['exploit']}\t{intel['intention']}\t{intel['mitigation']}\n")
                else:
                    f_out.write("Targeted Endpoints\tNone specifically mapped.\n")

                matching_creds = [c for c in credential_attempts if c['src_ip'] == user_query]
                if matching_creds:
                    f_out.write("\nAssociated Credential Attempts:\n")
                    f_out.write("Session\tUsername\tPassword\tTimestamp\n")
                    for cred in matching_creds:
                        f_out.write(f"{cred['session']}\t{cred['username']}\t{cred['password']}\t{format_short_time(cred['timestamp'])}\n")
                else:
                    f_out.write("\nAssociated Credential Attempts\tNone logged.\n")
            else:
                f_out.write(f"[!] IP address '{user_query}' was not found in the processed log hits.\n")

        elif is_fqdn:
            all_eps = set()
            for eps in ip_targeted_endpoints.values():
                all_eps.update(eps)
                
            matching_endpoints = [ep for ep in all_eps if user_query.lower() in ep.lower()]
            if matching_endpoints:
                found_matches = True
                f_out.write(f"FQDN / ENDPOINT VULNERABILITY REPORT: {user_query}\n")
                f_out.write("Endpoint / Context\tCVE Reference\tMITRE ATT&CK\tExploit Used\tIntention\tMitigation\n")
                for ep in matching_endpoints:
                    intel = get_threat_intel_mapping(ep)
                    f_out.write(f"{ep}\t{intel['cve']}\t{intel['mitre']}\t{intel['exploit']}\t{intel['intention']}\t{intel['mitigation']}\n")
            else:
                f_out.write(f"[!] FQDN or domain keyword '{user_query}' was not found across analyzed endpoints.\n")

        if not found_matches and (is_ip or is_fqdn):
            f_out.write(f"[!] No matching records were discovered for '{user_query}'.\n")

    if os.path.exists(query_report_file):
        try:
            subprocess.run(['less', '+1G', query_report_file])
        except Exception as e:
            print(f"[!] Could not launch 'less': {e}")
    else:
        print(f"[!] Query report file not generated.")

def run_honeypot_pipeline():
    print("[*] Starting Unified Honeypot_Omaha Processing and Analysis Pipeline...")
    
    json_files = glob.glob('webhoneypot_*.json') + glob.glob('cowrie.json')
    log_files = glob.glob('*.log') + glob.glob('webhoneypot_*.log') + glob.glob('cowrie.log')
    all_files = list(set(json_files + log_files))
    
    if not all_files:
        print("[-] No log files found. Exiting.")
        return

    ip_counter = Counter()
    endpoint_counter = Counter()
    endpoint_timestamps = {} 
    endpoint_statuses = {}
    ip_time_ranges = {}
    ip_targeted_endpoints = {} 
    credential_attempts = []
    
    username_counter = Counter()
    password_counter = Counter()
    protocol_counter = Counter()
    
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
                    
                    if method_url not in endpoint_timestamps:
                        endpoint_timestamps[method_url] = timestamp
                        endpoint_statuses[method_url] = 'Success'
                        
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
                        
                        status_val = 'Success'
                        if 'cowrie' in file_path or 'eventid' in data:
                            evid = data.get('eventid', '')
                            if 'failed' in evid.lower():
                                status_val = 'Fail'
                            elif 'success' in evid.lower():
                                status_val = 'Success'
                        else:
                            code = str(data.get('code') or data.get('status') or '200')
                            if not code.startswith('2'):
                                status_val = 'Fail'

                        if 'cowrie' in file_path or 'eventid' in data:
                            ip = data.get('src_ip') or data.get('sip') or '0.0.0.0'
                            protocol = data.get('protocol', 'unknown')
                            dst_port = data.get('dst_port', 0)
                            method_url = f"{protocol.upper()} (Port {dst_port})"
                            attempts = 1
                            
                            session = data.get('session', 'N/A')
                            timestamp = data.get('timestamp', 'N/A')
                            src_port = data.get('src_port', 0)
                            dst_ip = data.get('dst_ip', '0.0.0.0')
                            username = data.get('username', 'N/A')
                            password = data.get('password', 'N/A')
                            message = data.get('message', 'N/A')
                            
                            if protocol != 'unknown':
                                protocol_counter[protocol.upper()] += 1
                            if username != 'N/A':
                                username_counter[username] += 1
                            if password != 'N/A':
                                password_counter[password] += 1
                            
                            if username != 'N/A' or password != 'N/A':
                                credential_attempts.append({
                                    'session': session,
                                    'timestamp': timestamp,
                                    'src_ip': ip,
                                    'username': username,
                                    'password': password
                                })
                                
                            f_out.write(f"{session}\t{timestamp}\t{ip}\t{src_port}\t{dst_ip}\t{dst_port}\t{protocol}\t{username}\t{password}\t{message}\n")
                        
                        else:
                            ip = data.get('sip') or data.get('ip') or '0.0.0.0'
                            method = data.get('method', 'GET')
                            url = data.get('url') or data.get('endpoint') or '/'
                            method_url = f"{method} {url}"
                            timestamp = data.get('time') or data.get('timestamp') or 'N/A'
                            attempts = int(data.get('attempts', 1))
                            
                            f_out.write(f"{timestamp}\t{ip}\t{method_url}\t{attempts}\n")
                        
                        ip_counter[ip] += attempts
                        endpoint_counter[method_url] += attempts
                        
                        if ip not in ip_targeted_endpoints:
                            ip_targeted_endpoints[ip] = set()
                        ip_targeted_endpoints[ip].add(method_url)
                        
                        if method_url not in endpoint_timestamps:
                            endpoint_timestamps[method_url] = timestamp
                            endpoint_statuses[method_url] = status_val
                            
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

    print(f"\n===> TOP 10 UNIQUE IP SUMMARY (DETERMINISTIC) <===")
    for idx, (ip_addr, hits) in enumerate(sorted_ips_deterministic[:10], 1):
        print(f"{idx}. IP Address: {ip_addr} (Hits: {hits})")

    print("\n===> TOP 10 COWRIE PROTOCOLS <===")
    for proto, count in protocol_counter.most_common(10):
        print(f"Protocol: {proto} ===> Hits: {count}")

    print("\n===> TOP 10 COWRIE USERNAMES <===")
    for user, count in username_counter.most_common(10):
        print(f"Username: {user} ===> Attempts: {count}")

    print("\n===> TOP 10 COWRIE PASSWORDS <===")
    for pwd, count in password_counter.most_common(10):
        print(f"Password: {pwd} ===> Attempts: {count}")

    top_10_ips = sorted_ips_deterministic[:10]
    least_10_ips = list(reversed(sorted_ips_deterministic[-10:])) if len(sorted_ips_deterministic) >= 10 else list(reversed(sorted_ips_deterministic))

    print("\n===> TOP 10 TALKERS WITH THREAT INTEL <===\n")
    top_ip_intel_data = []
    for ip, count in top_10_ips:
        country, org = get_ip_intel(ip)
        top_ip_intel_data.append((ip, count, country, org))
        print(f"IP: {ip} ===> Attempts: {count} ===> Country: {country} ===> ISP/CSP: {org}")

    print("\n===> LEAST 10 TALKERS WITH THREAT INTEL <===\n")
    least_ip_intel_data = []
    for ip, count in least_10_ips:
        country, org = get_ip_intel(ip)
        least_ip_intel_data.append((ip, count, country, org))
        print(f"IP: {ip} ===> Attempts: {count} ===> Country: {country} ===> ISP/CSP: {org}")

    print("\n===> MOST TARGETED ENDPOINTS ACROSS ALL LOGS <===\n")
    for endpoint, count in endpoint_counter.most_common(10):
        print(f"  {endpoint}: =====>> {count} hits")

    generate_pie_charts(ip_counter, protocol_counter, username_counter, password_counter)

    report_name = 'honeypot_omaha_summary_report.csv'
    print(f"\n[*] Generating standard summary report: '{report_name}'...")
    
    with open(report_name, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["===> Category", "Start Time", "End Time", "Endpoints / IP Address", "Country / Details", "Organization / Hits <===\n"])

        for proto, count in protocol_counter.most_common(10):
            writer.writerow(['Top Cowrie Protocol', 'N/A', 'N/A', proto, 'N/A', count])

        for user, count in username_counter.most_common(10):
            writer.writerow(['Top Cowrie Username', 'N/A', 'N/A', user, 'N/A', count])

        for pwd, count in password_counter.most_common(10):
            writer.writerow(['Top Cowrie Password', 'N/A', 'N/A', pwd, 'N/A', count])

        for ip, count, country, org in top_ip_intel_data:
            timerange = ip_time_ranges.get(ip, {'start': 'N/A', 'end': 'N/A'})
            writer.writerow(['Top IP Talker', format_short_time(timerange['start']), format_short_time(timerange['end']), f" {ip}", f"{country}, {org}", f"===>{count}"])

        for ip, count, country, org in least_ip_intel_data:
            timerange = ip_time_ranges.get(ip, {'start': 'N/A', 'end': 'N/A'})
            writer.writerow(['Least IP Talker', format_short_time(timerange['start']), format_short_time(timerange['end']), ip, f"{country}, {org}", count])

        sorted_endpoints = sorted(endpoint_counter.items(), key=lambda x: x[0])
        for endpoint, count in sorted_endpoints:
            ts = endpoint_timestamps.get(endpoint, 'N/A')
            writer.writerow(['Targeted Endpoint', format_short_time(ts), format_short_time(ts), endpoint, endpoint_statuses.get(endpoint, 'Success'), count])

        for cred in credential_attempts:
            writer.writerow(['Auth Attempt', format_short_time(cred['timestamp']), format_short_time(cred['timestamp']), cred['src_ip'], f"Session: {cred['session']}", f"User: {cred['username']} | Pass: {cred['password']}"])

    cve_report_name = 'honeypot_omaha_cve_summary_report.csv'
    print(f"[*] Generating CVE & MITRE vulnerability report: '{cve_report_name}'...")
    
    with open(cve_report_name, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Endpoint / Protocol", "Hits", "CVE Reference", "MITRE ATT&CK", "Exploit Used", "Threat Actor Intention", "Mitigation"])

        sorted_endpoints = sorted(endpoint_counter.items(), key=lambda x: x[0])
        for endpoint, count in sorted_endpoints:
            intel = get_threat_intel_mapping(endpoint)
            writer.writerow([endpoint, count, intel['cve'], intel['mitre'], intel['exploit'], intel['intention'], intel['mitigation']])

    print(f"[+] All reports and charts successfully generated!")

    while True:
        print("\n" + "="*50)
        print("REPORT VIEWING SELECTION MENU")
        print("="*50)
        print("1. View Standard Summary Report (honeypot_omaha_summary_report.csv)")
        print("2. View CVE, MITRE & Exploits Report (honeypot_omaha_cve_summary_report.csv)")
        print("3. Generating visual summary pie charts")
        print("4. View Generated Report Summary Details (Quick Console Overview)")
        print("5. Search/Query Data by IP or FQDN")
        print("6. Exit Menu")
        
        choice = input("\nEnter your choice (1, 2, 3, 4, 5, or 6): ").strip()
        
        if choice == '1':
            if os.path.exists(report_name):
                try:
                    subprocess.run(['less', '+1G', report_name])
                except Exception as e:
                    print(f"[!] Could not launch 'less': {e}")
            else:
                print(f"[!] Report '{report_name}' not found.")
        elif choice == '2':
            if os.path.exists(cve_report_name):
                try:
                    subprocess.run(['less', '+1G', cve_report_name])
                except Exception as e:
                    print(f"[!] Could not launch 'less': {e}")
            else:
                print(f"[!] Report '{cve_report_name}' not found.")
        elif choice == '3':
            open_chart_application()
        elif choice == '4':
            print("\n" + "~"*40)
            print("GENERATED REPORT SUMMARY DETAILS")
            print("~"*40)
            print(f"Total Unique IPs Tracked: {len(ip_counter)}")
            print(f"[*] Total Endpoints Analyzed: {sum(endpoint_counter.values())}")
            print(f"[*] Total Credential Attempts Logged: {len(credential_attempts)}")
            print("~"*40)
        elif choice == '5':
            query_user_input_data(ip_counter, ip_time_ranges, ip_targeted_endpoints, credential_attempts)
        elif choice == '6':
            print("Exiting report viewer. Goodbye!")
            break
        else:
            print("[!] Invalid selection. Please choose a valid option (1-6).")

def main():
    try:
        run_honeypot_pipeline()
    except KeyboardInterrupt:
        print("\n[!] Process interrupted gracefully by user. Exiting safely.")
        sys.exit(0)

if __name__ == "__main__":
    main()
