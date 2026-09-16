#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
====================================================================
Project Name : Honeypot_Omaha (Unified Honeypot Analysis Pipeline)
Author       : Frank Ngoka Igbokwe
Created      : 2026
Copyright    : (c) 2026 Frank Ngoka Igbokwe. All rights reserved.
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
from datetime import datetime, timezone

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPixmap, QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QPushButton, QLabel, QTextEdit, QTextBrowser, QStackedWidget,
    QLineEdit, QMessageBox, QScrollArea, QSplitter
)

# ====================================================================
# INTELLECTUAL PROPERTY SECURITY & OBSCURE MODULE
# ====================================================================

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


def generate_comprehensive_analytics_dashboard(ip_counter, protocol_counter, username_counter, password_counter, command_attempts, file_artifacts):
    if not MATPLOTLIB_AVAILABLE:
        return False, "[!] Matplotlib is not installed."
    
    fig, axes = plt.subplots(2, 4, figsize=(22, 11))
    
    # 1. Top 10 Talkers
    top_10 = sorted(ip_counter.items(), key=lambda x: (-x[1], x[0]))[:10]
    if top_10:
        ips, hits = zip(*top_10)
        axes[0, 0].pie(hits, labels=ips, autopct='%1.1f%%', startangle=140)
        axes[0, 0].set_title('Top 10 Talkers')
    else:
        axes[0, 0].text(0.5, 0.5, 'No Data', ha='center', va='center')
        axes[0, 0].set_title('Top 10 Talkers')
        
    # 2. Least 10 Talkers
    least_10 = sorted(ip_counter.items(), key=lambda x: (x[1], x[0]))[:10]
    if least_10:
        l_ips, l_hits = zip(*least_10)
        axes[0, 1].pie(l_hits, labels=l_ips, autopct='%1.1f%%', startangle=140)
        axes[0, 1].set_title('Least 10 Talkers')
    else:
        axes[0, 1].text(0.5, 0.5, 'No Data', ha='center', va='center')
        axes[0, 1].set_title('Least 10 Talkers')
        
    # 3. Protocols (Separate)
    proto_data = protocol_counter.most_common(10)
    if proto_data:
        p_labels, p_vals = zip(*proto_data)
        axes[0, 2].pie(p_vals, labels=p_labels, autopct='%1.1f%%', startangle=140)
        axes[0, 2].set_title('Protocols Distribution')
    else:
        axes[0, 2].text(0.5, 0.5, 'No Protocol Data', ha='center', va='center')
        axes[0, 2].set_title('Protocols Distribution')

    # 4. Unique IP Addresses Distribution (Separate: single-hit vs multi-hit distribution)
    single_hits = sum(1 for ip, count in ip_counter.items() if count == 1)
    multi_hits = len(ip_counter) - single_hits
    unique_ip_data = {'Single-Hit IPs': single_hits, 'Multi-Hit IPs': multi_hits}
    if sum(unique_ip_data.values()) > 0:
        u_labels, u_vals = zip(*unique_ip_data.items())
        axes[0, 3].pie(u_vals, labels=u_labels, autopct='%1.1f%%', startangle=140)
        axes[0, 3].set_title('Unique IP Hit Frequency')
    else:
        axes[0, 3].text(0.5, 0.5, 'No Unique IP Data', ha='center', va='center')
        axes[0, 3].set_title('Unique IP Hit Frequency')
        
    # 5. Cowrie Usernames
    user_data = username_counter.most_common(10)
    if user_data:
        u_labels, u_vals = zip(*user_data)
        u_short = [(l[:15] + '...') if len(l) > 15 else l for l in u_labels]
        axes[1, 0].pie(u_vals, labels=u_short, autopct='%1.1f%%', startangle=140)
        axes[1, 0].set_title('Cowrie Usernames')
    else:
        axes[1, 0].text(0.5, 0.5, 'No Username Data', ha='center', va='center')
        axes[1, 0].set_title('Cowrie Usernames')
        
    # 6. Cowrie Passwords
    pwd_data = password_counter.most_common(10)
    if pwd_data:
        pw_labels, pw_vals = zip(*pwd_data)
        pw_short = [(l[:15] + '...') if len(l) > 15 else l for l in pw_labels]
        axes[1, 1].pie(pw_vals, labels=pw_short, autopct='%1.1f%%', startangle=140)
        axes[1, 1].set_title('Cowrie Passwords')
    else:
        axes[1, 1].text(0.5, 0.5, 'No Password Data', ha='center', va='center')
        axes[1, 1].set_title('Cowrie Passwords')
        
    # 7. Summary Metrics Panel (Bottom Right)
    ax_summary = axes[1, 2]
    ax_summary.axis('off')
    summary_str = (
        "Honeypot_Omaha Analytics Summary\n"
        "---------------------------------------\n"
        f"Total Unique IPs : {len(ip_counter)}\n"
        f"Total Commands   : {len(command_attempts)}\n"
        f"File Artifacts   : {len(file_artifacts)}\n"
        f"Top Talker IP    : {top_10[0][0] if top_10 else 'N/A'}"
    )
    ax_summary.text(0.05, 0.5, summary_str, fontsize=11, family='monospace', 
                    bbox=dict(boxstyle='round,pad=1', facecolor='#1e1e2d', edgecolor='#00ffcc', alpha=0.9),
                    color='#00ffcc', verticalalignment='center')
    ax_summary.set_title('Analytics Summary Panel')

    # Unused slot 8 cleanup
    axes[1, 3].axis('off')

    plt.suptitle('Honeypot_Omaha Dynamic Visual Analytics Dashboard', fontsize=16, color='#222')
    plt.tight_layout()
    plt.savefig('comprehensive_analytics_dashboard.png')
    plt.close()
    return True, 'comprehensive_analytics_dashboard.png'


def generate_ip_specific_pie_charts(ip, usernames_counter, passwords_counter):
    if not MATPLOTLIB_AVAILABLE:
        return False, "[!] Matplotlib is not installed."
    
    generated_files = []
    if usernames_counter:
        plt.figure(figsize=(8, 6))
        u_labels, u_vals = zip(*usernames_counter.most_common(10))
        plt.pie(u_vals, labels=u_labels, autopct='%1.1f%%', startangle=140)
        plt.title(f'Honeypot_Omaha: Usernames for IP {ip}')
        plt.tight_layout()
        fname_u = f'ip_{ip.replace(".", "_")}_usernames_pie_chart.png'
        plt.savefig(fname_u)
        plt.close()
        generated_files.append(fname_u)
        
    if passwords_counter:
        plt.figure(figsize=(8, 6))
        pw_labels, pw_vals = zip(*passwords_counter.most_common(10))
        pw_labels_short = [(lbl[:20] + '...') if len(lbl) > 20 else lbl for lbl in pw_labels]
        plt.pie(pw_vals, labels=pw_labels_short, autopct='%1.1f%%', startangle=140)
        plt.title(f'Honeypot_Omaha: Passwords for IP {ip}')
        plt.tight_layout()
        fname_p = f'ip_{ip.replace(".", "_")}_passwords_pie_chart.png'
        plt.savefig(fname_p)
        plt.close()
        generated_files.append(fname_p)
        
    return True, generated_files


class HoneypotGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Honeypot_Omaha Enterprise Security & Analytics Suite")
        self.resize(1200, 800)
        
        self.ip_counter = Counter()
        self.endpoint_counter = Counter()
        self.endpoint_timestamps = {}
        self.endpoint_statuses = {}
        self.ip_time_ranges = {}
        self.ip_targeted_endpoints = {}
        self.credential_attempts = []
        self.command_attempts = []
        self.ip_network_details = {}
        self.file_artifacts = []
        self.cowrie_event_records = []
        self.username_counter = Counter()
        self.password_counter = Counter()
        self.protocol_counter = Counter()
        self.ip_username_map = defaultdict(Counter)
        self.ip_password_map = defaultdict(Counter)
        
        self.report_name = 'honeypot_omaha_summary_report.txt'
        self.cve_report_name = 'honeypot_omaha_cve_summary_report.txt'
        self.last_queried_ip = None
        self.last_queried_usernames = Counter()
        self.last_queried_passwords = Counter()
        
        # Zoom state variables for Tab 4 charts
        self.chart_scale_factor = 1.0
        self.current_dashboard_pixmap = None
        
        self.run_pipeline_data()
        self.init_ui()

    def run_pipeline_data(self):
        json_files = glob.glob('webhoneypot_*.json') + glob.glob('cowrie.json*')
        log_files = glob.glob('*.log') + glob.glob('webhoneypot_*.log') + glob.glob('cowrie.log')
        all_files = list(set(json_files + log_files))

        for file_path in all_files:
            is_json = file_path.endswith('.json')
            tsv_file = file_path.replace('.json', '_import.tsv').replace('.log', '_import.tsv')

            try:
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

                            self.ip_counter[ip] += attempts
                            self.endpoint_counter[method_url] += attempts

                            if ip not in self.ip_targeted_endpoints:
                                self.ip_targeted_endpoints[ip] = set()
                            self.ip_targeted_endpoints[ip].add(method_url)

                            if ip not in self.ip_network_details:
                                self.ip_network_details[ip] = {'src_ports': set(), 'dst_ports': set(), 'protocols': {'HTTP'}, 'sessions': set()}

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

                                    self.cowrie_event_records.append({
                                        'timestamp': timestamp, 'session': session, 'src_ip': ip,
                                        'src_port': src_port, 'dst_ip': dst_ip, 'dst_port': dst_port,
                                        'protocol': protocol, 'eventid': evid, 'username': username,
                                        'password': password, 'message': message
                                    })

                                    if protocol != 'unknown':
                                        self.protocol_counter[protocol.upper()] += 1
                                    if username != 'N/A':
                                        self.username_counter[username] += 1
                                        self.ip_username_map[username][ip] += 1
                                    if password != 'N/A':
                                        self.password_counter[password] += 1
                                        self.ip_password_map[password][ip] += 1

                                    if username != 'N/A' or password != 'N/A':
                                        self.credential_attempts.append({
                                            'session': session, 'timestamp': timestamp, 'src_ip': ip,
                                            'username': username, 'password': password, 'status': status_str
                                        })
                                    if 'command' in evid.lower() or 'input' in data:
                                        cmd = data.get('input') or data.get('command')
                                        if cmd:
                                            self.command_attempts.append({
                                                'session': session, 'timestamp': timestamp, 'src_ip': ip, 'command': cmd
                                            })
                                            for ext in ['.exe', '.elf', '.pdf', '.png', '.mime', '.html']:
                                                if ext in cmd.lower():
                                                    self.file_artifacts.append({
                                                        'type': ext.upper().replace('.', ''), 'name': cmd, 'src_ip': ip, 'session': session
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
                                            self.file_artifacts.append({
                                                'type': ext.upper().replace('.', ''), 'name': url, 'src_ip': ip, 'session': session
                                            })
                                    f_out.write(f"{timestamp}\t{ip}\t{method_url}\t{attempts}\n")

                                self.ip_counter[ip] += attempts
                                self.endpoint_counter[method_url] += attempts

                                if ip not in self.ip_targeted_endpoints:
                                    self.ip_targeted_endpoints[ip] = set()
                                self.ip_targeted_endpoints[ip].add(method_url)
                                if ip not in self.ip_network_details:
                                    self.ip_network_details[ip] = {'src_ports': set(), 'dst_ports': set(), 'protocols': set(), 'sessions': set()}

                                if src_port:
                                    self.ip_network_details[ip]['src_ports'].add(src_port)
                                if dst_port:
                                    self.ip_network_details[ip]['dst_ports'].add(dst_port)
                                if protocol and protocol != 'unknown':
                                    self.ip_network_details[ip]['protocols'].add(protocol.upper())
                                else:
                                    self.ip_network_details[ip]['protocols'].add('HTTP')
                                if session and session != 'N/A':
                                    self.ip_network_details[ip]['sessions'].add(session)

                                if method_url not in self.endpoint_timestamps:
                                    self.endpoint_timestamps[method_url] = timestamp
                                    self.endpoint_statuses[method_url] = status_str

                                if timestamp != 'N/A':
                                    if ip not in self.ip_time_ranges:
                                        self.ip_time_ranges[ip] = {'start': timestamp, 'end': timestamp}
                                    else:
                                        if timestamp < self.ip_time_ranges[ip]['start']:
                                            self.ip_time_ranges[ip]['start'] = timestamp
                                        if timestamp > self.ip_time_ranges[ip]['end']:
                                            self.ip_time_ranges[ip]['end'] = timestamp
                            except Exception:
                                continue
            except Exception:
                pass

        with open(self.report_name, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write("Honeypot_Omaha SUMMARY REPORT\n")
            f.write("="*60 + "\n\n")
            f.write("--- FILE ARTIFACTS FOUND (.EXE, .ELF, .PDF, .PNG, .MIME, .HTML) ---\n")
            for fa in self.file_artifacts:
                f.write(f"Type: {fa['type']} | Artifact: {fa['name']} | IP: {fa['src_ip']} | Session: {fa['session']}\n")
            f.write("\n")

        with open(self.cve_report_name, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write("Honeypot_Omaha CVE, MITRE & EXPLOITS REPORT (Sorted by Score)\n")
            f.write("="*60 + "\n\n")
            sorted_endpoints_cve = sorted(
                self.endpoint_counter.items(),
                key=lambda x: get_threat_intel_mapping(x[0])['score_val'],
                reverse=True
            )
            for endpoint, count in sorted_endpoints_cve:
                intel = get_threat_intel_mapping(endpoint)
                status_str = self.endpoint_statuses.get(endpoint, '200 OK')
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

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        sidebar = QWidget()
        sidebar.setMinimumWidth(200)
        sidebar.setStyleSheet("background-color: #1e1e2d; color: #ffffff;")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(10, 10, 10, 10)
        sidebar_layout.setSpacing(10)
        
        title_label = QLabel("Honeypot_Omaha\nEnterprise Suite")
        title_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("padding: 10px; color: #00ffcc;")
        sidebar_layout.addWidget(title_label)
        
        nav_btn_style = """
            QPushButton {
                background-color: #2d2d3f;
                color: #ffffff;
                text-align: left;
                padding: 12px 15px;
                border: none;
                border-radius: 4px;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3d3d5f;
            }
            QPushButton:checked {
                background-color: #00ffcc;
                color: #1e1e2d;
            }
        """
        
        self.btn_nav1 = QPushButton("1. Quick Console Overview")
        self.btn_nav2 = QPushButton("2. Standard Summary Report")
        self.btn_nav3 = QPushButton("3. CVE, MITRE & Exploits Report")
        self.btn_nav4 = QPushButton("4. Visual Analytics & charts")
        self.btn_nav5 = QPushButton("5. Search / Query Data by IP or FQDN")
        
        self.nav_buttons = [self.btn_nav1, self.btn_nav2, self.btn_nav3, self.btn_nav4, self.btn_nav5]
        
        for idx, btn in enumerate(self.nav_buttons):
            btn.setStyleSheet(nav_btn_style)
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, index=idx: self.display_page(index))
            sidebar_layout.addWidget(btn)
            
        sidebar_layout.addStretch()
        
        exit_btn = QPushButton("EXIT Application")
        exit_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff4d4d;
                color: white;
                font-weight: bold;
                padding: 12px;
                border: none;
                border-radius: 4px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #ff3333;
            }
        """)
        exit_btn.clicked.connect(self.close)
        sidebar_layout.addWidget(exit_btn)
        
        self.stack = QStackedWidget()
        self.stack.setStyleSheet("background-color: #12121a; color: #ffffff;")
        
        self.page_overview = self.create_overview_page()
        self.page_summary = self.create_report_page(self.report_name)
        self.page_cve = self.create_report_page(self.cve_report_name)
        self.page_charts = self.create_charts_page()
        self.page_query = self.create_query_page()
        
        self.stack.addWidget(self.page_overview)
        self.stack.addWidget(self.page_summary)
        self.stack.addWidget(self.page_cve)
        self.stack.addWidget(self.page_charts)
        self.stack.addWidget(self.page_query)
        
        splitter.addWidget(sidebar)
        splitter.addWidget(self.stack)
        splitter.setSizes([280, 920])
        
        main_layout.addWidget(splitter)
        self.display_page(0)

    def display_page(self, index):
        self.stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(i == index)
            
        if index == 3:
            self.trigger_chart_generation()
        elif index == 1:
            self.refresh_report_page(self.page_summary, self.report_name)
        elif index == 2:
            self.refresh_report_page(self.page_cve, self.cve_report_name)

    def refresh_report_page(self, page_widget, filename):
        text_area = page_widget.findChild(QTextEdit)
        if text_area and os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                text_area.setText(f.read())

    def create_overview_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        header = QLabel("Quick Console Overview Summary")
        header.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ffcc; margin-bottom: 10px;")
        layout.addWidget(header)
        
        text_area = QTextEdit()
        text_area.setReadOnly(True)
        
        overview_text = "="*60 + "\n"
        overview_text += "Honeypot_Omaha QUICK CONSOLE OVERVIEW SUMMARY\n"
        overview_text += "="*60 + "\n"
        overview_text += f"[*] Total Unique Tracked IPs : {len(self.ip_counter)}\n"
        overview_text += f"[*] Total Commands Captured  : {len(self.command_attempts)}\n"
        overview_text += f"[*] Total File Artifacts Found: {len(self.file_artifacts)}\n\n"

        overview_text += "--- Top 5 IP Talkers ---\n"
        for ip, hits in self.ip_counter.most_common(5):
            overview_text += f"  - IP: {ip:<16} Hits: {hits}\n"
            
        overview_text += "\n--- Top Protocols Used ---\n"
        for proto, count in self.protocol_counter.most_common(5):
            overview_text += f"  - Protocol: {proto:<10} Count: {count}\n"
            
        overview_text += "\n--- Discovered File Artifacts (.exe, .elf, .pdf, .png, .mime, .html) ---\n"
        if self.file_artifacts:
            for art in list(self.file_artifacts)[:10]:
                overview_text += f"  - [{art['type']}] {art['name']} (IP: {art['src_ip']})\n"
        else:
            overview_text += "  - No specialized binary or document artifacts extracted in this run.\n"
        overview_text += "="*60 + "\n"
        
        text_area.setText(overview_text)
        layout.addWidget(text_area)
        return page

    def create_report_page(self, filename):
        page = QWidget()
        layout = QVBoxLayout(page)
        header = QLabel(f"Report: {filename}")
        header.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ffcc; margin-bottom: 10px;")
        layout.addWidget(header)
        
        text_area = QTextEdit()
        text_area.setReadOnly(True)
        text_area.setStyleSheet("background-color: #1a1a24; color: #e0e0e0; font-family: Courier, monospace; font-size: 13px; border: 1px solid #333;")
        
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                text_area.setText(f.read())
        else:
            text_area.setText("[!] Report file not found.")
            
        layout.addWidget(text_area)
        return page

    def create_charts_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        header = QLabel("Visual Analytics & charts")
        header.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ffcc; margin-bottom: 10px;")
        layout.addWidget(header)
        
        btn_layout = QHBoxLayout()
        generate_btn = QPushButton("Generate & Refresh Comprehensive Dashboard")
        generate_btn.setStyleSheet("background-color: #00ffcc; color: #1e1e2d; font-weight: bold; padding: 10px; border-radius: 4px;")
        generate_btn.clicked.connect(self.trigger_chart_generation)
        btn_layout.addWidget(generate_btn)
        
        # User zoom controls for Tab 4 charts
        zoom_in_btn = QPushButton("Zoom In (+)")
        zoom_in_btn.setStyleSheet("background-color: #2d2d3f; color: #00ffcc; font-weight: bold; padding: 10px; border-radius: 4px;")
        zoom_in_btn.clicked.connect(self.zoom_in_chart)
        btn_layout.addWidget(zoom_in_btn)
        
        zoom_out_btn = QPushButton("Zoom Out (-)")
        zoom_out_btn.setStyleSheet("background-color: #2d2d3f; color: #00ffcc; font-weight: bold; padding: 10px; border-radius: 4px;")
        zoom_out_btn.clicked.connect(self.zoom_out_chart)
        btn_layout.addWidget(zoom_out_btn)

        reset_zoom_btn = QPushButton("Reset Zoom")
        reset_zoom_btn.setStyleSheet("background-color: #2d2d3f; color: #00ffcc; font-weight: bold; padding: 10px; border-radius: 4px;")
        reset_zoom_btn.clicked.connect(self.reset_zoom_chart)
        btn_layout.addWidget(reset_zoom_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background: transparent; border: none;")
        
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        
        self.lbl_chart_dashboard = QLabel("Dashboard will generate automatically upon clicking tab 4.")
        self.lbl_chart_dashboard.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_chart_dashboard.setStyleSheet("color: #aaa; font-size: 14px; margin: 10px;")
        content_layout.addWidget(self.lbl_chart_dashboard)
        
        scroll.setWidget(content_widget)
        layout.addWidget(scroll)
        return page

    def trigger_chart_generation(self):
        success, res = generate_comprehensive_analytics_dashboard(
            self.ip_counter, self.protocol_counter, self.username_counter, 
            self.password_counter, self.command_attempts, self.file_artifacts
        )
        if success and os.path.exists(res):
            self.current_dashboard_pixmap = QPixmap(res)
            self.chart_scale_factor = 1.0
            self.update_chart_display()

    def update_chart_display(self):
        if self.current_dashboard_pixmap and not self.current_dashboard_pixmap.isNull():
            base_w = 1100
            base_h = 700
            scaled_w = int(base_w * self.chart_scale_factor)
            scaled_h = int(base_h * self.chart_scale_factor)
            pixmap = self.current_dashboard_pixmap.scaled(scaled_w, scaled_h, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            self.lbl_chart_dashboard.setPixmap(pixmap)

    def zoom_in_chart(self):
        if self.current_dashboard_pixmap:
            self.chart_scale_factor = min(self.chart_scale_factor * 1.25, 3.0)
            self.update_chart_display()

    def zoom_out_chart(self):
        if self.current_dashboard_pixmap:
            self.chart_scale_factor = max(self.chart_scale_factor / 1.25, 0.5)
            self.update_chart_display()

    def reset_zoom_chart(self):
        if self.current_dashboard_pixmap:
            self.chart_scale_factor = 1.0
            self.update_chart_display()

    def create_query_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        header = QLabel("Search / Query Data by IP or FQDN")
        header.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        header.setStyleSheet("color: #00ffcc; margin-bottom: 10px;")
        layout.addWidget(header)
        
        input_layout = QHBoxLayout()
        self.query_input = QLineEdit()
        self.query_input.setPlaceholderText("Enter IP address or FQDN (e.g., 92.118.39.71 or www.xyz.com)")
        self.query_input.setStyleSheet("padding: 8px; font-size: 13px; background-color: #1a1a24; color: #fff; border: 1px solid #444;")
        input_layout.addWidget(self.query_input)
        
        query_btn = QPushButton("Run Query")
        query_btn.setStyleSheet("background-color: #00ffcc; color: #1e1e2d; font-weight: bold; padding: 8px 16px; border-radius: 4px;")
        query_btn.clicked.connect(self.execute_user_query)
        input_layout.addWidget(query_btn)
        layout.addLayout(input_layout)
        
        ip_chart_btn_layout = QHBoxLayout()
        self.btn_ip_user_chart = QPushButton("Generate Username Pie Chart for Queried IP")
        self.btn_ip_user_chart.setStyleSheet("background-color: #2d2d3f; color: #00ffcc; font-weight: bold; padding: 6px 12px; border-radius: 4px;")
        self.btn_ip_user_chart.setEnabled(False)
        self.btn_ip_user_chart.clicked.connect(self.generate_queried_ip_user_chart)
        ip_chart_btn_layout.addWidget(self.btn_ip_user_chart)

        self.btn_ip_pwd_chart = QPushButton("Generate Password Pie Chart for Queried IP")
        self.btn_ip_pwd_chart.setStyleSheet("background-color: #2d2d3f; color: #00ffcc; font-weight: bold; padding: 6px 12px; border-radius: 4px;")
        self.btn_ip_pwd_chart.setEnabled(False)
        self.btn_ip_pwd_chart.clicked.connect(self.generate_queried_ip_pwd_chart)
        ip_chart_btn_layout.addWidget(self.btn_ip_pwd_chart)
        
        ip_chart_btn_layout.addStretch()
        layout.addLayout(ip_chart_btn_layout)
        
        self.query_output = QTextBrowser()
        self.query_output.setReadOnly(True)
        self.query_output.setOpenExternalLinks(True)
        self.query_output.setStyleSheet("""
            background-color: #1a1a24; 
            color: #00ffcc; 
            font-family: Courier, monospace; 
            font-size: 13px; 
            border: 1px solid #333;
        """)
        layout.addWidget(self.query_output)
        return page

    def generate_queried_ip_user_chart(self):
        if not self.last_queried_ip:
            return
        success, res = generate_ip_specific_pie_charts(self.last_queried_ip, self.last_queried_usernames, Counter())
        if success and res:
            open_chart_application(res[0])

    def generate_queried_ip_pwd_chart(self):
        if not self.last_queried_ip:
            return
        success, res = generate_ip_specific_pie_charts(self.last_queried_ip, Counter(), self.last_queried_passwords)
        if success and res:
            open_chart_application(res[0])

    def execute_user_query(self):
        user_query = self.query_input.text().strip()
        ip_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
        fqdn_pattern = r'^(?=.{1,253}$)(?!\-)[A-Za-z0-9\-]{1,63}(\.[A-Za-z0-9\-]{1,63})+$'
        is_ip = bool(re.match(ip_pattern, user_query))
        is_fqdn = bool(re.match(fqdn_pattern, user_query))
        if not is_ip and not is_fqdn:
            self.query_output.setText(f"[!] Invalid input format: '{user_query}'. Please enter a valid IPv4 address or FQDN.")
            self.btn_ip_user_chart.setEnabled(False)
            self.btn_ip_pwd_chart.setEnabled(False)
            self.last_queried_ip = None
            return

        query_report_file = 'honeypot_omaha_query_report.txt'
        with open(query_report_file, 'w', encoding='utf-8') as f_out:
            found_matches = False
            if is_ip:
                if user_query in self.ip_counter or user_query in self.ip_network_details:
                    found_matches = True
                    hits = self.ip_counter.get(user_query, 1)
                    timerange = self.ip_time_ranges.get(user_query, {'start': 'N/A', 'end': 'N/A'})
                    country, org = get_ip_intel(user_query)
                    net_info = self.ip_network_details.get(user_query, {'src_ports': set(), 'dst_ports': set(), 'protocols': set(), 'sessions': set()})
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

                    ip_creds = [c for c in self.credential_attempts if c.get('ip') == user_query or c.get('src_ip') == user_query or user_query in c.get('endpoint', '')]
                    unique_usernames = list(set([c.get('username') for c in ip_creds if c.get('username')]))
                    unique_passwords = list(set([c.get('password') for c in ip_creds if c.get('password')]))

                    self.last_queried_ip = user_query
                    self.last_queried_usernames = Counter()
                    self.last_queried_passwords = Counter()
                    for ev in self.cowrie_event_records:
                        if ev['src_ip'] == user_query:
                            if ev.get('username') and ev['username'] != 'N/A':
                                self.last_queried_usernames[ev['username']] += 1
                            if ev.get('password') and ev['password'] != 'N/A':
                                self.last_queried_passwords[ev['password']] += 1

                    self.btn_ip_user_chart.setEnabled(bool(self.last_queried_usernames))
                    self.btn_ip_pwd_chart.setEnabled(bool(self.last_queried_passwords))

                    total_attempts = self.ip_counter.get(user_query, 0)
                    is_brute_forcer = total_attempts > 20 or len(ip_creds) > 5
                    actor_behavior_tag = "[!] HIGH-VELOCITY BRUTE-FORCE ACTOR" if is_brute_forcer else "[*] Standard Scanning / Reconnaissance"

                    f_out.write(f"Actor Behavioral Profile   : {actor_behavior_tag}\n")
                    f_out.write(f"Total Attack Velocity      : {total_attempts} total requests logged\n")

                    if ip_creds:
                        f_out.write(f"[+] Brute-Force Credentials Harvested:\n")
                        f_out.write(f"    - Unique Usernames Tried ({len(unique_usernames)}) : {', '.join(unique_usernames[:10])}\n")
                        f_out.write(f"    - Unique Passwords Tried ({len(unique_passwords)}) : {', '.join(unique_passwords[:10])}\n")
                    else:
                        f_out.write(f"[+] Brute-Force Credentials: No explicit login credentials captured for this target.\n")
                    f_out.write("-" * 75 + "\n\n")

                    matching_cowrie_events = [ev for ev in self.cowrie_event_records if ev['src_ip'] == user_query]
                    if matching_cowrie_events:
                        matching_cowrie_events.sort(key=lambda x: x['timestamp'] if x['timestamp'] != 'N/A' else '')
                        session_cred_map = {}
                        for ev in self.cowrie_event_records:
                            if ev['session'] and ev['session'] != 'N/A':
                                if ev['username'] != 'N/A' or ev['password'] != 'N/A':
                                    session_cred_map[ev['session']] = {'username': ev['username'], 'password': ev['password']}
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
                            f_out.write(f"  - username               : {curr_user}\n")
                            f_out.write(f"  - password               : {curr_pwd}\n")
                            f_out.write(f"  - session id             : {ev['session']}\n")
                            f_out.write(f"  - UTC timestamp          : {ev['timestamp']}\n")
                            f_out.write(f"  - src ip                 : {ev['src_ip']}\n")
                            f_out.write(f"  - src port               : {ev['src_port']}\n")
                            f_out.write(f"  - dst ip                 : {ev['dst_ip']}\n")
                            f_out.write(f"  - dst port               : {ev['dst_port']} {'(Target Port 2222/2223 Honeypot Listener)' if ev['dst_port'] in [2222, 2223] else ''}\n")
                            f_out.write(f"  - message                : {ev['message']}\n")
                            f_out.write(f"  - eventid                : {ev['eventid']}\n")
                            f_out.write("  " + "-" * 60 + "\n")
                        f_out.write("\n")
                    else:
                        f_out.write("Cowrie Chronological Logs  : No matching Cowrie session records found for this IP on ports 2222/2223.\n\n")

                    targeted_eps = self.ip_targeted_endpoints.get(user_query, set())
                    if targeted_eps:
                        sorted_targeted_eps = sorted(targeted_eps, key=lambda ep: self.endpoint_timestamps.get(ep, ''), reverse=False)
                        f_out.write(f"Targeted Endpoints, Methods (GET/POST), Status Codes & CVE Threat Level (Sorted by Highest Score):\n")
                        f_out.write("=" * 75 + "\n")
                        for idx, ep in enumerate(sorted_targeted_eps, 1):
                            endpoint_log_time = self.endpoint_timestamps.get(ep, 'N/A')
                            intel = get_threat_intel_mapping(ep)
                            status_code = self.endpoint_statuses.get(ep, '200 OK')
                            f_out.write(f"  {idx}. Endpoint / Protocol : {ep}\n")
                            f_out.write(f"    Timestamp             : {endpoint_log_time}\n")
                            f_out.write(f"    HTTP Status Code      : {status_code}\n")
                            f_out.write(f"    CVE Reference         : {intel['cve']}\n")
                            f_out.write(f"    Threat Rating Score   : {intel['score_str']}\n")
                            f_out.write(f"    MITRE ATT&CK          : {intel['mitre']}\n")
                            f_out.write(f"    Exploit Used          : {intel['exploit']}\n")
                            f_out.write(f"    Threat Intention      : {intel['intention']}\n")
                            f_out.write(f"    Mitigation            : {intel['mitigation']}\n")
                            f_out.write(f"    " + "-"*45 + "\n")

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
                self.btn_ip_user_chart.setEnabled(False)
                self.btn_ip_pwd_chart.setEnabled(False)

        if not found_matches and (is_ip or is_fqdn):
            f_out.write(f"[!] No matching records were discovered for '{user_query}'.\n")
            self.btn_ip_user_chart.setEnabled(False)
            self.btn_ip_pwd_chart.setEnabled(False)

        if os.path.exists(query_report_file):
            with open(query_report_file, 'r', encoding='utf-8', errors='ignore') as f:
                raw_text = f.read()
                html_text = f"<pre style='font-family: Courier, monospace; color: #00ffcc; white-space: pre-wrap; word-wrap: break-word;'>{raw_text}</pre>"
                url_pattern = re.compile(r'(https?://[^\s]+)')
                html_text = url_pattern.sub(r'<a href="\1" style="color: #00ffff; text-decoration: underline;">\1</a>', html_text)
                self.query_output.setHtml(html_text)
        else:
            self.query_output.setText("[!] Query report file not generated.")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = HoneypotGUI()
    window.show()
    sys.exit(app.exec())
