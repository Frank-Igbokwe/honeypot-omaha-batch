# Project Honeypot-Omaha: Automated Log Processing & Threat Intelligence Pipeline

![License: BSL](https://img.shields.io/badge/License-BSL-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20AWS-lightgrey)

Project Honeypot-Omaha is an automated pipeline designed to aggregate, parse, and analyze threat telemetry and log data (optimized for Cowrie SSH/Telnet honeypots and DShield sensors). Whether you prefer working strictly from the terminal or managing your data through a clean graphical interface, this repository provides the tools you need.

## 📺 See It in Action (GUI Demo)

Watch the 7-minute walkthrough below to see how the GUI version simplifies log correlation, indicator extraction, and visualization:

[![Watch the Honeypot-Omaha GUI Demo](https://img.shields.io/badge/Watch-YouTube%20GUI%20Demo-red?style=for-the-badge&logo=youtube)](https://www.youtube.com/channel/UCFf9YseKE2HvkzCkWM-rhVA)

*(Or click the thumbnail above to open the video on YouTube)*

## 📂 Repository Structure

```
Honeypot_Omaha/
├── cli/
│   └── batch.py        # Automated command-line log aggregation & parsing script
├── gui/
│   ├── app.py          # Graphical User Interface application files
│   └── assets/         # UI styling and static resources
├── README.md
└── LICENSE
```
Building and deploying the "Honeypot-Omaha" DShield sensor during my undergraduate practicum with the SANS Internet Storm Center was an incredible deep-dive into live production threat hunting.
One of the biggest operational bottlenecks I ran into was parsing massive, unstructured volumes of raw sensor logs. Filtering out the background noise of the internet manually is slow, so I built a custom automation pipeline in Python to solve it: batch.py.
Because I want to support the broader security community and help fellow analysts optimize their data ingestion pipelines, I’ve made batch.py available for the ISC ecosystem. Check out the repository and let me know your thoughts or how you're tackling log automation in your own environments! 👇

#CyberSecurity #ThreatIntelligence #SourceAvailable #Python #IncidentResponse #SANS #DShield

## Pipeline Architecture & Workflow

The Honeypot-Omaha pipeline automates the ingestion, parsing, and correlation of telemetry gathered from your cloud-deployed sensors:
* **Telemetry Inception:** Cowrie SSH/Telnet honeypots and DShield sensors capture raw malicious connection attempts, authentication payloads, and command histories in the cloud environment.
* **Automated Parsing (batch.py):** The Python processing script ingests raw log exports, normalizes JSON attributes, and filters out noise.
* **IoC Extraction & Correlation:** The engine correlates IP addresses, credentials, and command execution patterns against known threat indicators.
* **Reporting & Output:** Processed data is structured into clean TSV/CSV datasets and exported for deeper analysis, Google Sheets reporting, or submission to the SANS Internet Storm Center.

## Features

* **Automated Bulk Log Parsing:** Quickly process large volumes of unstructured connection logs.
* **Event Aggregation:** Correlates disparate connection events to isolate high-priority anomalies.
* **IoC Extraction:** Isolate malicious source IPs, targeted ports, and high-frequency scan patterns.
* **Structured Output:** Export clean datasets for further analysis or reporting.
* **Data Transformation:** Transforms raw data into clean, structured datasets to drastically reduce analysis time.

## Prerequisites

* Python 3.8 or higher
* This tool is designed for Linux environments (or via WSL on Windows).

## Installation

```bash
git clone https://github.com/Frank-Igbokwe/honeypot-omaha-batch.git
cd honeypot-omaha-batch/cli
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

🚀 Quick Start

The command-line tool processes raw log exports, extracts Indicators of Compromise (IOCs), and formats outputs for easy review.
- Run the pipeline against your raw log directory by specifying the input path:

## In the same folder
```bash
 sudo python3 batch.py
```
## Specify a path and output format
```bash
python3 batch.py --input /path/to/raw/logs --output results.csv
```


For users who prefer a graphical workflow, navigate to the gui/ directory and follow the setup instructions in the GUI documentation to launch the dashboard.

🤝 Contributing & Feedback
Contributions, feature requests, and bug reports are welcome! Please feel free to open a GitHub Issue or submit a pull request.

## 💡 Support This Project

If Project Honeypot-Omaha has helped you streamline your log analysis, secure your environment, or save time during threat hunting, consider supporting its ongoing development:

* ** ⭐ Star this repository on GitHub to help others discover it!
* ** [GitHub Sponsors](https://github.com/sponsors/Frank-Igbokwe)** (Best for backing long-term open-source maintenance)
* ** ☕ Buy Me a Coffee(https://buymeacoffee.com/Frank-Igbokwe)** (Great for quick, one-time contributions)

Your support helps keep open-source security tools free, transparent, and actively updated for the analyst community!


## 📜 License

This project is licensed under the Business Source License 1.1 (BSL-1.1). See the LICENSE file for details.
Copyright (c) 2026 Frank Ngoka Igbokwe.





