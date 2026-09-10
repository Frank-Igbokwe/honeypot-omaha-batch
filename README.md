# "batch.py": Honeypot_Omaha unified analysis processing pipeline
# Honeypot Log Automation, correlation, and IoC Extraction Pipeline

A lightweight, automated Python pipeline designed to ingest, parse, and extract critical Indicators of Compromise (IoCs) from raw honeypot and DShield sensor logs. 

Building and deploying the "Honeypot-Omaha" DShield sensor during my undergraduate practicum with the SANS Internet Storm Center was an incredible deep-dive into live production threat hunting.

One of the biggest operational bottlenecks I ran into was parsing massive, unstructured volumes of raw sensor logs. Filtering out the background noise of the internet manually is slow, so I built a custom automation pipeline in Python to solve it: `batch.py`.

Because I want to support the broader security community and help fellow analysts optimize their data ingestion pipelines, I’ve made `batch.py` available for the ISC ecosystem. Check out the repository and

let me know your thoughts or how you're tackling log automation in your own environments! 👇


#CyberSecurity #ThreatIntelligence #SourceAvailable #Python #IncidentResponse #SANS #DShield


## Pipeline Architecture & Workflow

The Honeypot-Omaha pipeline automates the ingestion, parsing, and correlation of telemetry gathered from your cloud-deployed sensors:

1. **Telemetry Inception:** Cowrie SSH/Telnet honeypots and DShield sensors capture raw malicious connection attempts, authentication payloads, and command histories in the cloud environment.
2. **Automated Parsing (`batch.py`):** The Python processing script ingests raw log exports, normalizes JSON attributes, and filters out noise.
3. **IoC Extraction & Correlation:** The engine correlates IP addresses, credentials, and command execution patterns against known threat indicators.
4. **Reporting & Output:** Processed data is structured into clean TSV/CSV datasets and exported for deeper analysis, Google Sheets reporting, or submission to the SANS Internet Storm Center.


## Features

- **Automated Bulk Log Parsing:** Quickly process large volumes of unstructured connection logs.
- **Event Aggregation:** Correlates disparate connection events to isolate high-priority anomalies.
- **IoC Extraction:** Isolate malicious source IPs, targeted ports, and high-frequency scan patterns.
- **Structured Output:** Export clean datasets for further analysis or reporting.
- **Data Transformation:** Transforms raw data into clean, structured datasets to drastically reduce analysis time.

## Prerequisites

- Python 3.8 or higher
- This tool is designed for Linux environments (or via WSL on Windows).

## Installation

```bash
git clone https://github.com/Frank-Igbokwe/honeypot-omaha-batch.git
cd honeypot-omaha-batch
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

- Run the pipeline against your raw log directory by specifying the input path:

## In the same folder
```bash
 sudo python3 batch.py
```
## Specify a path and output format
```bash
python3 batch.py --input /path/to/raw/logs --output results.csv
```


## License

This project is licensed under the Business Source License 1.1 (BSL-1.1). See the LICENSE file for details.

Copyright (c) 2026 Frank Ngoka Igbokwe.
