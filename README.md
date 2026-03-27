# NIDA — Network Intrusion Detection Analyzer

## Project Overview

NIDA is a lightweight, rule-based network log analysis tool designed to assist analysts during the initial triage phase of a security investigation.

The system processes network connection logs, identifies suspicious behavioral patterns across source IPs, assigns weighted risk scores, and generates prioritized triage output via the CLI along with a risk score visualization.

This project is intended for academic demonstration purposes.

---

## Project Structure

```
NIDA/
│
├── logs/
│   └── network.log
├── output/              (empty before first run)
├── src/
│   ├── main.py
│   ├── parser.py
│   └── detector.py
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Features

- Network connection log parsing
- Port scan detection
- Brute force detection per destination port
- Breach detection (rejections followed by acceptance on same port)
- Sensitive port targeting detection
- Off-hours activity flagging (00:00–05:59)
- Data exfiltration hint detection (high bytes transferred)
- Velocity burst detection (high-frequency rejections within 60 seconds)
- Weighted risk scoring system
- Priority classification (LOW / MEDIUM / HIGH / CRITICAL)
- Explainable rule-based CLI output
- Risk score bar chart (saved as PNG)

---

## System Architecture

```
Network Connection Logs
↓
Log Parser (parser.py)
↓
Behavior Aggregation (per source IP)
↓
Rule-Based Scoring Engine (detector.py)
↓
Priority Classification
↓
Console Triage Report + Risk Score Graph (main.py)
```

---

## Log Format

Each line in `network.log` follows this format:

```
TIMESTAMP SRC_IP DST_IP DST_PORT PROTOCOL STATUS BYTES_SENT
```

Example:
```
2024-01-15 02:11:01 172.16.0.55 192.168.1.10 22 TCP REJECTED 0
```

Blank lines and lines starting with `#` are ignored.

---

## Scoring Model

| Rule | Condition | Score |
|------|-----------|-------|
| R1 | ≥ 10 distinct destination ports probed (port scan) | +3 |
| R2 | ≥ 5 REJECTED attempts to same port (brute force) | +3 |
| R3 | REJECTED attempts followed by ACCEPTED on same port (breach) | +2 |
| R4 | Connection to known sensitive port (22, 23, 3389, 445, etc.) | +1 per port |
| R5 | Activity between 00:00–05:59 (off-hours) | +1 |
| R6 | Total bytes sent > 500 KB via accepted connections (exfil hint) | +2 |
| R7 | ≥ 5 rejections within any 60-second window (velocity burst) | +2 |

Priority Mapping:

| Score | Priority |
|-------|----------|
| 0–1 | LOW |
| 2–3 | MEDIUM |
| 4–5 | HIGH |
| 6+ | CRITICAL |

---

## Technology Stack

- Python 3.11+
- `re` — log parsing
- `datetime` — timestamp handling and off-hours detection
- `collections` — per-IP behavior aggregation
- `matplotlib` — risk score visualization

---

## How to Run

Install dependencies:
```
pip install -r requirements.txt
```

From project root:
```
python src/main.py
```

Outputs:
- Console triage report (CLI)
- Risk score bar chart saved to `output/risk_scores.png`

---

## Design Note on Output Format

Output is intentionally CLI-first. DFIR analysts operate in terminal environments where output can be piped, redirected, or fed into downstream scripts. The PNG chart serves documentation and reporting purposes and is not part of the live triage workflow.

---

## Limitations

- Processes static log files only (no real-time ingestion)
- Rule-based detection — no machine learning or statistical modeling
- No packet payload inspection (connection metadata only)
- May produce false positives on high-traffic legitimate hosts
- Designed for academic demonstration

---

## Future Scope

- Real-time log ingestion via `tail -f` or syslog forwarding
- Time-window based correlation across multiple destination IPs
- Statistical baseline modeling to flag deviations from normal behavior
- GeoIP lookup for external source IP classification
- Integration with SIEM platforms (Splunk, Wazuh)
- SOC dashboard layer for non-technical stakeholder reporting
