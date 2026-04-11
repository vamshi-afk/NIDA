# NIDA — Network Intrusion Detection Analyzer

## Overview

NIDA is a lightweight, rule-based network log analysis tool designed for the initial triage phase of a security investigation.

It processes network connection logs captured from a Linux host firewall (UFW), identifies suspicious behavioral patterns per source IP, assigns weighted risk scores, and generates a prioritized triage report via CLI alongside a risk score visualization.

Built and validated against a live KVM lab environment: real nmap port scans and Hydra SSH brute force attacks captured from an isolated attacker/victim network, converted to NIDA format, and analyzed end-to-end.

> Academic project — Third Year B.Tech, End-Semester Seminar.

---

## Project Structure

```
NIDA/
│
├── logs/
│   ├── ufw.log          ← raw UFW capture from victim VM
│   └── network.log      ← NIDA format (output of converter.py)
├── output/              ← generated on first run
│   └── risk_scores.png
├── src/
│   ├── converter.py     ← converts ufw.log → network.log
│   ├── parser.py        ← parses network.log into event objects
│   ├── detector.py      ← rule engine + scoring + suggestions
│   └── main.py          ← entry point, CLI report, graph output
├── Dockerfile
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Lab Setup

NIDA was validated against real attack traffic in a KVM/virt-manager lab:

| Role    | OS              | IP               |
|---------|-----------------|------------------|
| Attacker | Kali Linux     | 192.168.100.36   |
| Victim   | Ubuntu Server 24.04 | 192.168.100.19 |

**Attacks performed:**
- `nmap -sS` SYN port scan across 1000 ports
- `hydra` SSH brute force against port 22

UFW logging was set to `medium` on the victim. Captured logs were transferred to the host and processed through NIDA's pipeline.

---

## Pipeline

```
ufw.log (raw firewall log)
        ↓
  converter.py  — parses UFW format, filters noise, maps to NIDA fields
        ↓
  network.log   — NIDA's internal log format
        ↓
   parser.py    — tokenizes each line into structured event objects
        ↓
  detector.py   — aggregates per-IP behavior, applies 7 detection rules
        ↓
   main.py      — renders CLI triage report + saves risk_scores.png
```

---

## Log Format

### UFW Input (`ufw.log`)
```
2026-04-06T15:48:40.263451+00:00 victim kernel: [UFW BLOCK] IN=enp1s0 OUT= MAC=... SRC=192.168.100.36 DST=192.168.100.19 LEN=44 ... PROTO=TCP SPT=35264 DPT=110 ...
```

### NIDA Format (`network.log`)
```
TIMESTAMP SRC_IP DST_IP DST_PORT PROTOCOL STATUS BYTES_SENT
2026-04-06 15:48:40 192.168.100.36 192.168.100.19 110 TCP REJECTED 44
```

Blank lines and lines starting with `#` are ignored by the parser.

---

## Detection Rules

| Rule | Condition | Score |
|------|-----------|-------|
| R1 — Port Scan | ≥ 10 distinct destination ports probed | +3 |
| R2 — Brute Force | ≥ 5 REJECTED attempts to the same port | +3 |
| R3 — Breach | REJECTED then ACCEPTED on the same port | +2 |
| R4 — Sensitive Port | Connection to a known high-value port | +1 per port |
| R5 — Off-Hours | Activity between 00:00–05:59 | +1 |
| R6 — Exfil Hint | Total bytes sent > 500 KB via accepted connections | +2 |
| R7 — Velocity Burst | ≥ 5 rejections within any 60-second window | +2 |

**Sensitive ports monitored:** 22, 23, 3389, 445, 3306, 5432, 6379, 27017, 8080, 8443

### Priority Mapping

| Score | Priority |
|-------|----------|
| 1     | LOW      |
| 2–3   | MEDIUM   |
| 4–5   | HIGH     |
| 6+    | CRITICAL |

---

## Remediation Suggestions

When a rule fires, NIDA outputs actionable remediation steps specific to each detected threat. Examples:

- **Brute Force detected** → Install fail2ban, enforce SSH key-only auth, move SSH off port 22
- **Breach detected** → Isolate machine, rotate credentials, audit `/var/log/auth.log`, check for new users/cron jobs/SUID binaries
- **Port Scan detected** → Apply `ufw default deny incoming`, consider port-knocking

---

## How to Run

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Convert UFW log (if starting from raw capture)

```bash
python src/converter.py
```

Reads `logs/ufw.log`, writes `logs/network.log`. Filters out localhost traffic, outbound noise, and UFW audit entries automatically.

### 3. Run NIDA

```bash
python src/main.py
```

**Output:**
- CLI triage report with scores, triggered rules, and remediation suggestions
- Risk score bar chart saved to `output/risk_scores.png`

### 4. Docker (optional)

```bash
docker build -t nida .
docker run nida
```

---

## Sample Output

```
============================================================
NIDA — NETWORK INTRUSION DETECTION REPORT
============================================================

Source IP    : 192.168.100.36
Risk Score   : 16
Priority     : CRITICAL
Connections  : 1994 rejected | Accepted: YES
Ports Probed : 997
Bytes Sent   : 4,260
Triggered Rules:
  - Port scan detected: 997 distinct ports probed
  - Brute force on port(s): 22
  - Possible breach: rejected then accepted on port(s): 22
  - Sensitive port(s) targeted: 22, 23, 3306, 3389, 8080
  - Burst detected: >=5 rejections within a 60-second window
Recommended Actions:
  -> IMMEDIATE: Isolate this machine from the network
  -> Rotate all credentials — assume keys/passwords are compromised
  -> Audit /var/log/auth.log for commands run post-compromise
  -> Install fail2ban with a low threshold (3-5 attempts)
  -> Apply rate-limiting now: ufw limit 22/tcp

============================================================
End of Report
============================================================
```

---

## Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.11+ |
| Log parsing | `re`, `datetime` |
| Behavior aggregation | `collections.defaultdict` |
| Visualization | `matplotlib` |
| Containerization | Docker |

---

## Limitations

- Processes static log files only — no real-time ingestion
- Rule-based detection — no ML or statistical modeling
- No packet payload inspection (connection metadata only)
- UFW log coverage depends on firewall logging level configured on the host
- May produce false positives on high-traffic legitimate hosts
- Designed for academic demonstration

---

## Future Scope

- Real-time ingestion via `tail -f` or syslog forwarding
- Time-window correlation across multiple destination IPs
- Statistical baseline modeling to flag deviations from normal behavior
- GeoIP lookup for external source IP enrichment
- SIEM integration (Splunk, Wazuh)
- SOC dashboard for non-technical stakeholder reporting
