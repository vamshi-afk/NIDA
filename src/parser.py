import re
from datetime import datetime

LOG_PATTERN = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<dst_port>\d+)\s+"
    r"(?P<protocol>\w+)\s+"
    r"(?P<status>ACCEPTED|REJECTED)\s+"
    r"(?P<bytes_sent>\d+)"
)


def parse_line(line):
    match = LOG_PATTERN.search(line)
    if not match:
        return None

    data = match.groupdict()

    try:
        timestamp = datetime.strptime(data["timestamp"], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "src_ip": data["src_ip"],
        "dst_ip": data["dst_ip"],
        "dst_port": int(data["dst_port"]),
        "protocol": data["protocol"].upper(),
        "status": data["status"].upper(),  # ACCEPTED or REJECTED
        "bytes_sent": int(data["bytes_sent"]),
    }


def parse_file(filepath):
    events = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parsed = parse_line(line)
                if parsed:
                    events.append(parsed)
    except FileNotFoundError:
        print(f"[!] Log file not found: {filepath}")
    return events
