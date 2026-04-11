from collections import defaultdict

# Ports considered high-value targets
SENSITIVE_PORTS = {22, 23, 3389, 445, 3306, 5432, 6379, 27017, 8080, 8443}

# Bytes threshold to flag possible data exfiltration
EXFIL_THRESHOLD = 500_000  # 500 KB

RULE_SUGGESTIONS = {
    "Port scan": [
        "Block all non-essential inbound ports (ufw default deny incoming)",
        "Enable port-knocking for SSH access",
        "Deploy a honeypot on commonly scanned ports",
    ],
    "Brute force": [
        "Install fail2ban to auto-ban IPs after repeated failures",
        "Disable password auth — use SSH key-only authentication",
        "Move SSH to a non-standard port to reduce automated attacks",
    ],
    "Possible breach": [
        "IMMEDIATE: Isolate this machine from the network",
        "Rotate all credentials — assume keys/passwords are compromised",
        "Audit /var/log/auth.log for commands run post-compromise",
        "Check for new user accounts, cron jobs, and SUID binaries",
        "Consider reimaging from clean snapshot",
    ],
    "Sensitive port": [
        "Audit which services are actually needed — disable unused ones",
        "Restrict database ports (3306, 5432) to localhost only",
        "Replace Telnet (23) with SSH equivalents",
    ],
    "Off-hours": [
        "Set up alerting for off-hours logins via webhook",
        "Consider IP allowlisting for admin access outside business hours",
    ],
    "High data transfer": [
        "Apply egress filtering — restrict outbound traffic rules",
        "Check what data is accessible from the compromised account",
        "Review recent file access: ausearch -f /sensitive/path",
    ],
    "Burst detected": [
        "Apply rate-limiting now: ufw limit 22/tcp",
        "Install fail2ban with a low threshold (3-5 attempts)",
    ],
}

def _has_velocity_burst(fail_timestamps, window_seconds=60, threshold=5):
    # Returns True if >= threshold REJECTEDs happened within any window_seconds window
    # This is how we distinguish a brute-force tool from a clumsy human
    if len(fail_timestamps) < threshold:
        return False
    for i in range(len(fail_timestamps) - threshold + 1):
        delta = (
            fail_timestamps[i + threshold - 1] - fail_timestamps[i]
        ).total_seconds()
        if delta <= window_seconds:
            return True
    return False


def analyze_events(events):
    ip_data = defaultdict(
        lambda: {
            "rejected_count": 0,
            "accepted": False,
            "off_hours": False,
            "reject_timestamps": [],  # for velocity burst detection
            "dst_ports": set(),  # for port scan detection
            "bytes_sent": 0,  # for exfil detection
            "reject_ports": set(),  # ports that saw rejections
            "accept_ports": set(),  # ports that saw acceptances
        }
    )

    for e in events:
        ip = e["src_ip"]
        ip_data[ip]["dst_ports"].add(e["dst_port"])

        if e["status"] == "REJECTED":
            ip_data[ip]["rejected_count"] += 1
            ip_data[ip]["reject_timestamps"].append(e["timestamp"])
            ip_data[ip]["reject_ports"].add(e["dst_port"])

        elif e["status"] == "ACCEPTED":
            ip_data[ip]["accepted"] = True
            ip_data[ip]["bytes_sent"] += e["bytes_sent"]
            ip_data[ip]["accept_ports"].add(e["dst_port"])
            if 0 <= e["timestamp"].hour <= 5:
                ip_data[ip]["off_hours"] = True

    # Sort timestamps per IP for velocity check
    for ip in ip_data:
        ip_data[ip]["reject_timestamps"].sort()

    results = []

    for ip, data in ip_data.items():
        score = 0
        reasons = []

        # Rule 1: Port Scan
        if len(data["dst_ports"]) >= 10:
            score += 3
            reasons.append(
                f"Port scan detected: {len(data['dst_ports'])} distinct ports probed"
            )

        # Rule 2: Brute Force
        brute_ports = [
            p
            for p in data["reject_ports"]
            if sum(1 for t in data["reject_timestamps"]) >= 5
        ]
        # more precise: count rejects per port
        from collections import Counter

        port_reject_counts = Counter()
        # recount per port properly
        port_reject_counts = defaultdict(int)
        for e in events:
            if e["src_ip"] == ip and e["status"] == "REJECTED":
                port_reject_counts[e["dst_port"]] += 1
        brute_ports = [p for p, c in port_reject_counts.items() if c >= 5]
        if brute_ports:
            score += 3
            reasons.append(
                f"Brute force on port(s): {', '.join(map(str, brute_ports))}"
            )

        # Rule 3: Breach
        breach_ports = data["reject_ports"] & data["accept_ports"]
        if breach_ports:
            score += 2
            reasons.append(
                f"Possible breach: rejected then accepted on port(s): {', '.join(map(str, breach_ports))}"
            )

        # Rule 4: Sensitive Port Access
        hit_sensitive = data["dst_ports"] & SENSITIVE_PORTS
        if hit_sensitive:
            score += len(hit_sensitive)
            reasons.append(
                f"Sensitive port(s) targeted: {', '.join(map(str, sorted(hit_sensitive)))}"
            )

        # Rule 5: Off-Hours Activity
        if data["off_hours"]:
            score += 1
            reasons.append("Off-hours activity detected (00:00–05:59)")

        # Rule 6: Data Exfiltration Hint
        if data["bytes_sent"] > EXFIL_THRESHOLD:
            score += 2
            reasons.append(
                f"High data transfer: {data['bytes_sent']:,} bytes via accepted connections"
            )

        # Rule 7: Velocity Burst
        if _has_velocity_burst(data["reject_timestamps"]):
            score += 2
            reasons.append("Burst detected: >=5 rejections within a 60-second window")

        if score == 0:
            continue

        # Priority mapping
        if score >= 6:
            priority = "CRITICAL"
        elif score >= 4:
            priority = "HIGH"
        elif score >= 2:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        suggestions = []
        for reason in reasons:
            for key, suggs in RULE_SUGGESTIONS.items():
                if key in reason:
                    suggestions.extend(suggs)
                    break

        results.append(
            {
                "ip": ip,
                "score": score,
                "priority": priority,
                "reasons": reasons,
                "rejected": data["rejected_count"],
                "accepted": data["accepted"],
                "ports_probed": len(data["dst_ports"]),
                "bytes_sent": data["bytes_sent"],
                "suggestions": suggestions
            }
        )

    # Sort highest risk first
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    results.sort(key=lambda x: (priority_order.get(x["priority"], 4), -x["score"]))
    return results
