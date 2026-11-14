import os
import matplotlib.pyplot as plt
from parser import parse_file
from detector import analyze_events

LOG_FILE = "logs/network.log"
OUTPUT_DIR = "output"
GRAPH_PATH = os.path.join(OUTPUT_DIR, "risk_scores.png")

PRIORITY_COLORS = {
    "CRITICAL": "#ff2d55",
    "HIGH": "#ff9500",
    "MEDIUM": "#ffd60a",
    "LOW": "#30d158",
}


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    events = parse_file(LOG_FILE)

    print("\nParsed Events:\n")
    for e in events:
        print(
            f"{e['timestamp']} | {e['src_ip']} -> {e['dst_ip']}:{e['dst_port']} | {e['status']} | {e['bytes_sent']} bytes"
        )

    analysis = analyze_events(events)

    print("\n" + "=" * 60)
    print("NIDA — NETWORK INTRUSION DETECTION REPORT")
    print("=" * 60)

    for item in analysis:
        print(f"\nSource IP    : {item['ip']}")
        print(f"Risk Score   : {item['score']}")
        print(f"Priority     : {item['priority']}")
        print(
            f"Connections  : {item['rejected']} rejected | Accepted: {'YES' if item['accepted'] else 'NO'}"
        )
        print(f"Ports Probed : {item['ports_probed']}")
        print(f"Bytes Sent   : {item['bytes_sent']:,}")
        print("Triggered Rules:")
        for r in item["reasons"]:
            print(f"  - {r}")
        if item.get("suggestions"):
            print("Recommended Actions:")
            for s in item["suggestions"]:
                print(f"  -> {s}")

    print("\n" + "=" * 60)
    print("End of Report")
    print("=" * 60)

    ips = [item["ip"] for item in analysis]
    scores = [item["score"] for item in analysis]
    colors = [PRIORITY_COLORS.get(item["priority"], "#888") for item in analysis]

    if ips:
        plt.figure(figsize=(10, 5))
        bars = plt.bar(ips, scores, color=colors)
        plt.xlabel("Source IP")
        plt.ylabel("Risk Score")
        plt.title("NIDA — Risk Score per Source IP")
        plt.xticks(rotation=45, ha="right")
        plt.ylim(0, max(scores) + 2)

        for bar, score in zip(bars, scores):
            plt.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.1,
                str(score),
                ha="center",
                fontsize=9,
            )

        plt.tight_layout()
        plt.savefig(GRAPH_PATH, dpi=300)
        print(f"\nGraph saved to {GRAPH_PATH}")
    else:
        print("\nNo suspicious activity detected. No graph generated.")


if __name__ == "__main__":
    main()
