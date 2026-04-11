import re
from datetime import datetime

INPUT = "../logs/ufw.log"
OUTPUT = "../logs/network.log"

def convert():
    with open(INPUT, "r") as infile, open(OUTPUT, "w") as outfile:
        for line in infile:

            # Ignore localhost + audit noise
            if "SRC=127." in line or "[UFW AUDIT]" in line:
                continue

            if "IN= OUT=enp1s0" in line or "IN= OUT=lo" in line:   # outbound traffic from victim — not attack traffic
                continue

            # Extract timestamp
            try:
                raw_ts = line.split()[0]
                dt = datetime.strptime(raw_ts, "%Y-%m-%dT%H:%M:%S.%f%z")
                timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                continue

            # Extract fields
            src = re.search(r"SRC=(\d+\.\d+\.\d+\.\d+)", line)
            dst = re.search(r"DST=(\d+\.\d+\.\d+\.\d+)", line)
            dpt = re.search(r"DPT=(\d+)", line)
            proto = re.search(r"PROTO=(\w+)", line)
            length = re.search(r"LEN=(\d+)", line)

            if not (src and dst and dpt):
                continue

            src_ip = src.group(1)
            dst_ip = dst.group(1)
            port = int(dpt.group(1))
            protocol = proto.group(1) if proto else "TCP"
            bytes_sent = int(length.group(1)) if length else 100

            # Map status
            if "BLOCK" in line:
                status = "REJECTED"
            else:
                status = "ACCEPTED"

            outfile.write(
                f"{timestamp} {src_ip} {dst_ip} {port} {protocol} {status} {bytes_sent}\n"
            )


if __name__ == "__main__":
    convert()
