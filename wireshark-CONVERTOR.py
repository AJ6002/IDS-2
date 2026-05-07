import pyshark
import pandas as pd
import sys
from pathlib import Path

# === DYNAMIC CONFIG ===
# Usage: python wireshark-CONVERTOR.py <input.pcap>
if len(sys.argv) > 1:
    pcap_file = sys.argv[1]
    # Automatically name output: test.pcap -> test_features.csv
    output_csv = pcap_file.replace(".pcap", "_features.csv")
else:
    pcap_file = "live_attacks.pcap"
    output_csv = "live_attacks_features.csv"

if not Path(pcap_file).exists():
    print(f"Error: {pcap_file} not found!")
    sys.exit(1)

print(f"Loading {pcap_file}...")
cap = pyshark.FileCapture(pcap_file, keep_packets=False)

flows = {}

print("Processing packets...")
for pkt in cap:
    try:
        # Use only IP packets
        if 'IP' not in pkt:
            continue

        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst
        proto = pkt.transport_layer or 'UNKNOWN'

        key = (src_ip, dst_ip, proto)
        ts = float(pkt.sniff_timestamp)
        pkt_len = int(pkt.length)

        # Flow splitting logic (0.5s timeout)
        if key not in flows or (ts - flows[key][-1]['end_time']) > 0.5:
            if key not in flows: flows[key] = []
            flows[key].append({
                'start_time': ts,
                'end_time': ts,
                'packet_count': 1,
                'total_bytes': pkt_len,
            })
        else:
            flow = flows[key][-1]
            flow['end_time'] = max(flow['end_time'], ts)
            flow['packet_count'] += 1
            flow['total_bytes'] += pkt_len

    except Exception as e:
        continue

# === Convert to DataFrame ===
print("Building dataset...")
rows = []
for key, flow_list in flows.items():
    for f in flow_list:
        duration = f['end_time'] - f['start_time']
        rows.append({
            'packet_count': f['packet_count'],
            'total_bytes': f['total_bytes'],
            'duration': round(duration, 3)
        })

df = pd.DataFrame(rows)
df.to_csv(output_csv, index=False)

print(f"Done! Dataset saved to {output_csv}")

