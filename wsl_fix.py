import sys
import os
from scapy.all import rdpcap
import cicflowmeter.flow_session as fs

# 1. Setup Input/Output
input_pcap = "patator_test.pcap"
output_csv = "high_def_features.csv"

if not os.path.exists(input_pcap):
    print(f"Error: {input_pcap} not found!")
    sys.exit(1)

print(f"Reading {input_pcap}...")
packets = rdpcap(input_pcap)

# 2. Extract Features (Version 0.5.0 Logic)
print("Extracting 78+ features...")

try:
    # In this version, FlowSession creates its own writer
    # It needs output_mode and output
    session = fs.FlowSession(output_mode="csv", output=output_csv)

    for pkt in packets:
        # Use 'process' as found in the directory listing
        session.process(pkt)

    # 3. Finalize and Save
    # Flush remaining flows
    session.garbage_collect(sys.maxsize)
    
    print(f"\n✅ SUCCESS! 78+ features saved to {output_csv}")

except Exception as e:
    print(f"Extraction Error: {e}")
    import traceback
    traceback.print_exc()
