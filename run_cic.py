import sys
from cicflowmeter.sniffer import create_sniffer
import inspect

input_pcap = sys.argv[1] if len(sys.argv) > 1 else "patator_test.pcap"
output_csv = sys.argv[2] if len(sys.argv) > 2 else "high_def_features.csv"

print(f"Starting CICFlowMeter extraction on {input_pcap} -> {output_csv} ...")

# 1. Detect the correct argument name (output vs output_file)
sig = inspect.signature(create_sniffer)
arg_name = "output" if "output" in sig.parameters else "output_file"

# 2. Prepare arguments
kwargs = {
    "input_file": input_pcap,
    "input_interface": None,
    "output_mode": "csv",
    arg_name: output_csv
}

try:
    # 3. Create sniffer and handle the (sniffer, session) tuple vs object
    res = create_sniffer(**kwargs)
    sniffer = res[0] if isinstance(res, tuple) else res
    
    sniffer.start()
    sniffer.join()
    print(f"\n✅ Successfully extracted 78+ features to {output_csv}!")
except Exception as e:
    print(f"Error: {e}")
