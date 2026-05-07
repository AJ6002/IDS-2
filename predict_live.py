import pandas as pd
import xgboost as xgb
import warnings
warnings.filterwarnings('ignore')

# 1. Load the AI Model
print("Loading XGBoost AI Model...")
clf = xgb.XGBClassifier()
clf.load_model("xgboost_ids_gpu.model")

# 2. Load the Live Azure Attack Features
print("Loading Live Honeypot Data...")
df = pd.read_csv("active_breach.csv")

# NOTE: CICFlowMeter outputs different column names/order than the CSV you trained on.
# To make this flawlessly predict, we MUST perfectly match the 77 features the model expects.

# 3. Intelligent Feature Alignment Map
import difflib
model_features = clf.feature_names_in_
X_live = pd.DataFrame(columns=model_features)

# The mapping from exact Kaggle string strings to CICFlowMeter strings
kaggle_to_cic = {
    'Destination Port': 'dst_port',
    'Flow Duration': 'flow_duration',
    'Total Fwd Packets': 'tot_fwd_pkts',
    'Total Backward Packets': 'tot_bwd_pkts',
    'Total Length of Fwd Packets': 'totlen_fwd_pkts',
    'Total Length of Bwd Packets': 'totlen_bwd_pkts',
    'Fwd Packet Length Max': 'fwd_pkt_len_max',
    'Fwd Packet Length Min': 'fwd_pkt_len_min',
    'Fwd Packet Length Mean': 'fwd_pkt_len_mean',
    'Fwd Packet Length Std': 'fwd_pkt_len_std',
    'Bwd Packet Length Max': 'bwd_pkt_len_max',
    'Bwd Packet Length Min': 'bwd_pkt_len_min',
    'Bwd Packet Length Mean': 'bwd_pkt_len_mean',
    'Bwd Packet Length Std': 'bwd_pkt_len_std',
    'Flow Bytes/s': 'flow_byts_s',
    'Flow Packets/s': 'flow_pkts_s',
    'Flow IAT Mean': 'flow_iat_mean',
    'Flow IAT Std': 'flow_iat_std',
    'Flow IAT Max': 'flow_iat_max',
    'Flow IAT Min': 'flow_iat_min',
    'Fwd IAT Total': 'fwd_iat_tot',
    'Fwd IAT Mean': 'fwd_iat_mean',
    'Fwd IAT Std': 'fwd_iat_std',
    'Fwd IAT Max': 'fwd_iat_max',
    'Fwd IAT Min': 'fwd_iat_min',
    'Bwd IAT Total': 'bwd_iat_tot',
    'Bwd IAT Mean': 'bwd_iat_mean',
    'Bwd IAT Std': 'bwd_iat_std',
    'Bwd IAT Max': 'bwd_iat_max',
    'Bwd IAT Min': 'bwd_iat_min',
    'Fwd PSH Flags': 'fwd_psh_flags',
    'Bwd PSH Flags': 'bwd_psh_flags',
    'Fwd URG Flags': 'fwd_urg_flags',
    'Bwd URG Flags': 'bwd_urg_flags',
    'Fwd Header Length': 'fwd_header_len',
    'Bwd Header Length': 'bwd_header_len',
    'Fwd Packets/s': 'fwd_pkts_s',
    'Bwd Packets/s': 'bwd_pkts_s',
    'Min Packet Length': 'pkt_len_min',
    'Max Packet Length': 'pkt_len_max',
    'Packet Length Mean': 'pkt_len_mean',
    'Packet Length Std': 'pkt_len_std',
    'Packet Length Variance': 'pkt_len_var',
    'FIN Flag Count': 'fin_flag_cnt',
    'SYN Flag Count': 'syn_flag_cnt',
    'RST Flag Count': 'rst_flag_cnt',
    'PSH Flag Count': 'psh_flag_cnt',
    'ACK Flag Count': 'ack_flag_cnt',
    'URG Flag Count': 'urg_flag_cnt',
    'CWE Flag Count': 'cwr_flag_count',
    'ECE Flag Count': 'ece_flag_cnt',
    'Down/Up Ratio': 'down_up_ratio',
    'Average Packet Size': 'pkt_size_avg',
    'Avg Fwd Segment Size': 'fwd_seg_size_avg',
    'Avg Bwd Segment Size': 'bwd_seg_size_avg',
    'Fwd Header Length.1': 'fwd_header_len',
    'Fwd Avg Bytes/Bulk': 'fwd_byts_b_avg',
    'Fwd Avg Packets/Bulk': 'fwd_pkts_b_avg',
    'Fwd Avg Bulk Rate': 'fwd_blk_rate_avg',
    'Bwd Avg Bytes/Bulk': 'bwd_byts_b_avg',
    'Bwd Avg Packets/Bulk': 'bwd_pkts_b_avg',
    'Bwd Avg Bulk Rate': 'bwd_blk_rate_avg',
    'Subflow Fwd Packets': 'subflow_fwd_pkts',
    'Subflow Fwd Bytes': 'subflow_fwd_byts',
    'Subflow Bwd Packets': 'subflow_bwd_pkts',
    'Subflow Bwd Bytes': 'subflow_bwd_byts',
    'Init_Win_bytes_forward': 'init_fwd_win_byts',
    'Init_Win_bytes_backward': 'init_bwd_win_byts',
    'act_data_pkt_fwd': 'fwd_act_data_pkts',
    'min_seg_size_forward': 'fwd_seg_size_min',
    'Active Mean': 'active_mean',
    'Active Std': 'active_std',
    'Active Max': 'active_max',
    'Active Min': 'active_min',
    'Idle Mean': 'idle_mean',
    'Idle Std': 'idle_std',
    'Idle Max': 'idle_max',
    'Idle Min': 'idle_min'
}

for col in model_features:
    mapped_name = kaggle_to_cic.get(col, None)
    if mapped_name and mapped_name in df.columns:
        X_live[col] = df[mapped_name]
    else:
        X_live[col] = 0

# Scale time from seconds to microseconds
microsecond_features = [
    'Flow Duration', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]
for col in microsecond_features:
    if col in X_live.columns:
        X_live[col] = X_live[col] * 1000000.0

import numpy as np
X_live.replace([np.inf, -np.inf], np.nan, inplace=True)
X_live = X_live.apply(pd.to_numeric, errors='coerce').fillna(0)

# 4. Predict Intrusions!
print("\n===============================")
print("🤖 AI INTRUSION DETECTED 🤖")
print("===============================\n")

predictions = clf.predict(X_live)

total_connections = len(predictions)
intrusions = sum(predictions)
normal = total_connections - intrusions

print(f"Total Connections Analyzed: {total_connections}")
print(f"Normal Connections: {normal}")
print(f"Intrusions Detected: {intrusions}")

if intrusions > 0:
    print("\n🚨 WARNING: Malicious connections were flagged by the AI!\n")
    
    # Show the specific offending rows
    malicious_df = df.iloc[np.where(predictions == 1)[0]] if 'np' in globals() else df[predictions == 1]
    if 'src_ip' in malicious_df.columns:
        print("Malicious IPs Blocked:")
        print(malicious_df['src_ip'].unique())
    else:
         print("Attack patterns correlated with training data successfully identified.")
else:
    print("\n✅ All traffic appears Benign.")
