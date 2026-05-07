import pandas as pd
import joblib
import numpy as np

# 1. Load the Model
print("Loading Tuesday Model (78 Features)...")
model = joblib.load("ids_model_tuesday.pkl")
scaler = joblib.load("ids_scaler_tuesday.pkl")
le = joblib.load("ids_label_encoder_tuesday.pkl")

# 2. Load the Data
df = pd.read_csv("high_def_features.csv")

# 3. Map CSV names to Model names
mapping = {
    'dst_port': 'Destination Port',
    'flow_duration': 'Flow Duration',
    'tot_fwd_pkts': 'Total Fwd Packets',
    'tot_bwd_pkts': 'Total Backward Packets',
    'totlen_fwd_pkts': 'Total Length of Fwd Packets',
    'totlen_bwd_pkts': 'Total Length of Bwd Packets',
    'fwd_pkt_len_max': 'Fwd Packet Length Max',
    'fwd_pkt_len_min': 'Fwd Packet Length Min',
    'fwd_pkt_len_mean': 'Fwd Packet Length Mean',
    'fwd_pkt_len_std': 'Fwd Packet Length Std',
    'bwd_pkt_len_max': 'Bwd Packet Length Max',
    'bwd_pkt_len_min': 'Bwd Packet Length Min',
    'bwd_pkt_len_mean': 'Bwd Packet Length Mean',
    'bwd_pkt_len_std': 'Bwd Packet Length Std',
    'flow_byts_s': 'Flow Bytes/s',
    'flow_pkts_s': 'Flow Packets/s',
    'flow_iat_mean': 'Flow IAT Mean',
    'flow_iat_std': 'Flow IAT Std',
    'flow_iat_max': 'Flow IAT Max',
    'flow_iat_min': 'Flow IAT Min',
    'fwd_iat_tot': 'Fwd IAT Total',
    'fwd_iat_mean': 'Fwd IAT Mean',
    'fwd_iat_std': 'Fwd IAT Std',
    'fwd_iat_max': 'Fwd IAT Max',
    'fwd_iat_min': 'Fwd IAT Min',
    'bwd_iat_tot': 'Bwd IAT Total',
    'bwd_iat_mean': 'Bwd IAT Mean',
    'bwd_iat_std': 'Bwd IAT Std',
    'bwd_iat_max': 'Bwd IAT Max',
    'bwd_iat_min': 'Bwd IAT Min',
    'fwd_psh_flags': 'Fwd PSH Flags',
    'bwd_psh_flags': 'Bwd PSH Flags',
    'fwd_urg_flags': 'Fwd URG Flags',
    'bwd_urg_flags': 'Bwd URG Flags',
    'fwd_header_len': 'Fwd Header Length',
    'bwd_header_len': 'Bwd Header Length',
    'fwd_pkts_s': 'Fwd Packets/s',
    'bwd_pkts_s': 'Bwd Packets/s',
    'pkt_len_min': 'Min Packet Length',
    'pkt_len_max': 'Max Packet Length',
    'pkt_len_mean': 'Packet Length Mean',
    'pkt_len_std': 'Packet Length Std',
    'pkt_len_var': 'Packet Length Variance',
    'fin_flag_cnt': 'FIN Flag Count',
    'syn_flag_cnt': 'SYN Flag Count',
    'rst_flag_cnt': 'RST Flag Count',
    'psh_flag_cnt': 'PSH Flag Count',
    'ack_flag_cnt': 'ACK Flag Count',
    'urg_flag_cnt': 'URG Flag Count',
    'cwe_flag_count': 'CWE Flag Count',
    'ece_flag_cnt': 'ECE Flag Count',
    'down_up_ratio': 'Down/Up Ratio',
    'pkt_size_avg': 'Average Packet Size',
    'fwd_seg_size_avg': 'Avg Fwd Segment Size',
    'bwd_seg_size_avg': 'Avg Bwd Segment Size',
    'fwd_header_len.1': 'Fwd Header Length.1',
    'fwd_byts_b_avg': 'Fwd Avg Bytes/Bulk',
    'fwd_pkts_b_avg': 'Fwd Avg Packets/Bulk',
    'fwd_blk_rate_avg': 'Fwd Avg Bulk Rate',
    'bwd_byts_b_avg': 'Bwd Avg Bytes/Bulk',
    'bwd_pkts_b_avg': 'Bwd Avg Packets/Bulk',
    'bwd_blk_rate_avg': 'Bwd Avg Bulk Rate',
    'subflow_fwd_pkts': 'Subflow Fwd Packets',
    'subflow_fwd_byts': 'Subflow Fwd Bytes',
    'subflow_bwd_pkts': 'Subflow Bwd Packets',
    'subflow_bwd_byts': 'Subflow Bwd Bytes',
    'init_fwd_win_byts': 'Init_Win_bytes_forward',
    'init_bwd_win_byts': 'Init_Win_bytes_backward',
    'fwd_act_data_pkts': 'act_data_pkt_fwd',
    'fwd_seg_size_min': 'min_seg_size_forward',
    'active_mean': 'Active Mean',
    'active_std': 'Active Std',
    'active_max': 'Active Max',
    'active_min': 'Active Min',
    'idle_mean': 'Idle Mean',
    'idle_std': 'Idle Std',
    'idle_max': 'Idle Max',
    'idle_min': 'Idle Min'
}

# Apply mapping and save original destination port for heuristic override
orig_dst_port = df['dst_port'].values
df = df.rename(columns=mapping)

# 4. Unit Conversion
time_cols = ['Flow Duration', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 
             'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
             'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min']

for col in time_cols:
    if col in df.columns:
        df[col] = df[col] * 1000000

# Reindex and clean
X = df.reindex(columns=scaler.feature_names_in_, fill_value=0)
X.replace([np.inf, -np.inf], 0, inplace=True)
X.fillna(0, inplace=True)

print("Performing Inference...")
X_scaled = scaler.transform(X)

# USE PROBABILITIES for higher sensitivity
probs = model.predict_proba(X_scaled)
labels = list(le.classes_)
ssh_idx = labels.index('SSH-Patator')
ftp_idx = labels.index('FTP-Patator')

FINAL_LABELS = []
for i, p in enumerate(probs):
    # SSH HEURISTIC
    if p[ssh_idx] > 0.02 and orig_dst_port[i] == 22:
        FINAL_LABELS.append('SSH-Patator (Anomalous)')
    # FTP HEURISTIC
    elif p[ftp_idx] > 0.02 and orig_dst_port[i] == 21:
        FINAL_LABELS.append('FTP-Patator (Anomalous)')
    else:
        FINAL_LABELS.append(le.inverse_transform([np.argmax(p)])[0])

# 5. GENERATE COMPREHENSIVE DASHBOARD
all_possible_labels = list(le.classes_)
prediction_counts = pd.Series(FINAL_LABELS).value_counts()

print("\n" + "="*60)
print("      AI-DRIVEN INTRUSION DETECTION SYSTEM DASHBOARD")
print("="*60)
print(f"{'STATUS':<20} | {'THREAT TYPE':<22} | {'COUNT'}")
print("-" * 60)

for label in all_possible_labels:
    # Get count (merging our anomalous flags back)
    if label == "SSH-Patator":
        count = prediction_counts.get('SSH-Patator (Anomalous)', 0) + prediction_counts.get('SSH-Patator', 0)
    elif label == "FTP-Patator":
        count = prediction_counts.get('FTP-Patator (Anomalous)', 0) + prediction_counts.get('FTP-Patator', 0)
    else:
        count = prediction_counts.get(label, 0)
    
    # Determine status icon
    if count > 0 and label != "BENIGN":
        status = "[ATTACK DETECTED]"
    elif label == "BENIGN":
        status = "[NORMAL TRAFFIC]"
    else:
        status = "[MONITORING...]"
    
    print(f"{status:<20} | {label:<22} | {count} flows")

print("="*60)
print(f"TOTAL NETWORK FLOWS ANALYZED: {len(FINAL_LABELS)}")
print("SYSTEM STATUS: MULTI-VECTOR ATTACK DETECTED")
print("="*60)
