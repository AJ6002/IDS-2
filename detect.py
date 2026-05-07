import pandas as pd
import joblib
import numpy as np
import sys

# 1. Load the NEW Lightweight model and preprocessing tools
try:
    model = joblib.load("ids_model_lightweight.pkl")
    scaler = joblib.load("ids_scaler_lightweight.pkl")
    le = joblib.load("ids_label_encoder_lightweight.pkl")
except Exception as e:
    print(f"Error loading model artifacts: {e}")
    sys.exit(1)

# 2. Load the newly captured data
INPUT_FILE = "patator_test_features.csv" 

try:
    print(f"Reading {INPUT_FILE}...")
    df_simple = pd.read_csv(INPUT_FILE)
    
    if df_simple.empty:
        print("Error: Input CSV is empty.")
        sys.exit(1)

    # 3. Use the exact 3 features we trained the lightweight model on
    X = pd.DataFrame()
    X['packet_count'] = df_simple['packet_count']
    X['total_bytes'] = df_simple['total_bytes']
    X['duration'] = df_simple['duration']
    
    # Apply Scaling
    X_scaled = scaler.transform(X)

    # 4. Hybrid Prediction (ML + Heuristics)
    print("Predicting...")
    
    print("\n" + "="*45)
    print("      LIVE IDS DETECTION REPORT")
    print("="*45)
    print(f"{'STATUS':<20} | {'LABEL':<12} | {'DETAILS'}")
    print("-" * 45)
    
    found_attack = False
    
    # Iterate row by row for hybrid detection
    ml_predictions = model.predict(X_scaled)
    
    for i in range(len(df_simple)):
        ml_label_encoded = ml_predictions[i]
        ml_label = le.inverse_transform([ml_label_encoded])[0]
        
        packet_rate = df_simple.iloc[i]['packet_count'] / max(df_simple.iloc[i]['duration'], 0.1)
        
        if ml_label != "BENIGN":
            print(f"[{'ATTACK DETECTED':<18}] | {ml_label:<12} | ML Signature Match")
            found_attack = True
        elif packet_rate > 5:
            # Heuristic override for unknown high-volume brute force
            print(f"[{'ATTACK DETECTED':<18}] | {'BRUTE-FORCE':<12} | Heuristic (High Pkt Rate: {packet_rate:.1f} p/s)")
            found_attack = True
    
    if not found_attack:
        print(f"[{'NORMAL TRAFFIC':<18}] | {'BENIGN':<12} | {len(df_simple)} flows")
        print("\nResult: No intrusions detected in this sample.")
    else:
        print("\nResult: Critical! Intrusion patterns identified.")
    print("="*45)

except Exception as e:

    print(f"Error during detection: {e}")
    import traceback
    traceback.print_exc()
