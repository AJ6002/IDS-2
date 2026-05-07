# Project: Network Intrusion Detection System (IDS) - "NEURAL-SHIELD"

This project implements an AI-driven Network Intrusion Detection System that processes network traffic (PCAP files) and uses Machine Learning to classify connections as normal or malicious.

## Tech Stack
- **Language:** Python 3.10+
- **Infrastructure:** Azure Cloud (Ubuntu 24.04), Docker (Cowrie), Pyftpdlib (FTP Trap)
- **Feature Extraction:** `scapy`, `cicflowmeter` (WSL-optimized version)
- **Machine Learning:** `scikit-learn` (RandomForest), `joblib`
- **Visualization:** `Streamlit`, `Plotly`, `Pandas`

## Architecture: "NEURAL-SHIELD" Pipeline
The system follows a distributed "Capture-Extract-Detect" architecture:

1.  **Distributed Collection (Azure VM):**
    - **Port 5555 (Admin):** Secure management port for genuine admin activity.
    - **Port 22 (Honeypot):** Cowrie Docker container capturing SSH brute-force attempts.
    - **Port 21 (FTP Trap):** Python-based FTP server capturing unauthorized access attempts.
    - **Sniffer:** `tcpdump` capturing multi-vector traffic into `patator_test.pcap`.

2.  **Cross-Platform Feature Extraction (WSL):**
    - Raw PCAP files are exfiltrated via `SCP` to the local machine.
    - **Script:** `wsl_fix.py` runs inside a WSL Linux environment to bypass Windows-specific library bugs.
    - **Output:** `high_def_features.csv` (78 high-fidelity network flow features).

3.  **Intelligent Inference (Windows):**
    - **Script:** `final_detect.py` performs inference using the Tuesday (SSH/FTP) ML Model.
    - **Heuristic Overrides:** Implemented "Sensitivity Boost" logic (prob > 0.02) for Ports 21 and 22 to detect modern low-volume brute force attacks that standard ML might miss.
    - **Unit Normalization:** Automatic conversion of flow metrics to microseconds to align with training artifacts.

4.  **Real-Time Visualization (Dashboard):**
    - **Script:** `admin_dashboard.py` provides a professional Streamlit UI.
    - **Features:** Auto-refreshing metrics, Threat Index percentage, Pie Chart distribution, and live logging simulations.

## File Map
- `/`: Core project root.
    - `admin_dashboard.py`: Premium Streamlit UI for monitoring.
    - `final_detect.py`: Advanced AI classification engine with port-specific heuristics.
    - `wsl_fix.py`: Universal feature extraction script for WSL.
    - `PROJECT_FINAL_REPORT.md`: Comprehensive project summary and architecture diagrams.
    - `ids_model_tuesday.pkl`: Trained RandomForest weights.

## Key Patterns & Decisions
- **Microservice-Style Decoupling:** Capture is handled on the Cloud, Extraction in WSL, and Dashboard in Windows. This prevents environment-specific library conflicts (e.g., scapy/cicflowmeter bugs on Windows).
- **Heuristic-Aided AI:** Pure ML was found to have "drift" for modern attacks. We solved this by using `predict_proba` thresholds (2%) combined with destination port filtering for high-confidence detections.
- **Live Data Pipeline:** The project moved from static datasets to **Live Harvesting**, proving the model's effectiveness against real-world internet background radiation.

## Current State (2026-05-08)
- **Deployment:** FULLY OPERATIONAL.
- **Capabilities:** Detects BENIGN, SSH-Patator, and FTP-Patator traffic vectors.
- **Dashboard:** Auto-refreshing every 5 seconds; linked to `high_def_features.csv`.
- **Next Potential Step:** Automated firewall response (SOAR) to ban IPs in the Azure NSG upon detection.
