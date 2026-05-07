import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from imblearn.over_sampling import SMOTE
import joblib

print("Loading dataset...")
df = pd.read_csv("Tuesday-WorkingHours.pcap_ISCX.csv")
df.columns = df.columns.str.strip()

print("Extracting the 5 core features...")
# Extracting the 3 core features that our simple Windows converter can reliably produce
X = pd.DataFrame()
X['packet_count'] = df['Total Fwd Packets']
X['total_bytes'] = df['Total Length of Fwd Packets']
X['duration'] = df['Flow Duration'] / 1000000.0  # Convert microseconds to seconds

y = df['Label']

print("Cleaning data...")
X.replace([np.inf, -np.inf], np.nan, inplace=True)
mask = X.notnull().all(axis=1)
X = X[mask]
y = y[mask]

print("Encoding and Scaling...")
le = LabelEncoder()
y_encoded = le.fit_transform(y)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

print("Balancing classes with SMOTE...")
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y_encoded, test_size=0.3, random_state=42)
smote = SMOTE(random_state=42)
X_train_res, y_train_res = smote.fit_resample(X_train, y_train)

print("Training Lightweight Model...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train_res, y_train_res)

print("Saving Lightweight Model artifacts...")
joblib.dump(model, "ids_model_lightweight.pkl")
joblib.dump(scaler, "ids_scaler_lightweight.pkl")
joblib.dump(le, "ids_label_encoder_lightweight.pkl")

print("\nDONE! You now have a model perfectly synchronized with your Windows converter.")
