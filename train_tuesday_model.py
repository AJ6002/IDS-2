import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from pathlib import Path

# Configuration
INPUT_CSV = "Tuesday-WorkingHours.pcap_ISCX.csv"
MODEL_PATH = "ids_model_tuesday.pkl"
SCALER_PATH = "ids_scaler_tuesday.pkl"
LABEL_ENCODER_PATH = "ids_label_encoder_tuesday.pkl"

def load_and_preprocess(filepath):
    print(f"Loading {filepath}...")
    # Read CSV
    df = pd.read_csv(filepath)
    
    # Clean column names (strip leading/trailing spaces)
    df.columns = df.columns.str.strip()
    
    print(f"Initial shape: {df.shape}")
    
    # Handle missing values and infinities
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    print(f"Shape after dropping NaNs/Infs: {df.shape}")
    
    # Separate features and label
    X = df.drop('Label', axis=1)
    y = df['Label']
    
    # Label Encoding
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    print(f"Classes found: {le.classes_}")
    
    # Feature Scaling
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    return X_scaled, y_encoded, le, scaler

def train_model(X, y):
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    
    # Handle class imbalance using SMOTE
    print("Applying SMOTE to balance classes...")
    smote = SMOTE(random_state=42)
    X_train_res, y_train_res = smote.fit_resample(X_train, y_train)
    print(f"Resampled shape: {X_train_res.shape}")
    
    # Train Random Forest
    print("Training RandomForestClassifier...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train_res, y_train_res)
    
    # Evaluate
    print("\nEvaluation on Test Set:")
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))
    
    return clf, X_test, y_test

def plot_results(clf, X_test, y_test, le):
    y_pred = clf.predict(X_test)
    cm = confusion_matrix(y_test, y_pred)
    
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", 
                xticklabels=le.classes_, yticklabels=le.classes_)
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix - Tuesday Traffic")
    plt.savefig("confusion_matrix_tuesday.png")
    print("Confusion matrix saved as confusion_matrix_tuesday.png")
    plt.show()

if __name__ == "__main__":
    if not Path(INPUT_CSV).exists():
        print(f"Error: {INPUT_CSV} not found!")
    else:
        X, y, le, scaler = load_and_preprocess(INPUT_CSV)
        model, X_test, y_test = train_model(X, y)
        
        # Save artifacts
        joblib.dump(model, MODEL_PATH)
        joblib.dump(scaler, SCALER_PATH)
        joblib.dump(le, LABEL_ENCODER_PATH)
        print(f"Model saved to {MODEL_PATH}")
        print(f"Scaler saved to {SCALER_PATH}")
        print(f"Label Encoder saved to {LABEL_ENCODER_PATH}")
        
        plot_results(model, X_test, y_test, le)
