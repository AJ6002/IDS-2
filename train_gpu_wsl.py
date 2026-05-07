import sys
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import xgboost as xgb
import time
import warnings
warnings.filterwarnings('ignore')

# 1. Load the Data
dataset_file = sys.argv[1] if len(sys.argv) > 1 else 'combine.csv'
print(f"Loading dataset {dataset_file}...")
start_time = time.time()
df = pd.read_csv(dataset_file, low_memory=False)
print(f"Loaded in {time.time() - start_time:.2f} seconds. Shape: {df.shape}")

# 2. Clean the Data
print("Cleaning data and dropping NaNs/Infinities...")
df.columns = df.columns.str.strip()  # Remove leading/trailing spaces in column names

# CICIDS2017 often has Infinity or NaNs in Flow Bytes/s. We must remove them for XGBoost.
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# 3. Label Encoding (BENIGN = 0, ATTACK = 1)
print("Encoding Labels...")
df['Is_Attack'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
X = df.drop(columns=['Label', 'Is_Attack'])
y = df['Is_Attack']

# Ensure all features are numeric
X = X.apply(pd.to_numeric, errors='coerce')
X.fillna(0, inplace=True)

# 4. Train/Test Split
print("Splitting data into 80% Train, 20% Test...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# 5. Initialize GPU-Accelerated XGBoost
# In XGBoost 2.0+, tree_method='hist' and device='cuda' forces RTX / CUDA usage
print("\n🔥 Firing up CUDA / RTX 3050 for Training 🔥...")
clf = xgb.XGBClassifier(
    n_estimators=100, 
    max_depth=8, 
    learning_rate=0.1, 
    tree_method='hist',   # Optimized histogram construction
    device='cuda',        # Force CUDA execution
    random_state=42
)

# 6. Train the Model
start_train = time.time()
clf.fit(X_train, y_train)
train_duration = time.time() - start_train
print(f"✅ GPU Training finished in just {train_duration:.2f} seconds!")

# 7. Evaluation
print("\nEvaluating Model on Test Data...")
y_pred = clf.predict(X_test)
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['BENIGN (0)', 'ATTACK (1)']))

# 8. Save the Model
model_filename = "xgboost_ids_gpu.model"
clf.save_model(model_filename)
print(f"Model successfully saved to {model_filename}")
