import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

INPUT_CSV = "synthetic_attacks_features.csv"
if not Path(INPUT_CSV).exists():
    INPUT_CSV = "live_attacks_features.csv"
if not Path(INPUT_CSV).exists():
	INPUT_CSV = "honeypot_features.csv"

df = pd.read_csv(INPUT_CSV)


df['label'] = 0  
df.loc[df['packet_count'] > 10, 'label'] = 1  


features = ['packet_count', 'total_bytes', 'duration', 'src_bytes', 'dst_bytes']
X = df[features]
y = df['label']


scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)


X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42)


clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)


y_pred = clf.predict(X_test)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))


cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Confusion Matrix")
plt.show()
