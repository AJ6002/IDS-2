# Import necessary libraries
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Load dataset (UCI Heart Disease dataset)
url = "https://archive.ics.uci.edu/ml/machine-learning-databases/heart-disease/processed.cleveland.data"
column_names = ['age', 'sex', 'cp', 'trestbps', 'chol', 'fbs', 'restecg', 'thalach', 'exang', 'oldpeak', 'slope', 'ca', 'thal', 'target']
data = pd.read_csv(url, names=column_names)

# Check for missing data and replace '?' with NaN
data.replace('?', np.nan, inplace=True)

# Convert columns with missing values to appropriate types
data = data.apply(pd.to_numeric, errors='coerce')

# Drop rows with any missing values
data.dropna(inplace=True)

# Split the data into features (X) and target (y)
X = data.drop('target', axis=1)
y = data['target']

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Initialize the Random Forest Classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)

# Train the model
model.fit(X_train, y_train)

# Evaluate the model's performance on the test set (optional)
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy * 100:.2f}%")

# Function to take user input and make predictions
def predict_heart_disease():
    print("Please enter the following details to check your heart disease risk:")
    
    # Take input from the user
    age = float(input("Age: "))
    sex = int(input("Sex (1 = Male, 0 = Female): "))
    cp = int(input("Chest Pain Type (0 = None, 1 = Typical Angina, 2 = Atypical Angina, 3 = Non-anginal Pain, 4 = Asymptomatic): "))
    trestbps = float(input("Resting Blood Pressure (mm Hg): "))
    chol = float(input("Serum Cholesterol (mg/dl): "))
    fbs = int(input("Fasting Blood Sugar > 120 mg/dl (1 = True, 0 = False): "))
    restecg = int(input("Resting Electrocardiographic Results (0 = Normal, 1 = Having ST-T wave abnormality, 2 = Showing probable or definite left ventricular hypertrophy): "))
    thalach = float(input("Maximum Heart Rate Achieved: "))
    exang = int(input("Exercise Induced Angina (1 = Yes, 0 = No): "))
    oldpeak = float(input("Depression Induced by Exercise Relative to Rest: "))
    slope = int(input("Slope of the Peak Exercise ST Segment (1 = Upsloping, 2 = Flat, 3 = Downsloping): "))
    ca = int(input("Number of Major Vessels Colored by Fluoroscopy (0-3): "))
    thal = int(input("Thalassemia (3 = Normal, 6 = Fixed Defect, 7 = Reversable Defect): "))

    # Create a DataFrame for the input data
    user_input = pd.DataFrame({
        'age': [age],
        'sex': [sex],
        'cp': [cp],
        'trestbps': [trestbps],
        'chol': [chol],
        'fbs': [fbs],
        'restecg': [restecg],
        'thalach': [thalach],
        'exang': [exang],
        'oldpeak': [oldpeak],
        'slope': [slope],
        'ca': [ca],
        'thal': [thal]
    })

    # Make prediction
    prediction = model.predict(user_input)
    
    # Output result
    if prediction == 1:
        print("\nYou are at risk of heart disease.")
    else:
        print("\nYou are not at risk of heart disease.")

# Call the function to get user input and make prediction
predict_heart_disease()
