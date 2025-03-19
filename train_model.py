import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os
import requests
from io import StringIO
import matplotlib.pyplot as plt
import seaborn as sns
from feature_extraction import get_feature_names

def download_dataset():
    """Download the phishing dataset if it doesn't exist"""
    data_dir = 'data'
    os.makedirs(data_dir, exist_ok=True)
    
    dataset_path = os.path.join(data_dir, 'phishing_dataset.csv')
    
    if not os.path.exists(dataset_path):
        print("Downloading phishing dataset...")
        # Using the UCI Machine Learning Repository - Phishing Websites Dataset
        url = "https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff"
        
        try:
            response = requests.get(url)
            if response.status_code == 200:
                # Parse ARFF file and convert to CSV
                lines = response.text.split('\n')
                data_start = False
                data_lines = []
                
                for line in lines:
                    if line.lower().startswith('@data'):
                        data_start = True
                        continue
                    if data_start and line.strip():
                        data_lines.append(line)
                
                # Convert to CSV
                csv_content = '\n'.join(data_lines)
                df = pd.read_csv(StringIO(csv_content), header=None)
                
                # The last column is the class (1 for phishing, -1 for legitimate)
                # Convert -1 to 0 for binary classification
                df[df.columns[-1]] = df[df.columns[-1]].replace(-1, 0)
                
                # Save to CSV
                df.to_csv(dataset_path, index=False)
                print(f"Dataset saved to {dataset_path}")
                return df
            else:
                print(f"Failed to download dataset: {response.status_code}")
        except Exception as e:
            print(f"Error downloading dataset: {e}")
    else:
        print(f"Dataset already exists at {dataset_path}")
        return pd.read_csv(dataset_path)
    
    # If we get here, create a small synthetic dataset
    print("Creating synthetic dataset for demonstration...")
    np.random.seed(42)
    n_samples = 1000
    n_features = 18  # Match the number of features in extract_features
    
    X = np.random.rand(n_samples, n_features)
    y = np.random.randint(0, 2, n_samples)
    
    df = pd.DataFrame(X)
    df['target'] = y
    df.to_csv(dataset_path, index=False)
    print(f"Synthetic dataset saved to {dataset_path}")
    return df

def train_model():
    """Train the phishing detection model"""
    # Load or download the dataset
    df = download_dataset()
    
    # Split features and target
    X = df.iloc[:, :-1]  # All columns except the last
    y = df.iloc[:, -1]   # Only the last column
    
    # Split into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print(f"Training data shape: {X_train.shape}")
    print(f"Testing data shape: {X_test.shape}")
    
    # Train a Random Forest classifier
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Plot feature importance
    feature_importance = model.feature_importances_
    feature_names = get_feature_names()
    
    # Ensure we have the same number of feature names as features
    if len(feature_names) > len(feature_importance):
        feature_names = feature_names[:len(feature_importance)]
    elif len(feature_names) < len(feature_importance):
        feature_names.extend([f"Feature {i}" for i in range(len(feature_names), len(feature_importance))])
    
    # Sort features by importance
    indices = np.argsort(feature_importance)[::-1]
    
    plt.figure(figsize=(10, 6))
    plt.title("Feature Importance")
    plt.bar(range(len(indices)), feature_importance[indices], align='center')
    plt.xticks(range(len(indices)), [feature_names[i] for i in indices], rotation=90)
    plt.tight_layout()
    plt.savefig('static/feature_importance.png')
    print("Feature importance plot saved to static/feature_importance.png")
    
    # Save the model
    model_path = 'phishing_detector_model.pkl'
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")
    
    return model

if __name__ == "__main__":
    train_model()