from flask import Flask, render_template, request, jsonify, redirect, url_for
import joblib
from feature_extraction import extract_features, get_feature_names
from safe_browsing import check_url_safety
from history_manager import HistoryManager
import os
import pandas as pd
import numpy as np
from dotenv import load_dotenv
import json
import streamlit as st


load_dotenv()

app = Flask(__name__)
history_manager = HistoryManager()

# Load the model
model_path = 'phishing_detector_model.pkl'
if not os.path.exists(model_path):
    print("Model not found. Training a new model...")
    from train_model import train_model
    model = train_model()
else:
    model = joblib.load(model_path)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form['url']
    
    # Extract features
    features = extract_features(url)
    feature_names = get_feature_names()
    
    # Make prediction
    prediction = model.predict([features])[0]
    probability = model.predict_proba([features])[0][1]  # Probability of being phishing
    
    # Check with Google Safe Browsing API
    safe_browsing_result = check_url_safety(url)
    
    # Create a dictionary of features for display
    features_dict = {}
    for i, feature_name in enumerate(feature_names):
        if i < len(features):
            features_dict[feature_name] = features[i]
    
    # Store in history
    history_manager.add_url(url, bool(prediction), float(probability), features_dict)
    
    # Prepare result
    result = {
        'url': url,
        'is_phishing': bool(prediction),
        'probability': float(probability) * 100,  # Convert to percentage
        'features': features_dict,
        'safe_browsing': safe_browsing_result,
        'risk_level': get_risk_level(probability)
    }
    
    return jsonify(result)

@app.route('/history')
def history():
    url_history = history_manager.get_history()
    return render_template('history.html', history=url_history)

@app.route('/clear_history', methods=['POST'])
def clear_history():
    history_manager.clear_history()
    return redirect(url_for('history'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for browser extension or other clients"""
    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Extract features
    features = extract_features(url)
    feature_names = get_feature_names()
    
    # Make prediction
    prediction = model.predict([features])[0]
    probability = model.predict_proba([features])[0][1]
    
    # Check with Google Safe Browsing API
    safe_browsing_result = check_url_safety(url)
    
    # Create a dictionary of features
    features_dict = {}
    for i, feature_name in enumerate(feature_names):
        if i < len(features):
            features_dict[feature_name] = features[i]
    
    # Store in history
    history_manager.add_url(url, bool(prediction), float(probability), features_dict)
    
    # Prepare result
    result = {
        'url': url,
        'is_phishing': bool(prediction),
        'probability': float(probability) * 100,  # Convert to percentage
        'features': features_dict,
        'safe_browsing': safe_browsing_result,
        'risk_level': get_risk_level(probability)
    }
    
    return jsonify(result)

def get_risk_level(probability):
    """Get the risk level based on probability"""
    if probability < 0.2:
        return "Low"
    elif probability < 0.6:
        return "Medium"
    else:
        return "High"

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=True)

@app.route("/")
def home():
    return "Hello, Railway!"

if __name__ == "__main__":
    app.run()