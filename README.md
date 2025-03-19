# 🛡️ Phishing URL Detector  

This is a **machine learning-based phishing URL detection** web application. It extracts features from a URL, applies a trained **Random Forest Classifier**, and predicts whether the URL is **legitimate or phishing**.  

## 💂 Project Structure  

```
📺 phishing-url-detector  
👉 data/  
👉 phishing_dataset.csv    # Dataset for training  
👉 static/  
👉 css/  
👉 style.css           # Frontend styles  
👉 js/  
👉 main.js             # JavaScript for frontend logic  
👉 feature_importance.png  # Feature importance visualization  
👉 templates/  
👉 index.html              # Home page  
👉 about.html              # About page  
👉 history.html            # Browsing history page  
👉 venv/                       # Virtual environment (not included in Git)  
👉 .env                        # Environment variables (not included in Git)  
👉 .gitignore                  # Files to ignore in Git  
👉 app.py                      # Flask app backend  
👉 feature_extraction.py       # Extracts URL features for prediction  
👉 history_manager.py          # Manages URL history storage  
👉 phishing_detector_model.pkl # Trained model  
👉 README.md                   # Project documentation  
👉 requirements.txt            # Python dependencies  
👉 safe_browsing.py            # Google Safe Browsing API integration  
👉 train_model.py              # Script to train the ML model  
👉 url_history.json            # Stores visited URLs  
```

---

## 🚀 Features  

✅ Extracts **30+ features** from a given URL  
✅ Uses a **trained Random Forest Model** to classify URLs  
✅ Stores history of analyzed URLs  
✅ Google Safe Browsing API integration *(optional)*  
✅ Simple **Flask Web App with HTML, CSS, and JavaScript**  

---

## 🛠️ Installation  

### 1️⃣ Clone the Repository  

```bash
git clone https://github.com/yourusername/phishing-url-detector.git
cd phishing-url-detector
```

### 2️⃣ Create a Virtual Environment  

```bash
python -m venv venv
source venv/bin/activate  # For macOS/Linux
venv\Scripts\activate      # For Windows
```

### 3️⃣ Install Dependencies  

```bash
pip install -r requirements.txt
```

### 4️⃣ Run the Application  

```bash
python app.py
```

The app will run on **http://127.0.0.1:5000/**.

---

## 📦 Model Training  

To train the phishing detection model, run:

```bash
python train_model.py
```

This will generate `phishing_detector_model.pkl`, which the app will use.

---

