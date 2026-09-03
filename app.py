import os
import re
import sqlite3
import torch
import numpy as np
import cv2
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
from lime.lime_text import LimeTextExplainer

app = Flask(__name__)
app.secret_key = 'super_secret_phishing_project_key'  # Required for session handling

DATABASE = 'users.db'

# --- DATABASE SETUP ---
def init_db():
    """Creates the user and analytics tables in SQLite."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # Analytics / Scans history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            scan_type TEXT,
            prediction TEXT,
            confidence REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # Create a default admin account if it doesn't exist
    cursor.execute("SELECT * FROM users WHERE email = 'admin@system.com'")
    if not cursor.fetchone():
        admin_pass = generate_password_hash('admin123', method='scrypt')
        cursor.execute("INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)",
                       ("System Admin", "admin@system.com", "0000000000", admin_pass))
        
    conn.commit()
    conn.close()

init_db()

# --- MODEL SETUP ---
MODEL_ID = "your-username/distilbert-sms-phishing"

print("Loading DistilBERT model and tokenizer from Hugging Face Hub...")
try:
    tokenizer = DistilBertTokenizer.from_pretrained(MODEL_ID)
    model = DistilBertForSequenceClassification.from_pretrained(MODEL_ID)
    model.eval()
    print("Model loaded successfully from cloud!")
except Exception as e:
    print(f"Error loading model: {e}")

# --- EXPLAINABLE AI (LIME) SETUP ---
print("Initializing LIME Explainer...")
explainer = LimeTextExplainer(class_names=['Ham', 'Spam'])

def lime_predictor(texts):
    """Wrapper function for LIME to send batches of text to DistilBERT."""
    inputs = tokenizer(
        texts,
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=512
    )
    with torch.no_grad():
        outputs = model(**inputs)
    
    probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
    return probabilities.numpy()

def explain_prediction(text, prediction):
    """Runs LIME to find the specific words that triggered a Spam alert."""
    if prediction == "Ham":
        return []
    
    exp = explainer.explain_instance(text, lime_predictor, num_features=6, num_samples=100)
    word_weights = exp.as_list(label=1)
    
    trigger_words = [word for word, weight in word_weights if weight > 0]
    return trigger_words

# --- INFERENCE FUNCTIONS ---
def run_text_inference(text):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=512)
    with torch.no_grad():
        outputs = model(**inputs)
    probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
    predicted_class_id = torch.argmax(probabilities, dim=-1).item()
    confidence = probabilities[0][predicted_class_id].item() * 100
    labels = {0: "Ham", 1: "Spam"}
    return labels.get(predicted_class_id, "Unknown"), round(confidence, 2)

def analyze_url_heuristics(url):
    score = 0
    if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        score += 3
    if len(url) > 75:
        score += 2
    if url.count('-') > 3 or '@' in url:
        score += 2
    if not url.startswith('https://'):
        score += 1

    if score >= 3:
        return "Phishing", min(85.0 + (score * 2), 99.0)
    else:
        return "Safe", round(90.0 - (score * 5), 2)

# --- AUTH ROUTES ---

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        phone = request.form['phone'].strip()
        password = request.form['password']

        hashed_password = generate_password_hash(password, method='scrypt')

        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)",
                           (name, email, phone, hashed_password))
            conn.commit()
            conn.close()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email or Phone Number already exists.', 'error')
            return redirect(url_for('signup'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier'].strip().lower()
        password = request.form['password']

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ? OR phone = ?", (identifier, identifier))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[4], password):
            session['user_id'] = user[0]
            session['user_name'] = user[1]
            session['user_email'] = user[2]
            return redirect(url_for('home'))
        else:
            flash('Invalid Email/Phone or Password.', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))


# --- MAIN DASHBOARD ROUTE ---

@app.route('/')
def home():
    user_name = session.get('user_name', None)
    return render_template('index.html', user_name=user_name)


@app.route('/predict', methods=['POST'])
def predict():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized access'}), 401

    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({'error': 'No input text provided'}), 400

    input_text = data['text'].strip()
    detection_type = data.get('type', 'email')

    if not input_text:
        return jsonify({'error': 'Input text cannot be empty'}), 400

    trigger_words = []

    if detection_type == 'link':
        prediction, confidence = analyze_url_heuristics(input_text)
    else:
        prediction, confidence = run_text_inference(input_text)
        if prediction == "Spam":
            trigger_words = explain_prediction(input_text, prediction)

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scans (user_id, scan_type, prediction, confidence) VALUES (?, ?, ?, ?)",
                   (session['user_id'], detection_type, prediction, confidence))
    conn.commit()
    conn.close()

    return jsonify({
        'prediction': prediction,
        'confidence': confidence,
        'type': detection_type,
        'trigger_words': trigger_words
    })


@app.route('/predict-qr', methods=['POST'])
def predict_qr():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized access'}), 401

    if 'file' not in request.files:
        return jsonify({'error': 'No image file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    try:
        file_bytes = np.frombuffer(file.read(), np.uint8)
        img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)

        if img is None:
            return jsonify({'error': 'Invalid image file format'}), 400

        qr_detector = cv2.QRCodeDetector()
        extracted_text = ""
        try:
            data, _, _ = qr_detector.detectAndDecode(img)
            if data:
                extracted_text = data.strip()
        except Exception:
            pass

        if not extracted_text:
            try:
                retval, decoded_info, _ = qr_detector.detectAndDecodeMulti(img)
                if retval and decoded_info:
                    extracted_text = decoded_info[0].strip()
            except Exception:
                pass

        if not extracted_text:
            return jsonify({
                'prediction': 'Safe', 
                'confidence': 100.0, 
                'extracted_text': 'No QR code or readable text detected in the image.'
            })

        if extracted_text.startswith('http://') or extracted_text.startswith('https://') or '.' in extracted_text:
            prediction, confidence = analyze_url_heuristics(extracted_text)
            detection_type = 'qr-link'
        else:
            prediction, confidence = run_text_inference(extracted_text)
            detection_type = 'qr-text'

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO scans (user_id, scan_type, prediction, confidence) VALUES (?, ?, ?, ?)",
                       (session['user_id'], detection_type, prediction, confidence))
        conn.commit()
        conn.close()

        return jsonify({
            'prediction': prediction,
            'confidence': confidence,
            'type': detection_type,
            'extracted_text': extracted_text
        })

    except Exception as e:
        return jsonify({'error': f'Failed to process image: {str(e)}'}), 500


@app.route('/chat', methods=['POST'])
def security_agent():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized access'}), 401

    data = request.get_json()
    query = data.get('message', '').strip().lower()

    if not query:
        return jsonify({'response': 'Please enter a valid security question.'})

    if 'link' in query or 'url' in query:
        response = "Link Guard Analysis: Check for mismatched domains, IP-based URLs, or URL shorteners. You can test any link using our Link & URL Checker tab above."
    elif 'email' in query or 'phish' in query:
        response = "Email Phishing Insight: Generative AI makes phishing emails look professional. Watch out for urgent calls-to-action, financial requests, and spoofed sender headers."
    elif 'sms' in query or 'text' in query:
        response = "Smishing Alert: Smishing texts often pretend to be package delivery or bank alerts. Legitimate entities rarely send login links via standard SMS numbers."
    elif 'qr' in query or 'code' in query:
        response = "Qrishing Warning: Attackers embed malicious URLs inside QR codes to bypass text filters. Always upload and inspect QR codes using our new QR Scanner tab!"
    elif 'lime' in query or 'explain' in query:
        response = "Explainable AI (LIME): When our DistilBERT model flags an email as Spam, LIME breaks down the text and highlights the exact trigger words that caused the alert."
    else:
        response = "AI Security Agent: I've processed your query. Paste suspicious text into our Email/SMS tabs, enter a URL, or upload a QR code for deep learning evaluation!"

    return jsonify({'response': response})


@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or session.get('user_email') != 'admin@system.com':
        flash('Access Denied. Administrator privileges required.', 'error')
        return redirect(url_for('home'))
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE prediction IN ('Spam', 'Phishing')")
    threats_blocked = cursor.fetchone()[0]
    
    cursor.execute("SELECT prediction, COUNT(*) FROM scans GROUP BY prediction")
    chart_data = dict(cursor.fetchall())
    
    cursor.execute('''
        SELECT users.name, scans.scan_type, scans.prediction, scans.confidence, scans.timestamp 
        FROM scans 
        JOIN users ON scans.user_id = users.id 
        ORDER BY scans.timestamp DESC LIMIT 10
    ''')
    recent_scans = cursor.fetchall()
    conn.close()
    
    return render_template('admin.html', 
                           total_users=total_users, 
                           total_scans=total_scans, 
                           threats_blocked=threats_blocked,
                           chart_data=chart_data,
                           recent_scans=recent_scans)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)