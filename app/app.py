import os
import sys

# Add src to path so 'predict' and other modules are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from flask import Flask, request, jsonify, render_template
from predict import FupShopPredictor

app = Flask(__name__, template_folder='templates')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'src', 'models', 'fupshop_model.pkl')

predictor = FupShopPredictor(model_path=MODEL_PATH)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict_endpoint():
    data = request.get_json() or request.form
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({"error": "URL required"}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    result = predictor.predict(url)
    prob = result['phishing_probability']
    
    reasons = []
    features = result['features']
    
    if not features['has_https']:
        reasons.append({"icon": "🔒", "title": "No SSL Certificate", "desc": "Connection not encrypted"})
    
    if features['has_ip_address']:
        reasons.append({"icon": "🌐", "title": "IP Address URL", "desc": "Uses raw IP instead of domain"})
    
    if features['suspicious_keyword_count'] > 0:
        reasons.append({"icon": "⚠️", "title": "Suspicious Keywords", "desc": f"Found {int(features['suspicious_keyword_count'])} suspicious terms"})
    
    if features['multiple_subdomains']:
        reasons.append({"icon": "📁", "title": "Multiple Subdomains", "desc": "Unusual subdomain structure"})
    
    if features['domain_entropy'] > 3.5:
        reasons.append({"icon": "🔀", "title": "High Domain Entropy", "desc": "Domain appears randomly generated"})
    
    if features['brand_in_domain'] or features['brand_in_path']:
        reasons.append({"icon": "🏷️", "title": "Brand Impersonation", "desc": "Contains well-known brand names"})
    
    if features['dot_count'] > 4:
        reasons.append({"icon": "•••", "title": "Many Dots", "desc": f"{int(features['dot_count'])} dots in URL (suspicious)"})
    
    if not reasons:
        reasons.append({"icon": "✅", "title": "Clean URL Structure", "desc": "No obvious red flags detected"})
    
    risk_score = prob * 100
    
    return jsonify({
        "url": result['url'],
        "domain": url.replace('https://', '').replace('http://', '').split('/')[0],
        "risk_score": round(risk_score, 1),
        "prediction": "HIGH RISK" if risk_score > 70 else "MEDIUM RISK" if risk_score > 40 else "LOW RISK",
        "top_reasons": reasons[:4],
        "features": {k: round(v, 3) for k, v in features.items()}
    })

@app.route('/health')
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": os.path.exists(MODEL_PATH),
        "model_path": MODEL_PATH,
        "model_accuracy": "98.74%",
        "dataset_size": "1593 URLs (1400 phishing + 193 legitimate)"
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
