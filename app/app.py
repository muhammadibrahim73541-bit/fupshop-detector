import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from flask import Flask, request, jsonify, render_template
from predict import FupShopPredictor, download_model_if_needed

app = Flask(__name__, template_folder='templates')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, 'src', 'models', 'fupshop_model.pkl')

# Download model if not present (for HF Spaces deployment)
if not os.path.exists(MODEL_PATH):
    try:
        download_model_if_needed()
    except Exception as e:
        print(f"Warning: Could not download model: {e}")
        print("App will fail on first prediction if model is missing.")

predictor = FupShopPredictor(model_path=MODEL_PATH)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict_endpoint():
    data = request.get_json() or request.form
    url = data.get('url', '').strip()
    cvr = data.get('cvr', '').strip()
    
    if not url:
        return jsonify({"error": "URL required"}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    result = predictor.predict(url, cvr=cvr if cvr else None)
    prob = result['phishing_probability']
    features = result['features']
    llm_reason = result['llm_reasoning']
    
    # Risk level
    risk_score = prob * 100
    if risk_score < 30:
        risk_level = 'SAFE'
        color = 'green'
    elif risk_score < 70:
        risk_level = 'CAUTION'
        color = 'gold'
    else:
        risk_level = 'DANGER'
        color = 'red'
    
    # Technical reasons
    reasons = []
    
    if not features['has_ssl']:
        reasons.append("No SSL certificate — data transmitted in plaintext")
    else:
        reasons.append("SSL certificate present — connection is encrypted")
    
    if features['typosquatting_score'] > 0.7:
        reasons.append(f"Domain closely resembles a known Danish shop (typosquatting score: {features['typosquatting_score']:.2f})")
    elif features['typosquatting_score'] > 0.3:
        reasons.append(f"Domain similar to known brand (typosquatting score: {features['typosquatting_score']:.2f})")
    
    if features['domain_age_real']:
        if features['domain_age_days'] > 3650:
            reasons.append(f"Domain is well-established ({features['domain_age_days']:.0f} days old)")
        elif features['domain_age_days'] < 30:
            reasons.append(f"Domain appears very new ({features['domain_age_days']:.0f} days old)")
    else:
        reasons.append("Domain age unknown — WHOIS lookup failed")
    
    if not features['dns_resolved']:
        reasons.append("DNS resolution failed — domain may not exist")
    
    if features['suspicious_keyword_count'] > 0:
        reasons.append(f"Contains {int(features['suspicious_keyword_count'])} suspicious keywords")
    
    if features['has_ip_address']:
        reasons.append("Uses raw IP address instead of domain name")
    
    if features['multiple_subdomains']:
        reasons.append("Unusual subdomain structure detected")
    
    if features['domain_entropy'] > 3.5:
        reasons.append("High domain randomness — possibly auto-generated")
    
    if features['cvr_found']:
        reasons.append("CVR number verified in Danish company registry")
    elif cvr:
        reasons.append("CVR number not found in registry")
    
    if features['vt_malicious'] > 0:
        reasons.append(f"Flagged by {int(features['vt_malicious'])} security engines on VirusTotal")
    
    if not reasons:
        reasons.append("No significant risk factors detected")
    
    return jsonify({
        "url": result['url'],
        "domain": url.replace('https://', '').replace('http://', '').split('/')[0],
        "risk_score": round(risk_score, 1),
        "risk_level": risk_level,
        "color": color,
        "prediction": result['prediction'],
        "llm_reasoning": llm_reason,
        "features": {
            "has_ssl": features['has_ssl'],
            "ssl_days_left": features['ssl_days_left'],
            "cvr_found": features['cvr_found'],
            "domain_age_days": features['domain_age_days'],
            "domain_age_real": features['domain_age_real'],
            "dns_resolved": features['dns_resolved'],
            "dns_ip": features['dns_ip'],
            "vt_malicious": features['vt_malicious'],
            "typosquatting_score": features['typosquatting_score'],
            "char_substitution_detected": features['char_substitution_detected'],
            "domain_entropy": features['domain_entropy'],
            "suspicious_keyword_count": features['suspicious_keyword_count']
        },
        "reasons": reasons,
        "scan_id": str(uuid.uuid4())[:8]
    })

@app.route('/health')
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": os.path.exists(MODEL_PATH),
        "model_path": MODEL_PATH,
        "model_accuracy": "94.51%",
        "dataset_size": "1091 URLs (900 phishing + 191 legitimate)",
        "features": "31 features including DNS, WHOIS, typosquatting, LLM reasoning",
        "version": "v2.0"
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
