import os
import sys
import json

# Add src to path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from flask import Flask, request, jsonify, render_template
from data_ingestion import DataIngestion
from data_transformation import extract_features
from model_trainer import predict
from database import save_scan, save_user_report, get_scan_history

app = Flask(__name__, template_folder='templates')

@app.route('/')
def home():
    """Main page with input form."""
    history = get_scan_history(10)
    return render_template('index.html', history=history)

@app.route('/predict', methods=['POST'])
def predict_endpoint():
    """API endpoint: scan a URL and return risk score."""
    data = request.get_json() or request.form
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({"error": "URL required"}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Extract CVR from URL if possible (simplified)
    cvr = data.get('cvr', None)
    
    # Run ingestion
    ingest = DataIngestion()
    raw_data = ingest.ingest_all(url, cvr)
    
    # Extract features
    features = extract_features(raw_data)
    
    # Predict
    result = predict(features)
    
    # Save to database
    scan_id = save_scan(
        url=url,
        domain=raw_data['domain'],
        risk_score=result['risk_score'],
        prediction=result['prediction'],
        features=features,
        raw_data=raw_data,
        shap_exp=result['top_reasons']
    )
    
    return jsonify({
        "scan_id": scan_id,
        "url": url,
        "domain": raw_data['domain'],
        "risk_score": round(result['risk_score'], 1),
        "prediction": result['prediction'],
        "reasons": result['top_reasons'],
        "features": features
    })

@app.route('/report', methods=['POST'])
def report_scam():
    """User reports a scam URL."""
    data = request.get_json() or request.form
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({"error": "URL required"}), 400
    
    domain = url.replace('https://', '').replace('http://', '').split('/')[0]
    
    save_user_report(
        url=url,
        domain=domain,
        lost_money=1 if data.get('lost_money') else 0,
        amount_lost=data.get('amount_lost'),
        description=data.get('description')
    )
    
    return jsonify({"message": "Report saved. Thank you!"})

@app.route('/api/history')
def api_history():
    """Get recent scans for dashboard."""
    limit = request.args.get('limit', 50, type=int)
    history = get_scan_history(limit)
    return jsonify([{
        "url": h[0],
        "domain": h[1],
        "risk_score": h[2],
        "prediction": h[3],
        "date": h[4]
    } for h in history])

@app.route('/health')
def health():
    """Health check for Render."""
    return jsonify({"status": "ok", "model_loaded": os.path.exists('../models/model.pkl')})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)