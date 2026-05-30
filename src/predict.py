import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import joblib
import json
import requests
import numpy as np
from features.url_features import URLFeatureExtractor

# Load .env
from dotenv import load_dotenv
load_dotenv('/workspaces/fupshop-detector/.env')

class FupShopPredictor:
    def __init__(self, model_path: str = None):
        if model_path is None:
            model_path = os.path.join(os.path.dirname(__file__), 'models', 'fupshop_model.pkl')
        
        self.model = joblib.load(model_path)
        with open(model_path.replace('.pkl', '_features.json'), 'r') as f:
            self.feature_names = json.load(f)
        self.extractor = URLFeatureExtractor()
        self.openrouter_key = os.getenv('OPENROUTER_KEY')
        self.llm_model = 'google/gemma-4-31b-it:free'
    
    def predict(self, url: str, cvr: str = None) -> dict:
        features = self.extractor.extract(url, cvr=cvr)
        feature_vector = np.array([[features[name] for name in self.feature_names]])
        prob = self.model.predict_proba(feature_vector)[0][1]
        prediction = "PHISHING" if prob > 0.5 else "LEGITIMATE"
        
        llm_reason = self._get_llm_reason(url, features, prediction, prob)
        
        return {
            'url': url,
            'prediction': prediction,
            'phishing_probability': float(prob),
            'features': features,
            'llm_reasoning': llm_reason
        }
    
    def _get_llm_reason(self, url: str, features: dict, prediction: str, prob: float) -> str:
        if not self.openrouter_key:
            return "LLM reasoning not available (no API key configured)"
        
        risk_level = "HIGH RISK" if prob > 0.7 else "MEDIUM RISK" if prob > 0.4 else "LOW RISK"
        
        prompt = f"""You are a cybersecurity expert analyzing URLs for phishing scams. 
Given this URL analysis, explain in 2-3 sentences why this URL is {risk_level}.

URL: {url}
Prediction: {prediction}
Phishing Probability: {prob:.1%}

Key Features:
- SSL Certificate: {'Yes' if features['has_ssl'] else 'No'}
- Domain Age: {features['domain_age_days']:.0f} days
- DNS Resolved: {'Yes' if features['dns_resolved'] else 'No (could be new domain or temporary issue)'}
- Typosquatting Score: {features['typosquatting_score']:.2f}
- Character Substitution Detected: {'Yes' if features['char_substitution_detected'] else 'No'}
- Suspicious Keywords: {int(features['suspicious_keyword_count'])}
- Domain Entropy: {features['domain_entropy']:.2f}
- VirusTotal Flags: {int(features['vt_malicious'])}

Give a concise, expert explanation for a non-technical user. Focus on the most important red flags. Be direct and actionable."""

        try:
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.openrouter_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://fupshop-detector.local",
                    "X-Title": "FupShop Detector"
                },
                json={
                    "model": self.llm_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 200
                },
                timeout=20
            )
            
            if response.status_code == 200:
                data = response.json()
                content = data['choices'][0]['message']['content'].strip()
                return content if content else "LLM returned empty response"
            else:
                return f"LLM error: {response.status_code} - {response.text[:150]}"
        except Exception as e:
            return f"LLM unavailable: {str(e)[:100]}"
    
    def predict_batch(self, urls: list) -> list:
        return [self.predict(url) for url in urls]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python predict.py <URL> [CVR]")
        sys.exit(1)
    
    url = sys.argv[1]
    cvr = sys.argv[2] if len(sys.argv) > 2 else None
    predictor = FupShopPredictor()
    result = predictor.predict(url, cvr=cvr)
    
    print(f"\nURL: {result['url']}")
    print(f"Prediction: {result['prediction']}")
    print(f"Phishing Probability: {result['phishing_probability']:.4f}")
    print(f"\nLLM Reasoning:")
    print(result['llm_reasoning'])
    print(f"\nDNS Resolved: {bool(result['features']['dns_resolved'])}")
    print(f"WHOIS Age: {result['features']['domain_age_days']:.0f} days")
    print(f"Typosquatting: {result['features']['typosquatting_score']}")
