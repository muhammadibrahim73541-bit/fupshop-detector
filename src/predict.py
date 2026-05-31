import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import joblib
import json
import requests
import numpy as np
import time
from datetime import datetime
from features.url_features import URLFeatureExtractor

from dotenv import load_dotenv
load_dotenv('/workspaces/fupshop-detector/.env')

import wandb

def download_model_if_needed():
    model_dir = os.path.join(os.path.dirname(__file__), 'models')
    model_path = os.path.join(model_dir, 'fupshop_model.pkl')
    if os.path.exists(model_path):
        return model_path
    print("Model not found locally. Downloading from Hugging Face Hub...")
    try:
        from huggingface_hub import hf_hub_download
        files = [
            'src/models/fupshop_model.pkl',
            'src/models/fupshop_model_features.json',
            'src/models/fupshop_model_metrics.json'
        ]
        for file in files:
            hf_hub_download(
                repo_id='mibrahimalpha/fupshop-detector',
                filename=file,
                repo_type='space',
                local_dir=model_dir,
                local_dir_use_symlinks=False
            )
            print(f"Downloaded {os.path.basename(file)}")
        return model_path
    except Exception as e:
        print(f"Failed to download model: {e}")
        raise

class FupShopPredictor:
    def __init__(self, model_path: str = None):
        if model_path is None:
            model_path = download_model_if_needed()
        self.model = joblib.load(model_path)
        with open(model_path.replace('.pkl', '_features.json'), 'r') as f:
            self.feature_names = json.load(f)
        self.extractor = URLFeatureExtractor()
        self.openrouter_key = os.getenv('OPENROUTER_KEY')
        self.llm_models = [
            'liquid/lfm-2.5-1.2b-thinking:free',
            'nvidia/nemotron-3-super-120b-a12b:free',
            'poolside/laguna-m.1:free',
        ]
        self.wandb_run = None

    def predict(self, url: str, cvr: str = None, log_wandb: bool = True) -> dict:
        start_time = time.time()
        features = self.extractor.extract(url, cvr=cvr)
        feature_vector = np.array([[features[name] for name in self.feature_names]])
        prob = self.model.predict_proba(feature_vector)[0][1]
        prediction = "PHISHING" if prob > 0.5 else "LEGITIMATE"

        llm_reason = self._get_llm_reason(url, features, prediction, prob)
        if not llm_reason or 'error' in llm_reason.lower() or 'unavailable' in llm_reason.lower():
            llm_reason = self._get_local_reason(url, features, prediction, prob)

        inference_time = time.time() - start_time

        result = {
            'url': url,
            'prediction': prediction,
            'phishing_probability': float(prob),
            'features': features,
            'llm_reasoning': llm_reason,
            'inference_time_ms': round(inference_time * 1000, 2),
            'timestamp': datetime.now().isoformat(),
            'version': 'v2.0'
        }

        if log_wandb:
            self._log_to_wandb(result)

        return result

    def _log_to_wandb(self, result: dict):
        try:
            if self.wandb_run is None:
                self.wandb_run = wandb.init(
                    project='fupshop-detector',
                    name=f"scan-{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                    anonymous='allow',
                    reinit=True
                )
            self.wandb_run.log({
                'phishing_probability': result['phishing_probability'],
                'prediction': 1 if result['prediction'] == 'PHISHING' else 0,
                'inference_time_ms': result['inference_time_ms'],
                'typosquatting_score': result['features']['typosquatting_score'],
                'has_ssl': result['features']['has_ssl'],
                'dns_resolved': result['features']['dns_resolved'],
                'domain_age_days': result['features']['domain_age_days'],
                'vt_malicious': result['features']['vt_malicious'],
            })
            self.wandb_run.log({
                'scan_results': wandb.Table(data=[[
                    result['url'],
                    result['prediction'],
                    result['phishing_probability'],
                    result['features']['typosquatting_score'],
                    result['features']['domain_entropy'],
                    result['timestamp']
                ]], columns=['url', 'prediction', 'probability', 'typosquatting', 'entropy', 'timestamp'])
            })
        except Exception as e:
            print(f"W&B logging skipped: {str(e)[:50]}")

    def _get_llm_reason(self, url: str, features: dict, prediction: str, prob: float) -> str:
        if not self.openrouter_key:
            return ""
        risk_level = "HIGH RISK" if prob > 0.7 else "MEDIUM RISK" if prob > 0.4 else "LOW RISK"
        prompt = f"""You are a cybersecurity expert. Explain in 2 sentences why this URL is {risk_level} for phishing.
URL: {url}
Prediction: {prediction}
Probability: {prob:.1%}
SSL: {'Yes' if features['has_ssl'] else 'No'}
Domain Age: {features['domain_age_days']:.0f} days (verified: {'Yes' if features['domain_age_real'] else 'No'})
DNS: {'Resolved' if features['dns_resolved'] else 'Failed'}
Typosquatting: {features['typosquatting_score']:.2f}
VirusTotal Flags: {int(features['vt_malicious'])}
Be concise and direct. Focus on the biggest red flag. If WHOIS is unavailable, do not mention it as a factor."""
        for model in self.llm_models:
            try:
                response = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.openrouter_key}",
                        "Content-Type": "application/json",
                        "HTTP-Referer": "https://fupshop-detector.local",
                        "X-Title": "FupShop"
                    },
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": 150
                    },
                    timeout=15
                )
                if response.status_code == 200:
                    data = response.json()
                    content = data['choices'][0]['message']['content'].strip()
                    if content and content.lower() not in ['none', 'null', '']:
                        return content
            except:
                continue
        return ""

    def _get_local_reason(self, url: str, features: dict, prediction: str, prob: float) -> str:
        reasons = []
        if features['typosquatting_score'] > 0.7:
            reasons.append(f"uses typosquatting (score: {features['typosquatting_score']:.2f}) to mimic a known brand")
        elif features['typosquatting_score'] > 0.3:
            reasons.append(f"closely resembles a known brand (typosquatting score: {features['typosquatting_score']:.2f})")
        if not features['has_ssl']:
            reasons.append("has no SSL certificate — data is transmitted in plaintext")
        if not features['dns_resolved']:
            reasons.append("DNS resolution failed — the domain may not exist or is temporarily down")
        if features['domain_age_real'] and features['domain_age_days'] < 30:
            reasons.append(f"is very new ({features['domain_age_days']:.0f} days old)")
        if features['vt_malicious'] > 0:
            reasons.append(f"is flagged by {int(features['vt_malicious'])} security engines on VirusTotal")
        if features['suspicious_keyword_count'] > 0:
            reasons.append(f"contains {int(features['suspicious_keyword_count'])} suspicious keywords")
        if features['domain_entropy'] > 3.5:
            reasons.append("has high domain randomness — possibly auto-generated")
        if not reasons:
            if prediction == "PHISHING":
                reasons.append("shows patterns consistent with phishing based on machine learning analysis")
            else:
                reasons.append("shows no significant phishing indicators")
        reason_text = "; ".join(reasons)
        risk_text = "HIGH RISK" if prob > 0.7 else "MEDIUM RISK" if prob > 0.4 else "LOW RISK"
        return f"This URL is {risk_text} because it {reason_text}. {'Avoid this site and use the official website instead.' if prediction == 'PHISHING' else 'This appears to be a legitimate website.'}"

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
    print(f"Inference Time: {result['inference_time_ms']}ms")
    print(f"\nLLM Reasoning:")
    print(result['llm_reasoning'])
    print(f"\nDNS Resolved: {bool(result['features']['dns_resolved'])}")
    print(f"WHOIS Age: {result['features']['domain_age_days']:.0f} days")
    print(f"Typosquatting: {result['features']['typosquatting_score']}")
