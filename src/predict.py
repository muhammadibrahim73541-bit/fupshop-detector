import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import joblib
import json
import numpy as np
from features.url_features import URLFeatureExtractor

class FupShopPredictor:
    def __init__(self, model_path: str = None):
        if model_path is None:
            model_path = os.path.join(os.path.dirname(__file__), 'models', 'fupshop_model.pkl')
        
        self.model = joblib.load(model_path)
        with open(model_path.replace('.pkl', '_features.json'), 'r') as f:
            self.feature_names = json.load(f)
        self.extractor = URLFeatureExtractor()
    
    def predict(self, url: str, cvr: str = None) -> dict:
        features = self.extractor.extract(url, cvr=cvr)
        feature_vector = np.array([[features[name] for name in self.feature_names]])
        prob = self.model.predict_proba(feature_vector)[0][1]
        prediction = "PHISHING" if prob > 0.5 else "LEGITIMATE"
        
        return {
            'url': url,
            'prediction': prediction,
            'phishing_probability': float(prob),
            'features': features
        }

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
    print(f"Features: {result['features']}")
