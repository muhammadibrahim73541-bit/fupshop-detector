import pandas as pd
import numpy as np
from typing import Dict, Tuple
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import xgboost as xgb
import joblib
import json
import os

class FupShopModelTrainer:
    def __init__(self, model_path: str = "models/fupshop_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.feature_names = None
        self.metrics = {}
    
    def prepare_data(self, df: pd.DataFrame) -> Tuple:
        feature_cols = [col for col in df.columns if col not in ['url', 'label']]
        self.feature_names = feature_cols
        
        X = df[feature_cols].values
        y = df['label'].values
        
        return train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    def train(self, X_train, y_train):
        print("\nTraining XGBoost...")
        self.model = xgb.XGBClassifier(
            n_estimators=100, max_depth=6, learning_rate=0.1,
            subsample=0.8, colsample_bytree=0.8, random_state=42
        )
        self.model.fit(X_train, y_train)
        return self.model
    
    def evaluate(self, X_test, y_test):
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\nAccuracy: {accuracy:.4f}")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        self.metrics = {
            'accuracy': float(accuracy),
            'feature_importance': dict(zip(
                self.feature_names,
                self.model.feature_importances_.tolist()
            ))
        }
        return self.metrics
    
    def save(self):
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        
        with open(self.model_path.replace('.pkl', '_metrics.json'), 'w') as f:
            json.dump(self.metrics, f, indent=2)
        
        with open(self.model_path.replace('.pkl', '_features.json'), 'w') as f:
            json.dump(self.feature_names, f, indent=2)
        
        print(f"\nModel saved to {self.model_path}")


def train_pipeline():
    from utils.dataset_builder import DatasetBuilder, SAMPLE_LEGITIMATE_URLS
    
    builder = DatasetBuilder(urlhaus_key="6fe27ca7aa571ad003699cc22fb33160c911773d0c979d8f")
    df = builder.build_full_dataset(SAMPLE_LEGITIMATE_URLS)
    
    trainer = FupShopModelTrainer(model_path="/workspaces/fupshop-detector/src/models/fupshop_model.pkl")
    X_train, X_test, y_train, y_test = trainer.prepare_data(df)
    trainer.train(X_train, y_train)
    trainer.evaluate(X_test, y_test)
    trainer.save()
    
    return trainer


if __name__ == "__main__":
    print("FupShop Detector - Training")
    print("=" * 50)
    train_pipeline()