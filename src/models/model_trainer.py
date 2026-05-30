import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pandas as pd
import numpy as np
from typing import Dict, Tuple
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import xgboost as xgb
import joblib
import json

class FupShopModelTrainer:
    def __init__(self, model_path: str = "models/fupshop_model.pkl"):
        self.model_path = model_path
        self.model = None
        self.feature_names = None
        self.metrics = {}
        self.X_train_ref = None
        self.y_train_ref = None
    
    def prepare_data(self, df: pd.DataFrame):
        feature_cols = [col for col in df.columns if col not in ['url', 'label']]
        self.feature_names = feature_cols
        
        X = df[feature_cols].values
        y = df['label'].values
        
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
        )
        
        print(f"Train: {len(X_train)} | Val: {len(X_val)} | Test: {len(X_test)}")
        
        return X_train, X_val, X_test, y_train, y_val, y_test
    
    def train(self, X_train, y_train, X_val=None, y_val=None):
        print("\nTraining XGBoost...")
        
        self.X_train_ref = X_train
        self.y_train_ref = y_train
        
        self.model = xgb.XGBClassifier(
            n_estimators=300,
            max_depth=4,
            learning_rate=0.05,
            subsample=0.7,
            colsample_bytree=0.7,
            reg_alpha=0.1,
            reg_lambda=1.0,
            random_state=42,
            eval_metric='logloss',
            early_stopping_rounds=30
        )
        
        eval_set = [(X_train, y_train)]
        if X_val is not None:
            eval_set.append((X_val, y_val))
        
        self.model.fit(
            X_train, y_train,
            eval_set=eval_set,
            verbose=False
        )
        
        print(f"Best iteration: {self.model.best_iteration}")
        return self.model
    
    def evaluate(self, X_test, y_test):
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\nTest Accuracy: {accuracy:.4f}")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        train_pred = self.model.predict(self.X_train_ref)
        train_acc = accuracy_score(self.y_train_ref, train_pred)
        gap = train_acc - accuracy
        
        print(f"\nTrain Accuracy: {train_acc:.4f}")
        print(f"Test Accuracy:  {accuracy:.4f}")
        print(f"Overfitting Gap: {gap:.4f}")
        
        if gap > 0.1:
            print("⚠️ WARNING: Model is overfitting!")
        else:
            print("✅ Model generalizes well")
        
        self.metrics = {
            'accuracy': float(accuracy),
            'train_accuracy': float(train_acc),
            'overfitting_gap': float(gap),
            'feature_importance': dict(zip(
                self.feature_names,
                self.model.feature_importances_.tolist()
            ))
        }
        
        return self.metrics
    
    def cross_validate(self, X, y):
        print("\nRunning 5-Fold Cross-Validation...")
        cv_model = xgb.XGBClassifier(n_estimators=100, max_depth=4, random_state=42)
        scores = cross_val_score(cv_model, X, y, cv=5, scoring='accuracy')
        print(f"CV Scores: {scores}")
        print(f"Mean: {scores.mean():.4f} (+/- {scores.std():.4f})")
        return scores
    
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
    
    trainer = FupShopModelTrainer(
        model_path="/workspaces/fupshop-detector/src/models/fupshop_model.pkl"
    )
    
    X_train, X_val, X_test, y_train, y_val, y_test = trainer.prepare_data(df)
    trainer.train(X_train, y_train, X_val, y_val)
    trainer.evaluate(X_test, y_test)
    
    feature_cols = [col for col in df.columns if col not in ['url', 'label']]
    X_full = df[feature_cols].values
    y_full = df['label'].values
    trainer.cross_validate(X_full, y_full)
    
    trainer.save()
    return trainer


if __name__ == "__main__":
    print("FupShop Detector - Training")
    print("=" * 50)
    train_pipeline()
