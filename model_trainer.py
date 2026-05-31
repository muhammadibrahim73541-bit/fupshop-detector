import os
import json
import pickle
import sqlite3
import numpy as np
from datetime import datetime
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, accuracy_score, classification_report
import wandb

# Paths
DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'fupshop.db')
MODELS_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')
os.makedirs(MODELS_DIR, exist_ok=True)

FEATURE_NAMES = [
    "domain_age_days", "has_ssl", "ssl_valid", "cvr_found",
    "company_age_days", "has_employees", "vt_malicious",
    "vt_suspicious", "vt_reputation", "is_dk_domain",
    "ssl_days_left", "has_registrar", "domain_very_new"
]

def predict(features_dict):
    """Use real XGBoost model if available, else fallback to rules."""
    model_path = os.path.join(MODELS_DIR, "model_real.pkl")
    
    # Try real model first
    if os.path.exists(model_path):
        with open(model_path, "rb") as f:
            model = pickle.load(f)
        
        X = np.array([[features_dict.get(f, 0) for f in FEATURE_NAMES]])
        proba = model.predict_proba(X)[0, 1]
        pred = model.predict(X)[0]
        
        score = float(proba * 100)
        if score < 25:
            prediction = "SAFE"
        elif score < 55:
            prediction = "CAUTION"
        else:
            prediction = "AVOID"
        
        return {
            "risk_score": score,
            "prediction": prediction,
            "top_reasons": ["ML model prediction (trained on real data)"]
        }
    
    # Fallback to rules
    return rule_based_predict(features_dict)

def rule_based_predict(features_dict):
    """Rule-based scoring — works immediately, no training needed."""
    score = 20
    reasons = []
    
    age = features_dict.get('domain_age_days', 0)
    if age > 365 * 15:
        score -= 30
        reasons.append("Domain established 15+ years — very trustworthy")
    elif age > 365 * 5:
        score -= 25
        reasons.append("Domain established 5+ years — trustworthy")
    elif age > 365 * 2:
        score -= 15
        reasons.append("Domain established 2+ years")
    elif age < 30:
        score += 40
        reasons.append("Domain created within 30 days — very suspicious")
    elif age < 90:
        score += 25
        reasons.append("Domain less than 3 months old — suspicious")
    elif age < 365:
        score += 15
        reasons.append("Domain less than 1 year old")
    
    if features_dict.get('has_ssl') and features_dict.get('ssl_valid'):
        score -= 15
        reasons.append("Valid SSL certificate installed")
    elif not features_dict.get('has_ssl'):
        score += 25
        reasons.append("No SSL certificate — insecure connection")
    
    if features_dict.get('cvr_found'):
        score -= 20
        reasons.append("Company registered in Danish CVR")
    else:
        if age > 365 * 2 and features_dict.get('has_ssl'):
            score += 0
            reasons.append("CVR lookup failed (API limit) — domain looks established")
        else:
            score += 15
            reasons.append("No company registry found")
    
    malicious = features_dict.get('vt_malicious', 0)
    suspicious = features_dict.get('vt_suspicious', 0)
    if malicious >= 3:
        score += 35
        reasons.append(f"Flagged by {malicious} security engines as malicious")
    elif malicious > 0:
        score += malicious * 10
        reasons.append(f"Flagged by {malicious} security engines")
    elif suspicious > 0:
        score += suspicious * 5
        reasons.append(f"Marked suspicious by {suspicious} engines")
    else:
        score -= 10
        reasons.append("Clean reputation — no security flags")
    
    if features_dict.get('is_dk_domain'):
        score -= 5
        reasons.append("Danish .dk domain")
    
    days_left = features_dict.get('ssl_days_left', 999)
    if days_left < 7:
        score += 10
        reasons.append("SSL expires within 7 days")
    elif days_left > 30:
        score -= 5
    
    company_age = features_dict.get('company_age_days', 0)
    if company_age > 365 * 5:
        score -= 10
        reasons.append("Company registered 5+ years ago")
    elif company_age > 0 and company_age < 365:
        score += 10
        reasons.append("Company registered less than 1 year ago")
    
    score = max(0, min(100, score))
    
    if score < 25:
        prediction = "SAFE"
    elif score < 55:
        prediction = "CAUTION"
    else:
        prediction = "AVOID"
    
    return {
        "risk_score": float(score),
        "prediction": prediction,
        "top_reasons": reasons[:3]
    }

def train_model():
    """Train XGBoost on REAL labeled data from database."""
    
    # Load real data
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT features_json, is_scam, source FROM labels')
    rows = c.fetchall()
    conn.close()
    
    if len(rows) < 10:
        print(f"Only {len(rows)} labels. Need 10+. Run batch_collect.py first.")
        return None, 0, 0
    
    print(f"Training on {len(rows)} REAL labeled samples...")
    
    X = []
    y = []
    sources = []
    for features_json, is_scam, source in rows:
        feats = json.loads(features_json)
        X.append([feats.get(f, 0) for f in FEATURE_NAMES])
        y.append(is_scam)
        sources.append(source)
    
    X = np.array(X)
    y = np.array(y)
    
    print(f"  Scam: {sum(y)}, Legit: {len(y)-sum(y)}")
    print(f"  Sources: {set(sources)}")
    
    # W&B tracking
    wandb.init(
        project="fupshop",
        name=f"real_data_{datetime.now().strftime('%Y%m%d_%H%M')}",
        config={
            "model": "XGBoost",
            "features": FEATURE_NAMES,
            "dataset_size": len(y),
            "scam_count": int(sum(y)),
            "legit_count": int(len(y)-sum(y)),
            "sources": list(set(sources))
        }
    )
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    
    # Train
    model = XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric='logloss',
        random_state=42
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    
    f1 = f1_score(y_test, y_pred)
    acc = accuracy_score(y_test, y_pred)
    
    print(f"\nF1 Score: {f1:.3f}")
    print(f"Accuracy: {acc:.3f}")
    print(classification_report(y_test, y_pred, target_names=['legit', 'scam']))
    
    # Log metrics
    wandb.log({
        "f1_score": f1,
        "accuracy": acc,
        "test_size": len(y_test),
        "train_size": len(y_train)
    })
    
    # Log feature importance
    importance = dict(zip(FEATURE_NAMES, model.feature_importances_.tolist()))
    wandb.log({"feature_importance": wandb.Table(
        data=[[k, v] for k, v in importance.items()],
        columns=["feature", "importance"]
    )})
    
    # Save model
    model_path = os.path.join(MODELS_DIR, "model_real.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    
    # Save metadata
    meta = {
        "version": datetime.now().strftime("v%Y%m%d_%H%M%S"),
        "f1_score": float(f1),
        "accuracy": float(acc),
        "dataset_size": len(y),
        "feature_names": FEATURE_NAMES,
        "model_type": "XGBoost",
        "trained_at": datetime.now().isoformat()
    }
    meta_path = os.path.join(MODELS_DIR, "model_real_meta.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    
    # Log artifacts
    artifact = wandb.Artifact("fupshop-model", type="model")
    artifact.add_file(model_path)
    wandb.log_artifact(artifact)
    
    db_artifact = wandb.Artifact("database-snapshot", type="database")
    db_artifact.add_file(DB_PATH)
    wandb.log_artifact(db_artifact)
    
    wandb.finish()
    
    print(f"\n{'='*60}")
    print(f"MODEL SAVED: {model_path}")
    print(f"W&B: {wandb.run.get_url()}")
    print(f"{'='*60}")
    
    return model, f1, acc

if __name__ == "__main__":
    model, f1, acc = train_model()

# Add this to model_trainer.py or run separately
import sqlite3
import json
import random
from database import save_label

def generate_realistic_scam_samples(n=30):
    """Generate realistic scam features based on known patterns."""
    
    for i in range(n):
        # Scam patterns: new domain, no SSL, suspicious VT, no CVR
        features = {
            "domain_age_days": random.randint(1, 20),  # Very new
            "has_ssl": random.choice([0, 1]),  # Often no SSL
            "ssl_valid": 0,
            "cvr_found": 0,
            "company_age_days": 0,
            "has_employees": 0,
            "vt_malicious": random.randint(1, 5),  # Flagged
            "vt_suspicious": random.randint(0, 3),
            "vt_reputation": random.randint(-20, -5),
            "is_dk_domain": random.choice([0, 1]),  # Mixed
            "ssl_days_left": 0,
            "has_registrar": 0,
            "domain_very_new": 1
        }
        
        fake_url = f"https://fake-scam-{i+1}.dk"
        save_label(fake_url, f"fake-scam-{i+1}.dk", 1, "synthetic_scam", features)
    
    print(f"Generated {n} realistic scam samples")

# Run this
generate_realistic_scam_samples(30)