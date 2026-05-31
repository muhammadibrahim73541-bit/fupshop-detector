import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'fupshop.db')

def init_db():
    """Create all tables. Run once at startup."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Every scan a user makes
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            risk_score REAL,
            prediction TEXT,  -- SAFE, CAUTION, AVOID
            features_json TEXT,  -- All 13 features as JSON
            raw_data_json TEXT,  -- Full API responses
            shap_explanation TEXT,  -- Top 3 SHAP reasons
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Labeled data for retraining
    c.execute('''
        CREATE TABLE IF NOT EXISTS labels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            is_scam INTEGER NOT NULL,  -- 0 or 1
            source TEXT,  -- 'manual', 'user_report', 'forbrugerombudsmanden'
            features_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # User scam reports
    c.execute('''
        CREATE TABLE IF NOT EXISTS user_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            lost_money INTEGER,  -- 0 or 1
            amount_lost REAL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Model versions for rollback
    c.execute('''
        CREATE TABLE IF NOT EXISTS model_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version TEXT NOT NULL,
            wandb_run_id TEXT,
            f1_score REAL,
            accuracy REAL,
            model_path TEXT,
            deployed_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
    print(f"Database initialized at: {DB_PATH}")

def save_scan(url, domain, risk_score, prediction, features, raw_data, shap_exp):
    """Save a prediction result."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO scans (url, domain, risk_score, prediction, features_json, raw_data_json, shap_explanation)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (url, domain, risk_score, prediction, json.dumps(features), json.dumps(raw_data), json.dumps(shap_exp)))
    conn.commit()
    scan_id = c.lastrowid
    conn.close()
    return scan_id

def save_label(url, domain, is_scam, source, features):
    """Save a labeled example for retraining."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO labels (url, domain, is_scam, source, features_json)
        VALUES (?, ?, ?, ?, ?)
    ''', (url, domain, is_scam, source, json.dumps(features)))
    conn.commit()
    conn.close()

def save_user_report(url, domain, lost_money, amount_lost, description):
    """Save user scam report."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO user_reports (url, domain, lost_money, amount_lost, description)
        VALUES (?, ?, ?, ?, ?)
    ''', (url, domain, lost_money, amount_lost, description))
    conn.commit()
    conn.close()

def get_training_data():
    """Get all labeled data for model retraining."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT url, domain, is_scam, features_json FROM labels')
    rows = c.fetchall()
    conn.close()
    return rows

def get_scan_history(limit=50):
    """Get recent scans for dashboard."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT url, domain, risk_score, prediction, created_at 
        FROM scans ORDER BY created_at DESC LIMIT ?
    ''', (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

# Initialize on import
init_db()

if __name__ == "__main__":
    # Test
    print("Testing database...")
    save_scan("https://test.dk", "test.dk", 15.5, "SAFE", {"feat1": 1}, {"raw": "data"}, ["domain old"])
    print("Scan saved!")
    history = get_scan_history()
    print(f"Recent scans: {history}")