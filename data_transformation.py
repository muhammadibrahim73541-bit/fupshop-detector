import json
import os
import re
from datetime import datetime

def extract_features(raw_data):
    """Convert raw API data to 13 numerical features."""
    
    domain = raw_data.get("domain", "")
    cvr = raw_data.get("cvr_data", {}) or {}
    whois = raw_data.get("whois", {}) or {}
    ssl = raw_data.get("ssl", {}) or {}
    vt = raw_data.get("virustotal", {}) or {}
    
    features = {
        # 1. Domain age (older = safer)
        "domain_age_days": whois.get("domain_age_days") or 0,
        
        # 2. Has SSL
        "has_ssl": 1 if ssl.get("has_ssl") else 0,
        
        # 3. SSL valid
        "ssl_valid": 1 if ssl.get("valid") else 0,
        
        # 4. CVR found (company registered in Denmark)
        "cvr_found": 1 if cvr.get("name") else 0,
        
        # 5. Company age (older = safer)
        "company_age_days": cvr.get("company_age_days") or 0,
        
        # 6. Has employees (0 employees = red flag)
        "has_employees": 1 if cvr.get("employees") and cvr.get("employees") > 0 else 0,
        
        # 7. VirusTotal malicious count
        "vt_malicious": vt.get("malicious", 0) if vt.get("checked") else 0,
        
        # 8. VirusTotal suspicious count
        "vt_suspicious": vt.get("suspicious", 0) if vt.get("checked") else 0,
        
        # 9. VirusTotal reputation (negative = bad)
        "vt_reputation": vt.get("reputation", 0) if vt.get("checked") else 0,
        
        # 10. Domain is .dk (Danish TLD = slightly more trustworthy for Danish users)
        "is_dk_domain": 1 if domain.endswith(".dk") else 0,
        
        # 11. SSL days until expiry (very low = red flag)
        "ssl_days_left": ssl.get("days_until_expiry", 0) or 0,
        
        # 12. Has registrar info (missing = suspicious)
        "has_registrar": 1 if whois.get("registrar") else 0,
        
        # 13. Domain very new (< 30 days = high risk)
        "domain_very_new": 1 if (whois.get("domain_age_days") or 999) < 30 else 0,
    }
    
    return features

def save_features_to_db(scan_id, features, db_path=None):
    """Update scan record with extracted features."""
    import sqlite3
    if db_path is None:
        db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'fupshop.db')
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('UPDATE scans SET features_json = ? WHERE id = ?', 
              (json.dumps(features), scan_id))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    # Test with your saved raw data
    raw_file = "/workspaces/fupshop-detector/data/raw/elgiganten.dk_20260524_224012.json"
    with open(raw_file) as f:
        raw = json.load(f)
    
    feats = extract_features(raw)
    print("Extracted features:")
    for k, v in feats.items():
        print(f"  {k}: {v}")