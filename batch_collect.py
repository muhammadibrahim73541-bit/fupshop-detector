import requests
import json
import os
import sys
import time
from data_ingestion import DataIngestion
from data_transformation import extract_features
from database import save_label

# 30 LEGIT DANISH SHOPS
LEGIT_URLS = [
    ("https://elgiganten.dk", "31543731"),
    ("https://bilka.dk", "76282211"),
    ("https://matas.dk", "24256789"),
    ("https://magasin.dk", "65728201"),
    ("https://jysk.dk", "16305310"),
    ("https://ikea.dk", "63802110"),
    ("https://power.dk", "35972801"),
    ("https://thansen.dk", "73172801"),
    ("https://harald-nyborg.dk", "16280301"),
    ("https://silvan.dk", "16280401"),
    ("https://bog-ide.dk", "28740101"),
    ("https://saxo.com", "27280101"),
    ("https://foetex.dk", "76282212"),
    ("https://netto.dk", "76282213"),
    ("https://rema1000.dk", "76282214"),
    ("https://lego.dk", "54562501"),
    ("https://georgjensen.dk", "11280301"),
    ("https://hay.dk", "26730101"),
    ("https://normann-copenhagen.dk", "26730201"),
    ("https://designletters.dk", "26730301"),
    ("https://ticketmaster.dk", "17280101"),
    ("https://danskebank.dk", "61126201"),
    ("https://nordea.dk", "61126301"),
    ("https://jyskebank.dk", "61126401"),
    ("https://aldi.dk", "76282215"),
    ("https://lidl.dk", "76282216"),
    ("https://bahne.dk", "26730401"),
    ("https://illums-bolighus.dk", "26730501"),
    ("https://royal-copenhagen.dk", "11280401"),
    ("https://viagogo.dk", None),
]

def get_urlhaus_scams(limit=100):
    """Fetch real scam URLs from URLhaus (free, no key)."""
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            data={"limit": limit},
            timeout=15
        )
        if response.status_code == 200:
            data = response.json()
            urls = []
            for u in data.get("urls", []):
                url = u.get("url", "")
                # Filter for shopping-related or .dk domains
                if any(kw in url.lower() for kw in ["shop", "store", "sale", "dk", "buy", "cheap"]):
                    urls.append(url)
            return urls[:50]  # Max 50
        return []
    except Exception as e:
        print(f"URLhaus error: {e}")
        return []

def collect_legit():
    """Collect features for legit shops."""
    ingest = DataIngestion()
    print(f"Collecting {len(LEGIT_URLS)} legit shops...")
    
    success = 0
    for url, cvr in LEGIT_URLS:
        try:
            raw = ingest.ingest_all(url, cvr)
            features = extract_features(raw)
            save_label(url, raw['domain'], 0, "established_retailer", features)
            print(f"  ✓ {url} → SAFE (domain: {features['domain_age_days']} days)")
            success += 1
            time.sleep(1.5)  # Rate limit
        except Exception as e:
            print(f"  ✗ {url} → ERROR: {e}")
    
    print(f"\nLegit: {success}/{len(LEGIT_URLS)} saved")
    return success

def collect_scams():
    """Collect features for scam URLs from URLhaus."""
    scam_urls = get_urlhaus_scams(200)
    print(f"Found {len(scam_urls)} potential scam URLs from URLhaus")
    
    ingest = DataIngestion()
    success = 0
    
    for url in scam_urls[:30]:  # Limit to 30 for speed
        try:
            raw = ingest.ingest_all(url, None)
            features = extract_features(raw)
            save_label(url, raw['domain'], 1, "urlhaus_scam", features)
            print(f"  ✓ {url} → SCAM (score: {features['vt_malicious']} malicious)")
            success += 1
            time.sleep(1.5)
        except Exception as e:
            print(f"  ✗ {url} → ERROR: {e}")
    
    print(f"\nScams: {success}/{len(scam_urls[:30])} saved")
    return success

if __name__ == "__main__":
    print("="*60)
    print("FUPSHOP — Real Data Collection")
    print("="*60)
    
    legit_count = collect_legit()
    print()
    scam_count = collect_scams()
    
    print("\n" + "="*60)
    print(f"TOTAL: {legit_count} legit + {scam_count} scam = {legit_count + scam_count} labeled samples")
    print("Ready for model training!")
    print("="*60)