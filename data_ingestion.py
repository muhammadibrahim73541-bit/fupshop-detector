import requests
import whois
import ssl
import socket
import time
import json
import os
from datetime import datetime
from dotenv import load_dotenv

# Load .env from parent directory
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

class DataIngestion:
    def __init__(self):
        self.dawa_base = "https://api.dataforsyningen.dk/dawa"
        self.virustotal_key = os.getenv("VIRUSTOTAL_KEY", "")
    
    def fetch_cvr_data(self, cvr_number: str):
        """Fetch from CVRAPI (free, 100/day)."""
        try:
            time.sleep(0.5)
            response = requests.get(
                f"https://cvrapi.dk/api?search={cvr_number}&country=dk",
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    "name": data.get("name"),
                    "address": data.get("address"),
                    "zipcode": data.get("zipcode"),
                    "city": data.get("city"),
                    "phone": data.get("phone"),
                    "email": data.get("email"),
                    "employees": data.get("employees"),
                    "company_age_days": self._calculate_age(data.get("startdate")),
                    "status": data.get("status"),
                    "source": "cvrapi"
                }
            return {"error": f"CVRAPI Status {response.status_code}", "source": "cvrapi"}
        except Exception as e:
            return {"error": str(e), "source": "cvrapi_failed"}
    
    def _calculate_age(self, start_date_str):
        """Calculate company age in days."""
        if not start_date_str:
            return None
        try:
            # Handle different date formats
            for fmt in ["%Y-%m-%d", "%d-%m-%Y", "%Y/%m/%d"]:
                try:
                    start = datetime.strptime(str(start_date_str)[:10], fmt)
                    return (datetime.now() - start).days
                except:
                    continue
            return None
        except:
            return None
    
    def fetch_dawa_address(self, address_text: str):
        """Validate Danish address via DAWA."""
        try:
            response = requests.get(
                f"{self.dawa_base}/datavask/adresser",
                params={"betegnelse": address_text},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                resultater = data.get("resultater", [])
                if resultater:
                    best = resultater[0]
                    addr = best.get("adresse", {})
                    return {
                        "validated": True,
                        "confidence": best.get("aktualitet", 0),
                        "address_string": addr.get("betegnelse", ""),
                        "is_residential": False  # Simplified - refine later
                    }
                return {"validated": False, "reason": "no_matches"}
            return {"error": f"DAWA Status {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def fetch_whois_data(self, domain: str):
        """Get domain age via python-whois."""
        try:
            w = whois.whois(domain)
            creation = w.creation_date
            
            if isinstance(creation, list):
                creation = creation[0]
            
            age_days = None
            if creation:
                if isinstance(creation, datetime):
                    age_days = (datetime.now() - creation).days
                elif isinstance(creation, str):
                    try:
                        creation_dt = datetime.strptime(creation, "%Y-%m-%d %H:%M:%S")
                        age_days = (datetime.now() - creation_dt).days
                    except:
                        pass
            
            return {
                "domain_age_days": age_days,
                "registrar": w.registrar,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "source": "whois"
            }
        except Exception as e:
            return {"error": str(e), "domain_age_days": None, "source": "whois_failed"}
    
    def check_ssl(self, domain: str):
        """Check SSL certificate."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    not_after = cert.get("notAfter")
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_until_expiry = (expiry - datetime.now()).days
                    return {
                        "has_ssl": True,
                        "valid": days_until_expiry > 0,
                        "days_until_expiry": days_until_expiry,
                        "issuer": str(cert.get("issuer", ""))
                    }
        except Exception as e:
            return {"has_ssl": False, "valid": False, "error": str(e)}
    
    def check_virustotal(self, domain: str):
        """Check domain reputation via VirusTotal."""
        if not self.virustotal_key:
            return {"checked": False, "note": "No API key configured"}
        try:
            headers = {"x-apikey": self.virustotal_key}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "checked": True,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total": sum(stats.values()) if stats else 0,
                    "reputation": attrs.get("reputation", 0)
                }
            return {"checked": False, "error": f"VT Status {response.status_code}"}
        except Exception as e:
            return {"checked": False, "error": str(e)}
    
    def ingest_all(self, url: str, cvr_number: str = None):
        """Full pipeline for one URL."""
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        
        # Run all checks
        cvr_data = self.fetch_cvr_data(cvr_number) if cvr_number else None
        whois_data = self.fetch_whois_data(domain)
        ssl_data = self.check_ssl(domain)
        vt_data = self.check_virustotal(domain)
        
        # Build result
        raw_data = {
            "url": url,
            "domain": domain,
            "cvr_data": cvr_data,
            "whois": whois_data,
            "ssl": ssl_data,
            "virustotal": vt_data,
            "timestamp": datetime.now().isoformat()
        }
        
        # Save to ../data/raw/
        raw_dir = os.path.join(os.path.dirname(__file__), '..', 'data', 'raw')
        os.makedirs(raw_dir, exist_ok=True)
        filename = os.path.join(
            raw_dir,
            f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(filename, "w") as f:
            json.dump(raw_data, f, indent=2, default=str)
        
        print(f"Saved raw data to: {filename}")
        return raw_data

# TEST
if __name__ == "__main__":
    ingest = DataIngestion()
    
    # Test with real Danish domains
    tests = [
        ("https://elgiganten.dk", "31543731"),
        ("https://bilka.dk", "76282211"),
    ]
    
    for url, cvr in tests:
        print(f"\n{'='*60}")
        print(f"Testing: {url}")
        result = ingest.ingest_all(url, cvr)
        print(json.dumps(result, indent=2, default=str))
        time.sleep(2)