import requests
from typing import List, Dict

class PhishHuntFetcher:
    def __init__(self):
        self.base_url = "https://phishunt.io/api/v1/domains"
    
    def fetch(self, limit: int = 50) -> List[Dict]:
        """Fetch phishing domains from PhishHunt"""
        try:
            response = requests.get(
                f"{self.base_url}?limit={limit}&format=json",
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            return data.get("results", [])
        except Exception as e:
            print(f"PhishHunt error: {e}")
            return []
    
    def get_urls_only(self, limit: int = 50) -> List[str]:
        """Get just the URL strings"""
        results = self.fetch(limit)
        return [item["url"] for item in results if "url" in item]

if __name__ == "__main__":
    fetcher = PhishHuntFetcher()
    urls = fetcher.get_urls_only(limit=10)
    print(f"PhishHunt: {len(urls)} URLs")
    for u in urls[:3]:
        print(f"  {u}")