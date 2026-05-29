import requests
from typing import List, Dict

class URLHausFetcher:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
        self.headers = {"Auth-Key": api_key}
    
    def fetch(self, limit: int = None) -> List[Dict]:
        """Fetch recent malicious URLs from URLhaus (past 3 days)"""
        try:
            response = requests.get(
                self.base_url,
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get("query_status") != "ok":
                print(f"URLhaus API error: {data.get('query_status')}")
                return []
            
            urls = data.get("urls", [])
            if limit:
                urls = urls[:limit]
            return urls
            
        except Exception as e:
            print(f"URLhaus fetch error: {e}")
            return []
    
    def get_urls_only(self, limit: int = None) -> List[str]:
        """Get just the URL strings"""
        urls_data = self.fetch(limit)
        return [item["url"] for item in urls_data if "url" in item]

if __name__ == "__main__":
    fetcher = URLHausFetcher("6fe27ca7aa571ad003699cc22fb33160c911773d0c979d8f")
    urls = fetcher.get_urls_only(limit=10)
    print(f"\nFetched {len(urls)} URLs")
    for u in urls[:5]:
        print(f"  {u}")
