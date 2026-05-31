import requests
from typing import List

class OpenPhishFetcher:
    def __init__(self):
        self.url = "https://openphish.com/feed.txt"
    
    def fetch(self, limit: int = None) -> List[str]:
        """Fetch phishing URLs from OpenPhish"""
        try:
            response = requests.get(self.url, timeout=30)
            response.raise_for_status()
            urls = [u.strip() for u in response.text.strip().split('\n') if u.strip()]
            if limit:
                urls = urls[:limit]
            return urls
        except Exception as e:
            print(f"OpenPhish error: {e}")
            return []

if __name__ == "__main__":
    fetcher = OpenPhishFetcher()
    urls = fetcher.fetch(limit=10)
    print(f"OpenPhish: {len(urls)} URLs")
    for u in urls[:3]:
        print(f"  {u}")