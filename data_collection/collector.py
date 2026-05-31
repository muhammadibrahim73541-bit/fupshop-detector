import csv
from typing import List, Dict
from datetime import datetime

from .urlhaus_fetcher import URLHausFetcher
from .openphish_fetcher import OpenPhishFetcher
from .phishhunt_fetcher import PhishHuntFetcher

class PhishingDataCollector:
    """Master collector that fetches from all sources and filters for shopping-related phishing"""
    
    SHOPPING_KEYWORDS = [
        'amazon', 'ebay', 'shop', 'store', 'sale', 'buy', 'cart', 'checkout',
        'allegro', 'paypal', 'apple', 'nike', 'adidas', 'zara', 'walmart',
        'bestbuy', 'target', 'costco', 'etsy', 'shopify', 'roblox',
        'netflix', 'spotify', 'steam', 'epicgames', 'playstation',
        'dhl', 'usps', 'fedex', 'bank', 'crypto', 'wallet'
    ]
    
    def __init__(self, urlhaus_key: str = None):
        self.urlhaus = URLHausFetcher(urlhaus_key) if urlhaus_key else None
        self.openphish = OpenPhishFetcher()
        self.phishhunt = PhishHuntFetcher()
    
    def fetch_all(self) -> Dict[str, List[str]]:
        """Fetch from all available sources"""
        print(f"[{datetime.now()}] Starting data collection...")
        
        sources = {}
        
        # URLhaus
        if self.urlhaus:
            sources['urlhaus'] = self.urlhaus.get_urls_only(limit=1000)
            print(f"  URLhaus: {len(sources['urlhaus'])} URLs")
        
        # OpenPhish
        sources['openphish'] = self.openphish.fetch(limit=1000)
        print(f"  OpenPhish: {len(sources['openphish'])} URLs")
        
        # PhishHunt
        sources['phishhunt'] = self.phishhunt.get_urls_only(limit=100)
        print(f"  PhishHunt: {len(sources['phishhunt'])} URLs")
        
        # Merge and deduplicate
        all_urls = []
        for source_urls in sources.values():
            all_urls.extend(source_urls)
        
        all_urls = list(set(all_urls))
        print(f"\nTotal unique URLs: {len(all_urls)}")
        
        return {
            'all': all_urls,
            'by_source': sources
        }
    
    def filter_shopping(self, urls: List[str]) -> List[str]:
        """Filter URLs for shopping/e-commerce related phishing"""
        shopping_urls = []
        for url in urls:
            url_lower = url.lower()
            if any(k in url_lower for k in self.SHOPPING_KEYWORDS):
                shopping_urls.append(url)
        return list(set(shopping_urls))
    
    def collect(self) -> Dict:
        """Full pipeline: fetch + filter"""
        data = self.fetch_all()
        
        shopping = self.filter_shopping(data['all'])
        print(f"Shopping-related phishing: {len(shopping)}")
        
        return {
            'all_phishing': data['all'],
            'shopping_phishing': shopping,
            'by_source': data['by_source']
        }

if __name__ == "__main__":
    collector = PhishingDataCollector(
        urlhaus_key="6fe27ca7aa571ad003699cc22fb33160c911773d0c979d8f"
    )
    result = collector.collect()
    
    print(f"\n{'='*50}")
    print("SAMPLE SHOPPING PHISHING URLs:")
    for url in result['shopping_phishing'][:10]:
        print(f"  {url}")