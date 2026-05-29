import pandas as pd
from typing import List

from data_collection.collector import PhishingDataCollector
from features.url_features import URLFeatureExtractor

class DatasetBuilder:
    def __init__(self, urlhaus_key: str = None):
        self.collector = PhishingDataCollector(urlhaus_key=urlhaus_key)
        self.extractor = URLFeatureExtractor()
    
    def build_phishing_dataset(self, limit: int = None) -> pd.DataFrame:
        print("Fetching phishing URLs...")
        data = self.collector.collect()
        
        phishing_urls = data['shopping_phishing']
        if limit:
            phishing_urls = phishing_urls[:limit]
        
        print(f"Extracting features from {len(phishing_urls)} phishing URLs...")
        features = self.extractor.extract_batch(phishing_urls)
        
        df = pd.DataFrame(features)
        df['url'] = phishing_urls
        df['label'] = 1
        
        return df
    
    def build_legitimate_dataset(self, legitimate_urls: List[str]) -> pd.DataFrame:
        print(f"Extracting features from {len(legitimate_urls)} legitimate URLs...")
        features = self.extractor.extract_batch(legitimate_urls)
        
        df = pd.DataFrame(features)
        df['url'] = legitimate_urls
        df['label'] = 0
        
        return df
    
    def build_full_dataset(self, legitimate_urls: List[str]) -> pd.DataFrame:
        phishing_df = self.build_phishing_dataset()
        legitimate_df = self.build_legitimate_dataset(legitimate_urls)
        
        df = pd.concat([phishing_df, legitimate_df], ignore_index=True)
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        print(f"\nDataset built:")
        print(f"  Total: {len(df)}")
        print(f"  Phishing: {len(df[df['label'] == 1])}")
        print(f"  Legitimate: {len(df[df['label'] == 0])}")
        
        return df


SAMPLE_LEGITIMATE_URLS = [
    "https://www.amazon.com", "https://www.ebay.com", "https://www.paypal.com",
    "https://www.apple.com", "https://www.nike.com", "https://www.adidas.com",
    "https://www.zara.com", "https://www.walmart.com", "https://www.etsy.com",
    "https://www.shopify.com", "https://www.dhl.com", "https://www.fedex.com",
    "https://www.ups.com", "https://www.netflix.com", "https://www.spotify.com",
    "https://www.steampowered.com", "https://www.playstation.com", "https://www.roblox.com",
    "https://www.bilka.dk", "https://www.matas.dk", "https://www.elgiganten.dk",
    "https://www.proshop.dk", "https://www.komplett.dk", "https://www.coolshop.dk",
]