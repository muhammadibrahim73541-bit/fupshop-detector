import re
import math
from urllib.parse import urlparse
from typing import Dict, List

class URLFeatureExtractor:
    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'verify', 'account', 'update', 'secure', 'banking',
        'confirm', 'password', 'credential', 'authenticate', 'wallet', 'payment',
        'billing', 'invoice', 'refund', 'suspended', 'locked', 'limited',
        'alert', 'warning', 'fraud', 'suspicious', 'unusual', 'activity'
    ]
    
    BRAND_NAMES = [
        'amazon', 'ebay', 'paypal', 'apple', 'microsoft', 'google', 'facebook',
        'netflix', 'spotify', 'steam', 'playstation', 'roblox', 'nike', 'adidas',
        'zara', 'walmart', 'bestbuy', 'target', 'costco', 'etsy', 'shopify',
        'dhl', 'usps', 'fedex', 'ups', 'bank', 'chase', 'wellsfargo', 'citi'
    ]
    
    def extract(self, url: str) -> Dict[str, float]:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        
        features = {
            'url_length': len(url),
            'domain_length': len(domain),
            'path_length': len(path),
            'query_length': len(query),
            'dot_count': url.count('.'),
            'hyphen_count': url.count('-'),
            'underscore_count': url.count('_'),
            'slash_count': url.count('/'),
            'digit_count': sum(c.isdigit() for c in url),
            'special_char_count': sum(not c.isalnum() for c in url),
            'has_https': 1 if url.startswith('https://') else 0,
            'has_ip_address': 1 if self._has_ip(domain) else 0,
            'has_port': 1 if ':' in domain else 0,
            'suspicious_keyword_count': sum(1 for k in self.SUSPICIOUS_KEYWORDS if k in url.lower()),
            'brand_in_domain': 1 if any(b in domain for b in self.BRAND_NAMES) else 0,
            'brand_in_path': 1 if any(b in path for b in self.BRAND_NAMES) else 0,
            'multiple_subdomains': 1 if domain.count('.') > 2 else 0,
            'path_depth': path.count('/'),
            'has_query_params': 1 if query else 0,
            'has_fragment': 1 if parsed.fragment else 0,
            'domain_entropy': self._calculate_entropy(domain),
        }
        
        return features
    
    def _has_ip(self, domain: str) -> bool:
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.match(ip_pattern, domain))
    
    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        length = len(text)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def extract_batch(self, urls: List[str]) -> List[Dict[str, float]]:
        return [self.extract(url) for url in urls]