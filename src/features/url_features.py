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
    
    # Danish shops for typosquatting detection
    DANISH_SHOPS = [
        'elgiganten', 'bilka', 'foetex', 'fotex', 'salling', 'matas', 'power',
        'proshop', 'komplett', 'coolshop', 'zalando', 'hm', 'boozt',
        'asos', 'thomann', 'bygma', 'silvan', 'stark', 'jemogfix',
        'ikea', 'bauhaus', 'xl-byg', 'xlbyg', 'dba', 'guloggratis', 'qxl',
        'telenor', 'telia', 'yousee', 'borger', 'skat',
        'virk', 'cvr', 'dr', 'tv2', 'politiken', 'berlingske',
        'jyllandsposten', 'jp', 'ekstrabladet', 'information',
        'bt', 'seoghoer', 'billedbladet', 'femina', 'alt',
        'fck', 'bif', 'fcm', 'agf', 'aab', 'rfc', 'ob', 'sif',
        'brondby', 'kobenhavn', 'randers', 'viborg', 'midtjylland',
        'odense', 'lyngby', 'nordsjaelland', 'horsens', 'silkeborg'
    ]
    
    def extract(self, url: str) -> Dict[str, float]:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        
        # Basic features
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
            
            # NEW: Typosquatting detection
            'typosquatting_score': self._check_typosquatting(domain),
            'is_danish_shop_fake': 1 if self._check_typosquatting(domain) > 0.7 else 0,
            
            # NEW: Domain age proxy (high entropy = likely new/fake)
            'domain_age_proxy': self._estimate_domain_age(domain),
            'is_new_domain': 1 if self._estimate_domain_age(domain) < 30 else 0,
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
    
    def _check_typosquatting(self, domain: str) -> float:
        """Check if domain is typosquatting a known Danish shop"""
        # Clean domain: remove TLD and www
        domain_clean = re.sub(r'\.(dk|com|net|org|de|eu|co\.uk|co)$', '', domain)
        domain_clean = re.sub(r'^www\.', '', domain_clean)
        domain_clean = re.sub(r'[^a-z]', '', domain_clean)  # Remove non-letters
        
        if not domain_clean:
            return 0.0
        
        min_distance = float('inf')
        matched_shop = None
        
        for shop in self.DANISH_SHOPS:
            shop_clean = re.sub(r'[^a-z]', '', shop)
            dist = self._levenshtein(domain_clean, shop_clean)
            if dist < min_distance:
                min_distance = dist
                matched_shop = shop
        
        # Score based on distance
        # 0 = exact match (legitimate)
        # 1-2 = typosquatting (high risk)
        # 3+ = probably different domain
        if min_distance == 0:
            return 0.0  # Exact match = legitimate
        elif min_distance == 1:
            return 0.95  # 1 char off = very likely fake
        elif min_distance == 2:
            return 0.85  # 2 chars off = likely fake
        elif min_distance == 3:
            return 0.5   # 3 chars off = suspicious
        else:
            return 0.0   # Too different = probably not typosquatting
    
    def _levenshtein(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _estimate_domain_age(self, domain: str) -> float:
        """Proxy for domain age: high entropy/randomness = likely new domain"""
        entropy = self._calculate_entropy(domain)
        
        # Remove TLD for cleaner check
        domain_no_tld = re.sub(r'\.(dk|com|net|org|de|eu|co\.uk)$', '', domain)
        
        # Check for random-looking patterns
        has_random_pattern = bool(re.search(r'[a-z]{2}[0-9]{2,}|[0-9]{2,}[a-z]{2}', domain_no_tld))
        has_many_hyphens = domain_no_tld.count('-') > 2
        is_long = len(domain_no_tld) > 25
        
        score = 0
        if entropy > 3.8:
            score += 1
        if has_random_pattern:
            score += 1
        if has_many_hyphens:
            score += 1
        if is_long:
            score += 1
        
        # Return estimated age in days
        if score >= 3:
            return 7.0    # Very new (1 week)
        elif score >= 2:
            return 30.0   # New (1 month)
        elif score >= 1:
            return 90.0   # Relatively new (3 months)
        else:
            return 365.0  # Established (1 year)
    
    def extract_batch(self, urls: List[str]) -> List[Dict[str, float]]:
        return [self.extract(url) for url in urls]