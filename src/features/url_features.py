import re
import math
import requests
from urllib.parse import urlparse
from typing import Dict, List
import os
from dotenv import load_dotenv

load_dotenv()

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
        'dhl', 'usps', 'fedex', 'ups', 'bank', 'chase', 'wellsfargo', 'citi',
        'samsung', 'lg', 'sony', 'huawei', 'xiaomi', 'oneplus', 'lenovo',
        'dell', 'hp', 'asus', 'acer', 'intel', 'amd', 'nvidia'
    ]
    
    ALL_BRANDS = [
        'elgiganten', 'bilka', 'foetex', 'fotex', 'salling', 'matas', 'power',
        'proshop', 'komplett', 'coolshop', 'zalando', 'hm', 'boozt',
        'asos', 'thomann', 'bygma', 'silvan', 'stark', 'jemogfix',
        'ikea', 'bauhaus', 'xlbyg', 'dba', 'guloggratis', 'qxl',
        'telenor', 'telia', 'yousee', 'borger', 'skat', 'virk', 'cvr',
        'dr', 'tv2', 'politiken', 'berlingske', 'jyllandsposten', 'jp',
        'ekstrabladet', 'information', 'bt', 'seoghoer', 'billedbladet',
        'femina', 'alt', 'fck', 'bif', 'fcm', 'agf', 'aab', 'rfc', 'ob', 'sif',
        'brondby', 'kobenhavn', 'randers', 'viborg', 'midtjylland',
        'odense', 'lyngby', 'nordsjaelland', 'horsens', 'silkeborg',
        'samsung', 'apple', 'microsoft', 'google', 'amazon', 'ebay', 'paypal',
        'netflix', 'spotify', 'facebook', 'instagram', 'twitter', 'linkedin',
        'youtube', 'tiktok', 'snapchat', 'whatsapp', 'telegram',
        'steam', 'epicgames', 'playstation', 'xbox', 'nintendo', 'roblox',
        'riotgames', 'blizzard', 'ubisoft', 'ea', 'activision',
        'chase', 'bankofamerica', 'wellsfargo', 'citi', 'capitalone',
        'americanexpress', 'discover', 'schwab', 'fidelity', 'vanguard',
        'robinhood', 'coinbase', 'binance', 'kraken',
    ]
    
    CHAR_SUBSTITUTIONS = {
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
        '7': 't', '8': 'b', '@': 'a', '$': 's',
    }
    
    def __init__(self):
        self.virustotal_key = os.getenv('VIRUSTOTAL_KEY')
    
    def extract(self, url: str, cvr: str = None) -> Dict[str, float]:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        
        # Raw domain (for char substitution detection)
        domain_raw = self._clean_domain(domain)
        # Normalized (substitutions applied)
        domain_normalized = self._normalize_domain(domain)
        
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
            'typosquatting_score': max(
                self._check_typosquatting(domain_raw),
                self._check_typosquatting(domain_normalized)
            ),
            'char_substitution_detected': 1 if domain_raw != domain_normalized else 0,
            'is_danish_shop_fake': 1 if self._check_typosquatting(domain_normalized) > 0.7 else 0,
            'domain_age_proxy': self._estimate_domain_age(domain),
            'is_new_domain': 1 if self._estimate_domain_age(domain) < 30 else 0,
        }
        
        features['has_ssl'] = features['has_https']
        features['ssl_days_left'] = 365
        features['domain_age_days'] = features['domain_age_proxy']
        
        features['cvr_found'] = 0
        if cvr and len(cvr) == 8 and cvr.isdigit():
            features['cvr_found'] = self._check_cvr(cvr)
        
        features['vt_malicious'] = 0
        if self.virustotal_key:
            features['vt_malicious'] = self._check_virustotal(domain)
        
        return features
    
    def _clean_domain(self, domain: str) -> str:
        """Remove TLD and www only"""
        domain = re.sub(r'\.(dk|com|net|org|de|eu|co\.uk|co|shop|store|io|app)$', '', domain)
        domain = re.sub(r'^www\.', '', domain)
        return domain.lower()
    
    def _normalize_domain(self, domain: str) -> str:
        """Remove TLD, www, hyphens, and apply char substitutions"""
        domain = self._clean_domain(domain)
        domain = domain.replace('-', '')
        for fake, real in self.CHAR_SUBSTITUTIONS.items():
            domain = domain.replace(fake, real)
        return domain.lower()
    
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
    
    def _check_typosquatting(self, domain_clean: str) -> float:
        if not domain_clean or len(domain_clean) < 3:
            return 0.0
        
        min_distance = float('inf')
        
        for brand in self.ALL_BRANDS:
            brand_clean = brand.replace('-', '')
            dist = self._levenshtein(domain_clean, brand_clean)
            if dist < min_distance:
                min_distance = dist
        
        if min_distance == 0:
            return 0.0
        elif min_distance == 1:
            return 0.95
        elif min_distance == 2:
            return 0.85
        elif min_distance == 3:
            return 0.6
        elif min_distance <= 5 and len(domain_clean) > 5:
            return 0.3
        else:
            return 0.0
    
    def _levenshtein(self, s1: str, s2: str) -> int:
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
        entropy = self._calculate_entropy(domain)
        domain_no_tld = re.sub(r'\.(dk|com|net|org|de|eu|co\.uk)$', '', domain)
        has_random_pattern = bool(re.search(r'[a-z]{2}[0-9]{2,}|[0-9]{2,}[a-z]{2}', domain_no_tld))
        has_many_hyphens = domain_no_tld.count('-') > 2
        is_long = len(domain_no_tld) > 25
        
        score = 0
        if entropy > 3.8: score += 1
        if has_random_pattern: score += 1
        if has_many_hyphens: score += 1
        if is_long: score += 1
        
        if score >= 3: return 7.0
        elif score >= 2: return 30.0
        elif score >= 1: return 90.0
        else: return 365.0
    
    def _check_cvr(self, cvr: str) -> int:
        try:
            response = requests.get(f"https://cvrapi.dk/api?search={cvr}&country=dk", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return 1 if data.get('vat') else 0
        except:
            pass
        return 0
    
    def _check_virustotal(self, domain: str) -> int:
        if not self.virustotal_key:
            return 0
        try:
            headers = {"x-apikey": self.virustotal_key}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers=headers,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return stats.get('malicious', 0)
        except:
            pass
        return 0
    
    def extract_batch(self, urls: List[str]) -> List[Dict[str, float]]:
        return [self.extract(url) for url in urls]
