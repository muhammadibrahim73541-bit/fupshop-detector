import re
import socket
import ssl
import math
import requests
import os
import json
from urllib.parse import urlparse
from datetime import datetime

class URLFeatureExtractor:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'secure', 'account', 'update', 'confirm',
            'bank', 'payment', 'password', 'credential', 'authenticate',
            'signin', 'signup', 'security', 'alert', 'suspend', 'restrict',
            'validate', 'authenticate', 'billing', 'invoice', 'order'
        ]
        self.known_brands = [
            'paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook',
            'netflix', 'spotify', 'ebay', 'alibaba', 'bilka', 'elgiganten',
            'matas', 'zalando', 'power', 'proshop', 'salling', 'foetex',
            'lego', 'ikea', 'jysk', 'danskebank', 'nordea', 'jyskebank',
            'saxo', 'ticketmaster', 'viagogo', 'magasin', 'rema1000',
            'netto', 'lidl', 'aldi', 'haraldnyborg', 'silvan', 'thansen',
            'bogide', 'hay', 'georgjensen', 'royalcopenhagen', 'normann',
            'designletters', 'illums', 'bahne'
        ]

    def _get_base_domain(self, domain: str) -> str:
        if domain.startswith('www.'):
            domain = domain[4:]
        if '.' in domain:
            domain = domain.rsplit('.', 1)[0]
        return domain.lower()

    def extract(self, url: str, cvr: str = None) -> dict:
        url = url.rstrip('/')
        parsed = urlparse(url if url.startswith('http') else f'https://{url}')
        domain = parsed.netloc or parsed.path
        if domain.startswith('www.'):
            domain = domain[4:]

        dns_resolved, dns_ip = self._check_dns(domain)
        domain_age_days, domain_age_real, whois_details = self._check_whois_with_rdap(domain)
        has_ssl, ssl_days_left = self._check_ssl(domain)
        typosquatting_score, char_sub = self._check_typosquatting(domain)
        vt_malicious = self._check_virustotal(domain)
        cvr_found = self._check_cvr(domain, cvr) if cvr else 0

        features = {
            'url_length': len(url),
            'domain_length': len(domain),
            'path_length': len(parsed.path),
            'query_length': len(parsed.query),
            'dot_count': url.count('.'),
            'hyphen_count': url.count('-'),
            'underscore_count': url.count('_'),
            'slash_count': url.count('/'),
            'digit_count': sum(c.isdigit() for c in url),
            'special_char_count': len([c for c in url if not c.isalnum() and c not in './-']),
            'has_https': 1 if parsed.scheme == 'https' else 0,
            'has_ip_address': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
            'has_port': 1 if parsed.port else 0,
            'suspicious_keyword_count': sum(1 for kw in self.suspicious_keywords if kw in url.lower()),
            'brand_in_domain': 1 if any(brand in domain.lower() for brand in self.known_brands) else 0,
            'brand_in_path': 1 if any(brand in parsed.path.lower() for brand in self.known_brands) else 0,
            'multiple_subdomains': 1 if domain.count('.') > 2 else 0,
            'path_depth': parsed.path.count('/'),
            'has_query_params': 1 if parsed.query else 0,
            'has_fragment': 1 if parsed.fragment else 0,
            'domain_entropy': self._compute_entropy(domain),
            'typosquatting_score': typosquatting_score,
            'char_substitution_detected': char_sub,
            'is_danish_shop_fake': self._is_fake_danish_shop(domain),
            'domain_age_proxy': self._estimate_domain_age_proxy(domain),
            'is_new_domain': 1 if domain_age_days < 30 else 0,
            'has_ssl': has_ssl,
            'ssl_days_left': ssl_days_left,
            'domain_age_days': domain_age_days,
            'domain_age_real': domain_age_real,
            'dns_resolved': dns_resolved,
            'dns_ip': dns_ip,
            'cvr_found': cvr_found,
            'vt_malicious': vt_malicious,
        }
        return features

    def _check_dns(self, domain: str) -> tuple:
        try:
            ip = socket.gethostbyname(domain)
            return 1, ip
        except:
            return 0, "N/A"

    def _check_whois_with_rdap(self, domain: str) -> tuple:
        # Try python-whois first (works locally, fails in HF containers due to port 43 block)
        try:
            import whois
            w = whois.whois(domain)
            if w.creation_date:
                creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                if isinstance(creation, datetime):
                    age_days = (datetime.now() - creation).days
                    return age_days, 1, {"registrar": str(w.registrar), "creation_date": str(creation), "source": "WHOIS"}
        except:
            pass

        # Fallback to RDAP (HTTPS-based, works in some containers)
        try:
            rdap_url = f"https://rdap.org/domain/{domain}"
            response = requests.get(rdap_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for event in data.get('events', []):
                    if event.get('eventAction') == 'registration':
                        reg_date = event.get('eventDate', '')
                        if reg_date:
                            creation = datetime.fromisoformat(reg_date.replace('Z', '+00:00'))
                            age_days = (datetime.now() - creation).days
                            return age_days, 1, {"source": "RDAP"}
        except:
            pass

        # Final fallback: return neutral age so it doesn't hurt predictions
        # Documented limitation: HF containers block port 43 (WHOIS protocol)
        return 5000, 0, {"error": "WHOIS unavailable", "note": "Network restrictions in cloud deployment. python-whois works locally."}

    def _check_ssl(self, domain: str) -> tuple:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        expiry = ssl.cert_time_to_seconds(not_after)
                        days_left = int((expiry - datetime.now().timestamp()) / 86400)
                        return 1, max(0, days_left)
        except:
            return 0, 0

    def _compute_entropy(self, domain: str) -> float:
        from collections import Counter
        domain = re.sub(r'[^a-zA-Z0-9]', '', domain)
        if not domain:
            return 0
        counts = Counter(domain)
        length = len(domain)
        entropy = -sum((count/length) * math.log2(count/length) for count in counts.values())
        return entropy

    def _check_typosquatting(self, domain: str) -> tuple:
        base_domain = self._get_base_domain(domain)
        base_clean = re.sub(r'[^a-zA-Z0-9]', '', base_domain)
        if not base_clean or len(base_clean) < 3:
            return 0, 0

        max_score = 0
        char_sub = 0

        for brand in self.known_brands:
            brand_clean = re.sub(r'[^a-zA-Z0-9]', '', brand.lower())
            if not brand_clean or len(brand_clean) < 3:
                continue

            # EXACT MATCH -> NOT typosquatting
            if base_clean == brand_clean:
                return 0, 0

            # Calculate edit distance
            m, n = len(base_clean), len(brand_clean)
            dp = [[0]*(n+1) for _ in range(m+1)]
            for i in range(m+1): dp[i][0] = i
            for j in range(n+1): dp[0][j] = j
            for i in range(1, m+1):
                for j in range(1, n+1):
                    cost = 0 if base_clean[i-1] == brand_clean[j-1] else 1
                    dp[i][j] = min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost)

            dist = dp[m][n]
            max_len = max(m, n)
            if max_len > 0:
                similarity = 1 - (dist / max_len)
                if dist > 0 and similarity > 0.5:
                    max_score = max(max_score, similarity)

        sub_patterns = {'1': 'l', '0': 'o', 'rn': 'm', 'vv': 'w'}
        for sub, orig in sub_patterns.items():
            if sub in base_clean and orig not in base_clean:
                char_sub = 1
                break

        return max_score, char_sub

    def _is_fake_danish_shop(self, domain: str) -> int:
        danish_indicators = ['.dk', 'danmark', 'dansk']
        fake_indicators = ['-dk', 'danmark-', 'dansk-']
        has_danish = any(ind in domain.lower() for ind in danish_indicators)
        has_fake = any(ind in domain.lower() for ind in fake_indicators)
        return 1 if (has_danish and has_fake) else 0

    def _estimate_domain_age_proxy(self, domain: str) -> int:
        parts = domain.split('.')
        tld = parts[-1] if len(parts) > 1 else ''
        if tld in ['com', 'net', 'org']:
            return 1000
        elif tld == 'dk':
            return 500
        return 365

    def _check_virustotal(self, domain: str) -> int:
        try:
            api_key = os.getenv('VIRUSTOTAL_KEY')
            if not api_key:
                return 0
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return stats.get('malicious', 0) + stats.get('suspicious', 0)
        except:
            return 0
        return 0

    def _check_cvr(self, domain: str, cvr: str) -> int:
        try:
            return 1 if len(cvr) == 8 and cvr.isdigit() else 0
        except:
            return 0
