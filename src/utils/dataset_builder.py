import pandas as pd
from typing import List
import random

from data_collection.collector import PhishingDataCollector
from features.url_features import URLFeatureExtractor


class DatasetBuilder:
    def __init__(self, urlhaus_key: str = None):
        self.collector = PhishingDataCollector(urlhaus_key=urlhaus_key)
        self.extractor = URLFeatureExtractor()
    
    def build_phishing_dataset(self, limit: int = None) -> pd.DataFrame:
        print("Fetching phishing URLs...")
        data = self.collector.collect()
        
        phishing_urls = data['all_phishing']
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
    
    def build_full_dataset(self, legitimate_urls: List[str], limit: int = None) -> pd.DataFrame:
        phishing_df = self.build_phishing_dataset(limit=limit)
        legitimate_df = self.build_legitimate_dataset(legitimate_urls)
        
        df = pd.concat([phishing_df, legitimate_df], ignore_index=True)
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        print(f"\nDataset built:")
        print(f"  Total: {len(df)}")
        print(f"  Phishing: {len(df[df['label'] == 1])}")
        print(f"  Legitimate: {len(df[df['label'] == 0])}")
        
        return df
    
    def generate_typosquatting_urls(self, legitimate_urls: List[str], count: int = 200) -> List[str]:
        """Generate realistic fake typosquatting versions of real shops"""
        import random
        
        typos = []
        
        # Subtle modifications that are hard to spot
        subtle_mods = [
            # Character substitution (homoglyphs)
            lambda s: s.replace('a', 'а'),  # Cyrillic а (looks identical)
            lambda s: s.replace('e', 'е'),  # Cyrillic е
            lambda s: s.replace('o', 'о'),  # Cyrillic о
            lambda s: s.replace('p', 'р'),  # Cyrillic р
            lambda s: s.replace('c', 'с'),  # Cyrillic с
            # Common typos
            lambda s: s.replace('a', 'aa', 1),
            lambda s: s.replace('e', 'ee', 1),
            lambda s: s.replace('n', 'nn', 1),
            lambda s: s.replace('l', '1', 1),
            lambda s: s.replace('o', '0', 1),
            lambda s: s.replace('i', 'j', 1),
            # Add subtle suffixes/prefixes
            lambda s: s + '-dk',
            lambda s: s + '-shop',
            lambda s: s + '-online',
            lambda s: 'secure-' + s,
            lambda s: 'login-' + s,
            # TLD swaps
            lambda s: s,  # Will add different TLD
        ]
        
        used = set()
        attempts = 0
        
        while len(typos) < count and attempts < count * 10:
            attempts += 1
            
            base = random.choice(legitimate_urls)
            domain = base.replace('https://', '').replace('http://', '').replace('www.', '').split('.')[0]
            
            # Apply 1-2 subtle modifications
            mod = random.choice(subtle_mods)
            fake = mod(domain)
            
            # If no change happened, try another
            if fake == domain:
                fake = domain + random.choice(['dk', 'shop', 'store', 'online'])
            
            # Add realistic TLD
            tld = random.choice(['.dk', '.com', '.net', '.shop', '.store', '.online'])
            fake_url = f"https://www.{fake}{tld}"
            
            # Avoid duplicates
            if fake_url not in used and fake_url not in legitimate_urls:
                used.add(fake_url)
                typos.append(fake_url)
        
        return typos[:count]
    
    def build_synthetic_phishing_dataset(self, legitimate_urls: List[str], count: int = 200) -> pd.DataFrame:
        """Build phishing dataset from SYNTHETIC typosquatting URLs"""
        print(f"Generating {count} synthetic typosquatting URLs...")
        synthetic_urls = self.generate_typosquatting_urls(legitimate_urls, count=count)
        
        print(f"Extracting features from {len(synthetic_urls)} synthetic phishing URLs...")
        features = self.extractor.extract_batch(synthetic_urls)
        
        df = pd.DataFrame(features)
        df['url'] = synthetic_urls
        df['label'] = 1
        
        print(f"Synthetic phishing dataset: {len(df)} samples")
        return df
    
    def build_full_dataset_with_synthetic(self, legitimate_urls: List[str], 
                                          real_phishing_limit: int = None,
                                          synthetic_count: int = 200) -> pd.DataFrame:
        """ULTIMATE DATASET: Real phishing + Synthetic phishing + Legitimate"""
        real_phishing_df = self.build_phishing_dataset(limit=real_phishing_limit)
        synthetic_phishing_df = self.build_synthetic_phishing_dataset(legitimate_urls, count=synthetic_count)
        legitimate_df = self.build_legitimate_dataset(legitimate_urls)
        
        df = pd.concat([real_phishing_df, synthetic_phishing_df, legitimate_df], ignore_index=True)
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        print(f"\n{'='*50}")
        print(f"FULL DATASET WITH SYNTHETIC DATA:")
        print(f"  Total: {len(df)}")
        print(f"  Real Phishing: {len(real_phishing_df)}")
        print(f"  Synthetic Phishing: {len(synthetic_phishing_df)}")
        print(f"  Legitimate: {len(legitimate_df)}")
        print(f"{'='*50}\n")
        
        return df


SAMPLE_LEGITIMATE_URLS = [
    "https://www.amazon.com", "https://www.ebay.com", "https://www.paypal.com",
    "https://www.apple.com", "https://www.microsoft.com", "https://www.google.com",
    "https://www.facebook.com", "https://www.instagram.com", "https://www.twitter.com",
    "https://www.linkedin.com", "https://www.youtube.com", "https://www.twitch.tv",
    "https://www.discord.com", "https://www.slack.com", "https://www.zoom.us",
    "https://www.dropbox.com", "https://www.github.com", "https://www.gitlab.com",
    "https://www.stackoverflow.com", "https://www.reddit.com", "https://www.pinterest.com",
    "https://www.tiktok.com", "https://www.snapchat.com", "https://www.whatsapp.com",
    "https://www.telegram.org", "https://www.signal.org", "https://www.mozilla.org",
    "https://www.opera.com", "https://www.brave.com", "https://www.vivaldi.com",
    "https://www.nike.com", "https://www.adidas.com", "https://www.zara.com",
    "https://www.walmart.com", "https://www.etsy.com", "https://www.shopify.com",
    "https://www.alibaba.com", "https://www.aliexpress.com", "https://www.rakuten.com",
    "https://www.wayfair.com", "https://www.overstock.com", "https://www.newegg.com",
    "https://www.bestbuy.com", "https://www.target.com", "https://www.costco.com",
    "https://www.homedepot.com", "https://www.lowes.com", "https://www.ikea.com",
    "https://www.chewy.com", "https://www.zappos.com",
    "https://www.asos.com", "https://www.boohoo.com", "https://www.shein.com",
    "https://www.fashionnova.com", "https://www.prettylittlething.com",
    "https://www.netflix.com", "https://www.spotify.com", "https://www.hulu.com",
    "https://www.disneyplus.com", "https://www.hbomax.com", "https://www.peacocktv.com",
    "https://www.paramountplus.com", "https://www.appletv.com", "https://www.crunchyroll.com",
    "https://www.funimation.com", "https://www.vudu.com", "https://www.tubitv.com",
    "https://www.pluto.tv", "https://www.roku.com",
    "https://www.steampowered.com", "https://www.playstation.com", "https://www.roblox.com",
    "https://www.xbox.com", "https://www.nintendo.com", "https://www.epicgames.com",
    "https://www.riotgames.com", "https://www.blizzard.com", "https://www.ubisoft.com",
    "https://www.ea.com", "https://www.activision.com", "https://www.bethesda.net",
    "https://www.gog.com", "https://www.humblebundle.com", "https://www.itch.io",
    "https://www.chase.com", "https://www.bankofamerica.com", "https://www.wellsfargo.com",
    "https://www.citi.com", "https://www.capitalone.com", "https://www.americanexpress.com",
    "https://www.discover.com", "https://www.usbank.com", "https://www.pnc.com",
    "https://www.td.com", "https://www.bbt.com", "https://www.suntrust.com",
    "https://www.schwab.com", "https://www.fidelity.com", "https://www.vanguard.com",
    "https://www.robinhood.com", "https://www.coinbase.com", "https://www.binance.com",
    "https://www.kraken.com", "https://www.gemini.com", "https://www.blockfi.com",
    "https://www.airbnb.com", "https://www.booking.com", "https://www.expedia.com",
    "https://www.hotels.com", "https://www.agoda.com", "https://www.trip.com",
    "https://www.kayak.com", "https://www.priceline.com", "https://www.trivago.com",
    "https://www.skyscanner.com", "https://www.google.com/travel", "https://www.tripadvisor.com",
    "https://www.uber.com", "https://www.lyft.com", "https://www.grab.com",
    "https://www.bolt.eu", "https://www.ola.com", "https://www.didiglobal.com",
    "https://www.bilka.dk", "https://www.foetex.dk", "https://www.salling.dk",
    "https://www.matas.dk", "https://www.elgiganten.dk", "https://www.power.dk",
    "https://www.proshop.dk", "https://www.komplett.dk", "https://www.coolshop.dk",
    "https://www.2trendy.dk", "https://www.zalando.dk", "https://www2.hm.com/da_dk",
    "https://www.boozt.com", "https://www.amazon.de", "https://www.ebay.de",
    "https://www.thomann.de", "https://www.bygma.dk", "https://www.silvan.dk",
    "https://www.stark.dk", "https://www.jemogfix.dk", "https://www.ikea.com/dk",
    "https://www.bauhaus.dk", "https://www.xl-byg.dk", "https://www.dba.dk",
    "https://www.guloggratis.dk", "https://www.qxl.dk", "https://www.telenor.dk",
    "https://www.telia.dk", "https://www.yousee.dk", "https://www.3.dk",
    "https://www.energinet.dk", "https://www.dsb.dk", "https://www.rejseplanen.dk",
    "https://www.sundhed.dk", "https://www.borger.dk", "https://www.skat.dk",
    "https://www.virk.dk", "https://www.cvr.dk", "https://www.dr.dk",
    "https://www.tv2.dk", "https://www.bt.dk", "https://www.ekstrabladet.dk",
    "https://www.politiken.dk", "https://www.information.dk", "https://www.berlingske.dk",
    "https://www.jyllands-posten.dk", "https://www.kristeligt-dagblad.dk",
    "https://www.alt.dk", "https://www.femina.dk", "https://www.seoghoer.dk",
    "https://www.billedbladet.dk", "https://www.tipsbladet.dk", "https://www.bold.dk",
    "https://www.transfermarkt.dk", "https://www.fck.dk", "https://www.bif.dk",
    "https://www.fcm.dk", "https://www.agf.dk", "https://www.aab.dk",
    "https://www.rfc.dk", "https://www.ob.dk", "https://www.sif.dk",
    "https://www.achorsens.dk", "https://www.hobroik.dk", "https://www.vff.dk",
    "https://www.lbk.dk", "https://www.sonderjyske.dk", "https://www.nordvestfc.dk",
]


if __name__ == "__main__":
    builder = DatasetBuilder()
    synthetic = builder.generate_typosquatting_urls(SAMPLE_LEGITIMATE_URLS, count=10)
    print("Sample synthetic URLs:")
    for url in synthetic:
        print(f"  {url}")
