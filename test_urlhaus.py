import requests

API_KEY = "6fe27ca7aa571ad003699cc22fb33160c911773d0c979d8f"

headers = {"Auth-Key": API_KEY}

# FIXED: Use GET, not POST
response = requests.get(
    'https://urlhaus-api.abuse.ch/v1/urls/recent/',
    headers=headers,
    timeout=30
)

print(f"Status code: {response.status_code}")
data = response.json()

# Check query_status first
print(f"Query status: {data.get('query_status')}")
print(f"Full response keys: {list(data.keys())}")

if data.get('query_status') == 'ok':
    urls = data.get('urls', [])
    print(f"URLhaus URLs fetched: {len(urls)}")
    if urls:
        print("First 3 URLs:")
        for u in urls[:3]:
            print(f"  - {u.get('url')} (status: {u.get('url_status')})")
else:
    print(f"Error: {data.get('query_status')}")
