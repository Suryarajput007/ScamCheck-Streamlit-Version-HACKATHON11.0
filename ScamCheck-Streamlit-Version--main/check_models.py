import urllib.request
import json
import os

key = os.environ.get("GROQ_API_KEY")

if not key:
    print("Error: GROQ_API_KEY environment variable not found.")
else:
    # The User-Agent header is required to bypass Cloudflare bot protection
    req = urllib.request.Request(
        "https://api.groq.com/openai/v1/models",
        headers={
            "Authorization": f"Bearer {key}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ScamCheck/1.0"
        }
    )
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode("utf-8"))
            print("Models you have access to:")
            for model in data.get("data", []):
                print(f"- {model['id']}")
    except Exception as e:
        print(f"Failed to fetch models: {e}")