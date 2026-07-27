import os
from dotenv import load_dotenv

load_dotenv()

keys_pool = os.getenv("GROQ_API_KEYS", "").split(",")
primary_key = os.getenv("GROQ_API_KEY", "")

if not keys_pool and primary_key:
    keys_pool = [primary_key]

print(f"Total keys to test: {len(keys_pool)}")

for key in keys_pool:
    key = key.strip()
    if not key:
        continue
    masked = key[:8] + "..." + key[-4:]
    print(f"Testing key: {masked}")

    # Try querying Groq
    try:
        from groq import Groq
        client = Groq(api_key=key)
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "user", "content": "hi"}
            ],
            max_tokens=10
        )
        print(f"  [+] SUCCESS: {response.choices[0].message.content}")
    except Exception as e:
        print(f"  [-] FAILED: {e}")
