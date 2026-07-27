import os
import requests
import re
from dotenv import load_dotenv

load_dotenv()


def test_openrouter(model_name):
    openrouter_key = os.getenv('OPENROUTER_API_KEY')
    try:
        r = requests.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers={
                'Authorization': f'Bearer {openrouter_key}',
                'Content-Type': 'application/json'},
            json={'model': model_name, 'messages': [
                {'role': 'user', 'content': 'Say exactly OK'}]},
            timeout=10
        )
        if r.status_code == 200:
            return True, r.json()['choices'][0]['message']['content'].strip()
        else:
            return False, f"{r.status_code} {r.text}"
    except Exception as e:
        return False, str(e)


def test_gemini(model_name):
    gemini_key = os.getenv('GOOGLE_API_KEY')
    try:
        r = requests.post(
            f'https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={gemini_key}',
            headers={'Content-Type': 'application/json'},
            json={'contents': [{'parts': [{'text': 'Say exactly OK'}]}]},
            timeout=10
        )
        if r.status_code == 200:
            return True, r.json()[
                'candidates'][0]['content']['parts'][0]['text'].strip()
        else:
            return False, f"{r.status_code} {r.text}"
    except Exception as e:
        return False, str(e)


print("--- Testing OpenRouter Models ---")
or_models = [
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
    "poolside/laguna-xs.2:free",
    "poolside/laguna-m.1:free",
    "deepseek/deepseek-v4-flash:free",
    "moonshotai/kimi-k2.6:free",
    "google/gemma-4-26b-a4b-it:free",
    "google/gemma-4-31b-it:free"
]
working_or = None
for m in or_models:
    success, msg = test_openrouter(m)
    if success:
        print(f"[SUCCESS] {m} WORKS! Response: {msg}")
        if not working_or:
            working_or = m
        break
    else:
        print(f"[FAILED] {m} FAILED: {msg[:100]}...")

print("\n--- Testing Gemini Models ---")
gemini_models = [
    "gemini-3.1-flash-lite",
    "gemini-2.0-flash",
    "gemini-1.5-flash",
    "gemini-flash-latest",
]
working_gemini = None
for m in gemini_models:
    success, msg = test_gemini(m)
    if success:
        print(f"[SUCCESS] {m} WORKS! Response: {msg}")
        if not working_gemini:
            working_gemini = m
        break
    else:
        print(f"[FAILED] {m} FAILED: {msg[:100]}...")

if working_or:
    with open(".env", "r") as f:
        content = f.read()
    content = re.sub(
        r'OPENROUTER_MODEL=.*',
        f'OPENROUTER_MODEL={working_or}',
        content)
    with open(".env", "w") as f:
        f.write(content)
    print(f"\nUpdated OPENROUTER_MODEL to {working_or} in .env")

if working_gemini:
    with open(".env", "r") as f:
        content = f.read()
    content = re.sub(
        r'GOOGLE_MODEL=.*',
        f'GOOGLE_MODEL={working_gemini}',
        content)
    with open(".env", "w") as f:
        f.write(content)
    print(f"Updated GOOGLE_MODEL to {working_gemini} in .env")
