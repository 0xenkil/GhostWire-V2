import os
from dotenv import load_dotenv

load_dotenv()
print(f"GROQ_API_KEY: {os.getenv('GROQ_API_KEY')}")
print(f"GROQ_API_KEYS: {os.getenv('GROQ_API_KEYS')}")
