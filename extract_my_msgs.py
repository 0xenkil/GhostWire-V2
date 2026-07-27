import json
import re

my_transcript = r"C:\Users\ASUS\.gemini\antigravity\brain\9192f495-4fd4-4963-a820-51a956d44cda\.system_generated\logs\transcript.jsonl"
out_file = r"C:\Users\ASUS\Desktop\red team\clean_messages.txt"

senders = [
    '7aa330f0-a904-45a6-9165-e0843fc213d4',
    'dabd4a20-e886-4a12-8a61-52ae1020b2c9',
    '012f8be3-bd5d-4996-8cbd-05f3a8ac8cd9',
    'f790ac77-e5db-442f-bd8f-0cdb0ea4773a',
    '2cd80fa3-1c5d-4493-a005-6549135cdd2e',
    'f6b2441a-aaec-4871-8815-f5e6b2351cd8',
    '8b529fd5-708b-4591-9790-6b47bf6f9313'
]

with open(out_file, 'w', encoding='utf-8') as out:
    with open(my_transcript, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                obj = json.loads(line)
                if obj.get('type') == 'SYSTEM_MESSAGE':
                    content = obj.get('content', '')
                    # Look for [Message] timestamp=... sender=... content=...
                    match = re.search(
                        r'\[Message\] timestamp=\S+ sender=(\S+) priority=\S+ content=(.*?)(\n</SYSTEM_MESSAGE>|$)',
                        content,
                        re.DOTALL)
                    if match:
                        sender = match.group(1)
                        msg_content = match.group(2)
                        if any(s in sender for s in senders):
                            out.write(
                                f"--- SENDER: {sender} ---\n{msg_content}\n\n")
            except Exception as _e:
                import logging
                logging.getLogger(__name__).debug(
                    f'Swallowed exception in extract_my_msgs.py: {_e}')
