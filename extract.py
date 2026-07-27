import json
import os

ids = [
    '7aa330f0-a904-45a6-9165-e0843fc213d4',
    'dabd4a20-e886-4a12-8a61-52ae1020b2c9',
    '012f8be3-bd5d-4996-8cbd-05f3a8ac8cd9',
    'f790ac77-e5db-442f-bd8f-0cdb0ea4773a',
    '2cd80fa3-1c5d-4493-a005-6549135cdd2e',
    'f6b2441a-aaec-4871-8815-f5e6b2351cd8',
    '8b529fd5-708b-4591-9790-6b47bf6f9313'
]

with open('C:/Users/ASUS/Desktop/red team/subagent_summaries.md', 'w', encoding='utf-8') as out:
    for sub_id in ids:
        path = f'C:/Users/ASUS/.gemini/antigravity/brain/{sub_id}/.system_generated/logs/transcript.jsonl'
        if not os.path.exists(path):
            continue
        out.write(f'# Summary from {sub_id}\n\n')
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    if 'tool_calls' in obj:
                        for tc in obj['tool_calls']:
                            if tc.get('name') == 'send_message':
                                msg = tc['args'].get('Message', '')
                                out.write(msg + '\n\n')
                except BaseException:
                    pass
