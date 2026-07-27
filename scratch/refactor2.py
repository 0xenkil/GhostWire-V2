import re

file_path = r"C:\Users\ASUS\Desktop\red team\agents\exploitation_agent.py"
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Replace the cognitive engine part with a call to _stage_exploiter,
# passing necessary vars
cognitive_pattern = r"(# ── Hypothesis-Driven Cognitive Exploitation \(V7\.1\) ────────────\n.*?)(# Flush any remaining dedup stats)"
cognitive_match = re.search(cognitive_pattern, content, flags=re.DOTALL)

if cognitive_match:
    cog_code = cognitive_match.group(1)

    # Define _stage_exploiter to contain this code
    stage_exploiter_code = f"""
    def _stage_exploiter(self, target: str, roe: dict):
{cog_code}
"""
    # Fix indentation for the extracted code (it is indented 8 spaces, needs to be 8 spaces inside the method which is already 8)
    # wait, cog_code has 8 spaces. The method body needs 8 spaces.

    content = content.replace(
        cog_code, "        self._stage_exploiter(target, roe)\n\n        ")

    # Now replace the dummy _stage_exploiter with the real one
    content = re.sub(
        r"    def _stage_exploiter\(self\):\n\s+self\.log\.info\(\"Pipeline: Exploiter Stage\"\)",
        stage_exploiter_code.strip('\n'),
        content)

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Refactor 2 complete.")
