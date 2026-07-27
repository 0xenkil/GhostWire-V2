
with open('agents/base_agent.py', 'r', encoding='utf-8') as f:
    content = f.read()

# We replace at line 918
replacement = """        if tool_name == "gobuster":
            if not re.search(r'\\b(dir|vhost|dns|fuzz|tftp|s3|gcs)\\b', repaired):
                repaired = re.sub(r'gobuster\\s+', 'gobuster dir ', repaired)
            repaired = repaired.replace('--useragent', '-a')
            repaired = re.sub(r'-H\\s+"[^":]+;q=[0-9.]+"', '', repaired)
            repaired = re.sub(r"-q", "", repaired)

        if tool_name == "whatweb":
            repaired = repaired.replace('--color -c', '')
            repaired = repaired.replace('--color', '')
            repaired = repaired.replace('-c ', ' ')

        if tool_name == "nmap":
            repaired = repaired.replace('-p 1-65535', '--top-ports 1000')
            repaired = repaired.replace('-p1-65535', '--top-ports 1000')
            if '--max-rtt-timeout' not in repaired:
                repaired += ' --max-rtt-timeout 2s --max-retries 1'
            if '--host-timeout' not in repaired:
                repaired += ' --host-timeout 10m'

        if tool_name == "sqlmap":"""

content = content.replace('        if tool_name == "sqlmap":', replacement, 1)

with open('agents/base_agent.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("done")
