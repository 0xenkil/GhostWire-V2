import re
c = "masscan -p80,443 $(dig +short usageapi.216.198.79.1)"
print("original:", c)
c = re.sub(r'\$\(\s*dig\s+\+short\s+([^\)]+)\)', r'\1', c)
print("after clean_command:", c)
