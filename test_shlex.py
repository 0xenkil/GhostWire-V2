import shlex
print(shlex.quote("ffuf -H 'User-Agent: Mozilla/5.0' -H 'X-Forwarded-For: 231.21.108.60'"))
