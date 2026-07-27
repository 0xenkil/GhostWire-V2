import subprocess
import time

cmd = 'ffuf -H '"'"'User-Agent: Mozilla/5.0'"'"' -H '"'"'X-Forwarded-For: 231.21.108.60'"'"''
wsl_cmd = ["wsl", "-e", "bash", "-c", f"timeout 1200s bash -c {cmd}"]

start = time.time()
p = subprocess.Popen(
    wsl_cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True)
stdout, stderr = p.communicate(timeout=10)
print("Return code:", p.returncode)
print("Stderr:", stderr)
