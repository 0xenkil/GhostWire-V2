"""
Fallback installation helpers for tools that need special handling.
"""
import subprocess
import os

def install_wordlists():
    """Install common wordlists if not present."""
    paths = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/rockyou.txt.gz"
    ]
    if not any(os.path.exists(p) for p in paths):
        subprocess.run(["sudo", "apt-get", "install", "-y", "wordlists"], capture_output=True)
        # Unzip rockyou if present but compressed
        gz = "/usr/share/wordlists/rockyou.txt.gz"
        dest = "/usr/share/wordlists/rockyou.txt"
        if os.path.exists(gz) and not os.path.exists(dest):
            import gzip
            import shutil
            with gzip.open(gz, 'rb') as f_in:
                with open(dest, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

def install_seclist():
    """Install SecLists if not present."""
    if not os.path.exists("/usr/share/seclists"):
        result = subprocess.run(
            ["sudo", "apt-get", "install", "-y", "seclists"],
            capture_output=True
        )
        if result.returncode != 0:
            subprocess.run([
                "git", "clone", "--depth", "1", 
                "https://github.com/danielmiessler/SecLists.git", 
                "/usr/share/seclists"
            ], capture_output=True)

