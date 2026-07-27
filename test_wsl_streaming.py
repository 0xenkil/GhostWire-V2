from core.wsl_executor import WSLExecutor
import sys
import os

sys.path.append(os.getcwd())

executor = WSLExecutor()


def on_line(line):
    print("LIVE FEED:", line)


cmd = 'ffuf -u http://127.0.0.1/FUZZ -w /tmp/word.txt'
print("Running:", cmd)
exit_code, out, err = executor.execute_streaming(
    cmd, timeout=30, on_line=on_line)
print("Exit code:", exit_code)
print("Out length:", len(out))
print("Err length:", len(err))
print("Err preview:", err[:500])
