import sys
import time

for i in range(5):
    sys.stderr.write(f"Progress {i}\r")
    sys.stderr.flush()
    time.sleep(0.5)
sys.stderr.write("Done\n")
