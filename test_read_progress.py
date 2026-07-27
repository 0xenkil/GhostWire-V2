import subprocess

p = subprocess.Popen(["python", "test_progress.py"],
                     stderr=subprocess.PIPE, text=True)
for line in p.stderr:
    print("GOT LINE:", repr(line))
