from rich.cells import cell_len
import sys
sys.stdout.reconfigure(encoding='utf-8')


logo = [
    " ▄███▄ ██  ██  ▄██▄   ▄███▄ ██████ ██  ██ ██████ █████▄ ██████",
    "██▀  ▀ ██  ██ ██  ██ ██▀      ██   ██  ██   ██   ██  ██ ██    ",
    "██ ▄█▄ ██████ ██  ██  ▀███▄   ██   ██  ██   ██   █████▀ █████ ",
    "██▄  █ ██  ██ ██  ██ ▄   ██   ██   ▀████▀   ██   ██  ██ ██    ",
    " ▀███▀ ██  ██  ▀██▀  ▀████▀   ██    ▀██▀  ██████ ██  ██ ██████"
]

for i, line in enumerate(logo):
    print(f"Line {i + 1}: char_len={len(line)}, cell_len={cell_len(line)}")
