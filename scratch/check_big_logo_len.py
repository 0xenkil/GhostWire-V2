from rich.cells import cell_len
import sys
sys.stdout.reconfigure(encoding='utf-8')


# Design: GHOSTWIRE split into two halves: GHOST and WIRE
# Each half on its own row set - but that's ugly
#
# Better approach: just make the big logo work at any width
# by REMOVING the outer panel's horizontal padding
# padding=(1,0) instead of (1,2)
# That saves 4 chars of margin on each side.
#
# Panel at 80 cols: border(2) + padding(0,2 -> 4) = 6 overhead -> usable = 74
# Without padding: border(2) + padding(0,0 -> 0) = 2 overhead -> usable = 78
# Logo is 80 chars - still doesn't fit at 79 default!
#
# So let's design a REAL 72-char wide version that works at 80-col terminals:
# At 80: border(2) + padding=(1,1 -> 2 each side = 4) = 6 -> usable = 74.
# 72 fits!

G = [
    " █████  ",  # 8
    "██   ██ ",
    "██   ██ ",
    "██ ████ ",
    "██    █ ",
    " █████  ",
]
H = [
    "██   ██ ",
    "██   ██ ",
    "███████ ",
    "██   ██ ",
    "██   ██ ",
    "██   ██ ",
]
O = [
    " █████  ",
    "██   ██ ",
    "██   ██ ",
    "██   ██ ",
    "██   ██ ",
    " █████  ",
]
S = [
    " █████  ",
    "██      ",
    " █████  ",
    "     ██ ",
    "     ██ ",
    " █████  ",
]
T = [
    "███████ ",
    "  ██    ",
    "  ██    ",
    "  ██    ",
    "  ██    ",
    "  ██    ",
]
W = [
    "██   ██ ",
    "██   ██ ",
    "██ █ ██ ",
    "██████  ",
    " ████   ",
    "  ██    ",
]
I = [
    "██████  ",
    "  ██    ",
    "  ██    ",
    "  ██    ",
    "  ██    ",
    "██████  ",
]
R = [
    "██████  ",
    "██   ██ ",
    "██████  ",
    "██  ██  ",
    "██   ██ ",
    "██   ██ ",
]
E = [
    "███████ ",
    "██      ",
    "█████   ",
    "██      ",
    "██      ",
    "███████ ",
]

letters = [G, H, O, S, T, W, I, R, E]

rows = []
for r in range(6):
    line = "".join(l[r] for l in letters)
    rows.append(line)

print("72-char logo:")
for i, line in enumerate(rows):
    print(f"({cell_len(line)}): {line}")

print(f"\nMax width: {max(cell_len(l) for l in rows)}")
