import sys
sys.stdout.reconfigure(encoding='utf-8')

# Custom designed 6-character aligned block font for GHOSTWIRE
G = [
    " ▄███▄",
    "██▀  ▀",
    "██ ▄█▄",
    "██▄  █",
    " ▀███▀"
]

H = [
    "██  ██",
    "██  ██",
    "██████",
    "██  ██",
    "██  ██"
]

O = [
    " ▄██▄ ",
    "██  ██",
    "██  ██",
    "██  ██",
    " ▀██▀ "
]

S = [
    " ▄███▄",
    "██▀   ",
    " ▀███▄",
    "▄   ██",
    "▀████▀"
]

T = [
    "██████",
    "  ██  ",
    "  ██  ",
    "  ██  ",
    "  ██  "
]

W = [
    "██  ██",
    "██  ██",
    "██  ██",
    "▀████▀",
    " ▀██▀ "
]

I = [
    "██████",
    "  ██  ",
    "  ██  ",
    "  ██  ",
    "██████"
]

R = [
    "█████▄",
    "██  ██",
    "█████▀",
    "██  ██",
    "██  ██"
]

E = [
    "██████",
    "██    ",
    "█████ ",
    "██    ",
    "██████"
]

letters = [G, H, O, S, T, W, I, R, E]

assembled = []
for row in range(5):
    line_parts = []
    for l in letters:
        line_parts.append(l[row])
    assembled.append(" ".join(line_parts))

for i, line in enumerate(assembled):
    print(f"Line {i + 1} (len={len(line)}): {line}")
