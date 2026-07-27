import sys
sys.stdout.reconfigure(encoding='utf-8')

# BIG BOXY font - each letter is 10 chars wide x 7 lines tall
# We only need G H O S T W I R E (9 letters)
# Target: fill ~120 cols, but also look great at 100 cols

G = [
    " ██████  ",
    "██       ",
    "██  ████ ",
    "██    ██ ",
    "██    ██ ",
    " ██████  ",
    "         ",
]
H = [
    "██    ██ ",
    "██    ██ ",
    "████████ ",
    "██    ██ ",
    "██    ██ ",
    "██    ██ ",
    "         ",
]
O = [
    " ██████  ",
    "██    ██ ",
    "██    ██ ",
    "██    ██ ",
    "██    ██ ",
    " ██████  ",
    "         ",
]
S = [
    " ███████ ",
    "██       ",
    " ██████  ",
    "      ██ ",
    "      ██ ",
    "███████  ",
    "         ",
]
T = [
    "████████ ",
    "   ██    ",
    "   ██    ",
    "   ██    ",
    "   ██    ",
    "   ██    ",
    "         ",
]
W = [
    "██     ██",
    "██     ██",
    "██  █  ██",
    "██ ███ ██",
    "███   ███",
    " ██   ██ ",
    "         ",
]
I = [
    "███████  ",
    "  ██     ",
    "  ██     ",
    "  ██     ",
    "  ██     ",
    "███████  ",
    "         ",
]
R = [
    "███████  ",
    "██    ██ ",
    "███████  ",
    "██   ██  ",
    "██    ██ ",
    "██    ██ ",
    "         ",
]
E = [
    "████████ ",
    "██       ",
    "█████    ",
    "██       ",
    "██       ",
    "████████ ",
    "         ",
]

letters = [G, H, O, S, T, W, I, R, E]

assembled = []
for row in range(7):
    line = "".join(l[row] for l in letters)
    assembled.append(line)

print("Full logo preview:")
for i, line in enumerate(assembled):
    print(f"L{i + 1} ({len(line)}): {line}")

print("\nTotal width:", max(len(l) for l in assembled))
