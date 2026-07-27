
def safe_print(text):
    try:
        print(text.encode('ascii', errors='replace').decode('ascii'))
    except Exception:
        print("".join(c if ord(c) < 128 else '?' for c in text))


log_path = r"C:\Users\ASUS\Desktop\red team\last ran cli out.txt"
with open(log_path, 'rb') as f:
    content = f.read()

# Split by \r or \n
lines = content.decode(
    'utf-8',
    errors='ignore').replace(
        '\r',
    '\n').split('\n')

for idx, line in enumerate(lines):
    if "Invalid target definition!" in line:
        safe_print(f"\n--- MATCH AT LINE {idx} ---")
        # Print surrounding lines
        start = max(0, idx - 15)
        end = min(len(lines), idx + 5)
        for i in range(start, end):
            safe_print(f"Line {i:04d}: {lines[i]}")
