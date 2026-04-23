import zipfile
import os
import filecmp
from pathlib import Path
import sys

zip_path = r"C:\Users\ASUS\Downloads\working red team.zip"
extract_dir = r"C:\Users\ASUS\Desktop\red team\working"

if not os.path.exists(zip_path):
    print(f"Zip file not found: {zip_path}")
    sys.exit(1)

# Extract
with zipfile.ZipFile(zip_path, 'r') as zip_ref:
    zip_ref.extractall(extract_dir)

print(f"Extracted to {extract_dir}")

# Diff
current_dir = r"C:\Users\ASUS\Desktop\red team"
working_dir = os.path.join(extract_dir, "red team") # Assuming it extracts to a 'red team' folder

if not os.path.exists(working_dir):
    # Try finding the root of the extracted code
    dirs = [d for d in os.listdir(extract_dir) if os.path.isdir(os.path.join(extract_dir, d))]
    if len(dirs) == 1:
        working_dir = os.path.join(extract_dir, dirs[0])
    else:
        working_dir = extract_dir

print(f"Comparing {working_dir} to {current_dir}")

def compare_dirs(dir1, dir2):
    diffs = []
    for root, _, files in os.walk(dir1):
        for file in files:
            if file.endswith(".py"):
                f1 = os.path.join(root, file)
                rel_path = os.path.relpath(f1, dir1)
                f2 = os.path.join(dir2, rel_path)
                
                if not os.path.exists(f2):
                    diffs.append(f"Missing in current: {rel_path}")
                elif not filecmp.cmp(f1, f2, shallow=False):
                    diffs.append(f"Different: {rel_path}")
    return diffs

diffs = compare_dirs(working_dir, current_dir)
if diffs:
    print("Found differences:")
    for d in diffs:
        print(d)
else:
    print("No differences found in .py files!")
