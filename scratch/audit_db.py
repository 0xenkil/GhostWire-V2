import sqlite3
import sys

db_path = "results/eng_777f9245/state.db"
conn = sqlite3.connect(db_path)
curr = conn.cursor()

print("--- TOOL RUNS ---")
# The schema uses status, exit_code, duration_sec
curr.execute("SELECT tool, status, exit_code, duration_sec FROM tool_runs")
for row in curr.fetchall():
    print(row)

print("\n--- FINDINGS ---")
# Schema uses finding_type
curr.execute("SELECT finding_type, target, detail, severity FROM findings")
for row in curr.fetchall():
    print(row)

conn.close()
