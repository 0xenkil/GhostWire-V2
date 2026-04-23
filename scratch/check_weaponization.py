import sqlite3
import os

db_path = 'results/' + sorted(os.listdir('results'))[-1] + '/state.db'
conn = sqlite3.connect(db_path)
c = conn.cursor()
c.execute("SELECT tool, status, command, stdout, stderr FROM tool_runs WHERE phase='weaponization'")
for row in c.fetchall():
    print(f"Tool: {row[0]}, Status: {row[1]}, Command: {row[2][:100]}")
    print(f"Stdout: {row[3][:100]}")
    print(f"Stderr: {row[4][:100]}")
    print("-" * 40)
