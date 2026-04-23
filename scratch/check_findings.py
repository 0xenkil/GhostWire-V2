import os
import sqlite3

results_dir = 'results'
latest = sorted([d for d in os.listdir(results_dir) if d.startswith('eng_')], key=lambda d: os.path.getmtime(os.path.join(results_dir, d)))[-1]
db_path = os.path.join('results', latest, 'state.db')
conn = sqlite3.connect(db_path)
c = conn.cursor()
c.execute("SELECT finding_type, severity, detail FROM findings WHERE phase='exploitation'")
for row in c.fetchall():
    print(f"Type: {row[0]}, Severity: {row[1]}, Detail: {row[2][:50]}...")
conn.close()
