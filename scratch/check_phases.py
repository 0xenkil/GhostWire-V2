import os
import sqlite3

def get_latest_engagement():
    results_dir = 'results'
    engagements = [d for d in os.listdir(results_dir) if d.startswith('eng_')]
    if not engagements:
        return None
    latest = sorted(engagements, key=lambda d: os.path.getmtime(os.path.join(results_dir, d)))[-1]
    return latest

latest = get_latest_engagement()
if not latest:
    print("No engagements found.")
else:
    print(f"Latest Engagement: {latest}")
    db_path = os.path.join('results', latest, 'state.db')
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT phase, status, started_at FROM phases ORDER BY started_at")
        print("PHASE EXECUTION ORDER:")
        for row in c.fetchall():
            print(row)
        conn.close()
    else:
        print("DB not found.")
