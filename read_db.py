import sqlite3

try:
    conn = sqlite3.connect(r'results\eng_4bd01ad5\state.db')
    cursor = conn.cursor()
    cursor.execute("SELECT finding_type, detail, severity FROM findings")
    results = cursor.fetchall()

    for r in results:
        print(f"[{r[2]}] {r[0]}: {r[1][:200]}...")
except Exception as e:
    print("Error:", e)
