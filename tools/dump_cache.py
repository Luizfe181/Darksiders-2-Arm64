import sqlite3
c = sqlite3.connect(r'C:\Darksiders2-Android-Port\analysis\harness_cache.sqlite')
cur = c.cursor()
print("TABLES:")
tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")]
for (name, sql) in cur.execute("SELECT name, sql FROM sqlite_master WHERE type='table'"):
    print(" ", name, "\n   ", sql)
for t in tables:
    n = cur.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0]
    print(f"--- {t}: {n} rows")
    for row in cur.execute(f"SELECT * FROM [{t}] LIMIT 8"):
        print("   ", str(row)[:600])
