
import sqlite3

database_path = "instance/trustvault.db"

connection = sqlite3.connect(database_path)
connection.row_factory = sqlite3.Row

try:
    rows = connection.execute(
        """
        SELECT id, action, outcome, details, created_at
        FROM audit_logs
        WHERE action = ?
        ORDER BY id DESC
        LIMIT 5
        """,
        ("authentication_denied",),
    ).fetchall()

    print("Matching audit entries:")
    for row in rows:
        print(dict(row))

    if not rows:
        print("No authentication_denied entries found.")

finally:
    connection.close()
