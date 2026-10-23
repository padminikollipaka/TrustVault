
from database import get_db_connection

connection = get_db_connection()

try:
    user_count = connection.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]

    document_count = connection.execute(
        "SELECT COUNT(*) FROM documents"
    ).fetchone()[0]

    permissions_table = connection.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type = 'table' AND name = 'document_permissions'"
    ).fetchone()

    audit_table = connection.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type = 'table' AND name = 'audit_logs'"
    ).fetchone()

    print("Users:", user_count)
    print("Documents:", document_count)
    print("Permissions table:", permissions_table is not None)
    print("Audit table:", audit_table is not None)

finally:
    connection.close()
