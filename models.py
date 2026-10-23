
import sqlite3
from database import get_db_connection


def create_tables():
    """
    Create TrustVault tables and safely migrate the existing database.
    Existing users and documents are preserved.
    """
    connection = get_db_connection()

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL UNIQUE,
                uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        # Migrate existing users without deleting their accounts.
        user_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        }

        if "role" not in user_columns:
            connection.execute("""
                ALTER TABLE users
                ADD COLUMN role TEXT NOT NULL DEFAULT 'owner'
            """)

        # Add document categories for search and filtering.
        document_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(documents)"
            ).fetchall()
        }

        if "category" not in document_columns:
            connection.execute("""
                ALTER TABLE documents
                ADD COLUMN category TEXT NOT NULL DEFAULT 'General'
            """)

        # Named-user permissions for individual documents.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS document_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                permission TEXT NOT NULL
                    CHECK (permission IN ('read', 'edit')),
                granted_by INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (document_id, user_id),
                FOREIGN KEY (document_id)
                    REFERENCES documents(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id)
                    REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (granted_by)
                    REFERENCES users(id)
            )
        """)

        # Audit records form a hash chain.
        # Hashes will be calculated by the audit module.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER,
                action TEXT NOT NULL,
                document_id INTEGER,
                target_user_id INTEGER,
                outcome TEXT NOT NULL
                    CHECK (outcome IN ('success', 'denied', 'failure')),
                details TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL UNIQUE
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_documents_owner
            ON documents(owner_id)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_documents_uploaded
            ON documents(uploaded_at)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_permissions_user_document
            ON document_permissions(user_id, document_id)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_created
            ON audit_logs(created_at)
        """)

        # Protect audit records from ordinary SQL updates and deletes.
        # This does not protect against someone who can replace the DB file.
        connection.executescript("""
            CREATE TRIGGER IF NOT EXISTS prevent_audit_update
            BEFORE UPDATE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'Audit records cannot be updated');
            END;

            CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
            BEFORE DELETE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'Audit records cannot be deleted');
            END;
        """)

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()
