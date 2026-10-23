
import getpass
import sqlite3

from werkzeug.security import generate_password_hash

from auth import validate_password
from database import get_db_connection
from models import create_tables


def create_admin():
    """Create an administrator through a local setup script."""

    print("\n=== TrustVault Administrator Setup ===\n")

    # Ensure the database and required tables exist.
    create_tables()

    username = input("Enter admin username: ").strip()
    email = input("Enter admin email: ").strip().lower()

    if not username or not email:
        print("Error: Username and email are required.")
        return

    password = getpass.getpass("Enter admin password: ")
    confirm_password = getpass.getpass("Confirm admin password: ")

    if password != confirm_password:
        print("Error: Passwords do not match.")
        return

    is_valid, message = validate_password(password)

    if not is_valid:
        print(f"Error: {message}")
        return

    password_hash = generate_password_hash(password)

    connection = get_db_connection()

    try:
        connection.execute(
            """
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, 'admin')
            """,
            (username, email, password_hash),
        )

        connection.commit()
        print("\nAdministrator account created successfully.")
        print(f"Username: {username}")
        print(f"Email: {email}")
        print("You can now log in using this email and password.")

    except sqlite3.IntegrityError:
        connection.rollback()
        print(
            "\nError: This username or email may already exist."
        )

    except Exception:
        connection.rollback()
        print("\nError: The administrator account could not be created.")

    finally:
        connection.close()


if __name__ == "__main__":
    create_admin()
