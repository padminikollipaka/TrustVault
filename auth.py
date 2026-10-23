
import re
import sqlite3

from werkzeug.security import generate_password_hash, check_password_hash

from database import get_db_connection


def validate_password(password):
    """Check whether a password meets TrustVault's strength requirements."""

    if not isinstance(password, str) or not password:
        return False, "Password is required."

    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if not re.search(r"[A-Z]", password):
        return False, "Include at least one uppercase letter (A-Z)."

    if not re.search(r"[a-z]", password):
        return False, "Include at least one lowercase letter (a-z)."

    if not re.search(r"\d", password):
        return False, "Include at least one number (0-9)."

    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Include at least one special character, such as @, #, or !."

    return True, "Password is strong."


def register_user(username, email, password):
    """Register a new account with a securely hashed password."""

    if not all(isinstance(value, str) for value in (username, email, password)):
        return False, "Username, email, and password are required."

    username = username.strip()
    email = email.strip().lower()

    if not username or not email or not password:
        return False, "Username, email, and password are required."

    is_valid, message = validate_password(password)

    if not is_valid:
        return False, message

    password_hash = generate_password_hash(password)
    connection = get_db_connection()

    try:
        # The database default assigns new public registrations the owner role.
        # Users cannot choose their own role during registration.
        connection.execute(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (username, email, password_hash),
        )

        connection.commit()
        return True, "User registered successfully."

    except sqlite3.IntegrityError:
        return False, "Username or email already exists."

    finally:
        connection.close()


def verify_user(email, password):
    """Verify credentials and return the user's role after successful login."""

    if not isinstance(email, str) or not isinstance(password, str):
        return None

    if not email or not password:
        return None

    connection = get_db_connection()

    try:
        user = connection.execute(
            """
            SELECT id, username, email, password_hash, role
            FROM users
            WHERE email = ?
            """,
            (email.strip().lower(),),
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            return {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
            }

        return None

    finally:
        connection.close()
