
import sqlite3
from pathlib import Path

# Main project folder
BASE_DIR = Path(__file__).resolve().parent

# Store the database inside the instance folder
INSTANCE_DIR = BASE_DIR / "instance"
DATABASE_PATH = INSTANCE_DIR / "trustvault.db"


def get_db_connection():
    """Create and return a connection to the TrustVault database."""
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection
