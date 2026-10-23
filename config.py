
import os
from pathlib import Path
from dotenv import load_dotenv

# Find the main TrustVault project folder
BASE_DIR = Path(__file__).resolve().parent

# Load private settings from the .env file
load_dotenv(BASE_DIR / ".env")


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")

    # Refuse to start without a configured secret key.
    if not SECRET_KEY or SECRET_KEY == "replace_with_a_private_random_key":
        raise RuntimeError(
            "SECRET_KEY is missing or is still the example placeholder. "
            "Set a private random key in your local .env file."
        )

    # Maximum upload size: 10 MB
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024

    # Folder for uploaded documents
    UPLOAD_FOLDER = BASE_DIR / "uploads"

    # Allowed document file extensions
    ALLOWED_EXTENSIONS = {
        "pdf",
        "txt",
        "doc",
        "docx",
        "png",
        "jpg",
        "jpeg",
    }
