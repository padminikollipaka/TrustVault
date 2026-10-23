
import re
import uuid
from pathlib import Path

from config import Config


def allowed_file(filename):
    """Check whether a filename has an allowed extension."""
    if not filename or "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()

    return extension in Config.ALLOWED_EXTENSIONS


def create_stored_filename(original_filename):
    """Generate a unique storage name instead of trusting the user's name."""
    extension = Path(original_filename).suffix.lower()

    # Keep only a short, safe extension.
    if not re.fullmatch(r"\.[a-z0-9]{1,10}", extension):
        raise ValueError("Invalid file extension.")

    return f"{uuid.uuid4().hex}{extension}"


def get_upload_folder():
    """Create the upload directory if it does not exist."""
    upload_folder = Path(Config.UPLOAD_FOLDER)
    upload_folder.mkdir(parents=True, exist_ok=True)

    return upload_folder
