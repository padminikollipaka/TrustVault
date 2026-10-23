import magic
import zipfile
from io import BytesIO
from datetime import datetime

from werkzeug.exceptions import RequestEntityTooLarge

import logging
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    jsonify,
    request,
    session,
    send_from_directory,
    render_template,
)
from werkzeug.utils import secure_filename

from config import Config
from auth import register_user, verify_user
from database import get_db_connection
from documents import (
    allowed_file,
    create_stored_filename,
    get_upload_folder,
)
from audit import write_audit_log, verify_audit_chain


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)
app.config.from_object(Config)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Local HTTP development only.
# Enable Secure cookies when deploying behind HTTPS.
app.config["SESSION_COOKIE_SECURE"] = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("trustvault")


@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    return jsonify({
        "success": False,
        "error": "File is too large. The maximum upload size is 10 MB."
    }), 413


# --------------------------------------------------
# SECURITY AUDIT HELPER
# --------------------------------------------------

def log_denied_attempt(
    actor_id,
    action,
    document_id=None,
    target_user_id=None,
    details=None,
):
    """Record a denied action without exposing private information."""

    connection = None

    try:
        connection = get_db_connection()

        write_audit_log(
            connection,
            actor_id=actor_id,
            action=action,
            outcome="denied",
            document_id=document_id,
            target_user_id=target_user_id,
            details=details or {},
        )

        connection.commit()

    except Exception:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass

        logger.exception(
            "Could not record denied security event: %s",
            action,
        )

    finally:
        if connection is not None:
            connection.close()


# --------------------------------------------------
# AUTHENTICATION HELPERS
# --------------------------------------------------

def current_user():
    """Return the logged-in user, or None."""

    user_id = session.get("user_id")

    if not user_id:
        return None

    connection = get_db_connection()

    try:
        user = connection.execute(
            """
            SELECT id, username, email, role
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

        return dict(user) if user else None

    finally:
        connection.close()


def login_required(function):
    """Require a valid authenticated user."""

    @wraps(function)
    def wrapper(*args, **kwargs):
        user = current_user()

        if not user:
            log_denied_attempt(
                actor_id=None,
                action="authentication_denied",
                details={
                    "method": request.method,
                    "path": request.path,
                    "reason": "authentication_required",
                },
            )

            session.clear()

            return jsonify({
                "success": False,
                "error": "Authentication required.",
            }), 401

        return function(*args, **kwargs)

    return wrapper


def get_document_access(document_id, user):
    """
    Return the document if the user owns it or has explicit access.

    Returns:
        (document, permission) when access is allowed.
        (None, None) when access is not allowed.
    """

    connection = get_db_connection()

    try:
        document = connection.execute(
            """
            SELECT
                id,
                owner_id,
                filename,
                stored_filename,
                category,
                uploaded_at
            FROM documents
            WHERE id = ?
            """,
            (document_id,),
        ).fetchone()

        if not document:
            return None, None

        document = dict(document)

        # The owner has full access.
        if document["owner_id"] == user["id"]:
            return document, "owner"

        # Other users need explicit permission.
        permission = connection.execute(
            """
            SELECT permission
            FROM document_permissions
            WHERE document_id = ?
              AND user_id = ?
            """,
            (document_id, user["id"]),
        ).fetchone()

        if permission:
            return document, permission["permission"]

        return None, None

    finally:
        connection.close()


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "success": True,
        "message": "TrustVault backend is running.",
    }), 200


# --------------------------------------------------
# USER REGISTRATION
# --------------------------------------------------

@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "A valid JSON request body is required.",
        }), 400

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    success, message = register_user(
        username,
        email,
        password,
    )

    if not success:
        status_code = (
            409
            if "already exists" in message.lower()
            else 400
        )

        return jsonify({
            "success": False,
            "error": message,
        }), status_code

    return jsonify({
        "success": True,
        "message": message,
    }), 201


# --------------------------------------------------
# USER LOGIN
# --------------------------------------------------

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "A valid JSON request body is required.",
        }), 400

    email = data.get("email")
    password = data.get("password")

    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify({
            "success": False,
            "error": "Email and password are required.",
        }), 400

    user = verify_user(email, password)

    if not user:
        return jsonify({
            "success": False,
            "error": "Invalid email or password.",
        }), 401

    # Start a fresh session after successful authentication.
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]

    logger.info(
        "Successful login for user_id=%s",
        user["id"],
    )

    return jsonify({
        "success": True,
        "message": "Login successful.",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
        },
    }), 200


# --------------------------------------------------
# CURRENT USER
# --------------------------------------------------

@app.route("/api/me", methods=["GET"])
def api_me():
    user = current_user()

    if not user:
        return jsonify({
            "success": True,
            "logged_in": False,
        }), 200

    return jsonify({
        "success": True,
        "logged_in": True,
        "user": user,
    }), 200


# --------------------------------------------------
# USER LOGOUT
# --------------------------------------------------

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()

    return jsonify({
        "success": True,
        "message": "Logged out successfully.",
    }), 200


# --------------------------------------------------
# LIST DOCUMENT PERMISSIONS
# Only the document owner can see them.
# --------------------------------------------------

@app.route(
    "/api/documents/<int:document_id>/permissions",
    methods=["GET"],
)
def list_document_permissions(document_id):
    user = current_user()

    if not user:
        log_denied_attempt(
            actor_id=None,
            action="permission_list_authentication_denied",
            document_id=document_id,
            details={
                "method": request.method,
                "path": request.path,
                "reason": "authentication_required",
            },
        )

        return jsonify({
            "success": False,
            "error": "Authentication required.",
        }), 401

    connection = get_db_connection()

    try:
        document = connection.execute(
            """
            SELECT owner_id
            FROM documents
            WHERE id = ?
            """,
            (document_id,),
        ).fetchone()

        if not document or document["owner_id"] != user["id"]:
            log_denied_attempt(
                actor_id=user["id"],
                action="permission_list_denied",
                document_id=document_id,
                details={
                    "method": request.method,
                    "path": request.path,
                    "reason": "owner_access_required",
                },
            )

            return jsonify({
                "success": False,
                "error": "Document not found.",
            }), 404

        rows = connection.execute(
            """
            SELECT
                p.user_id,
                u.username,
                u.email,
                p.permission,
                p.created_at
            FROM document_permissions AS p
            JOIN users AS u
                ON u.id = p.user_id
            WHERE p.document_id = ?
            ORDER BY p.created_at DESC
            """,
            (document_id,),
        ).fetchall()

        return jsonify({
            "success": True,
            "permissions": [
                dict(row) for row in rows
            ],
        }), 200

    finally:
        connection.close()


# --------------------------------------------------
# GRANT DOCUMENT PERMISSION
# Only the document owner can grant access.
# --------------------------------------------------

@app.route(
    "/api/documents/<int:document_id>/permissions",
    methods=["POST"],
)
@login_required
def grant_document_permission(document_id):
    user = current_user()

    if not user:
        return jsonify({
            "success": False,
            "error": "Authentication required.",
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "A valid JSON request body is required.",
        }), 400

    email = data.get("email")
    permission = data.get("permission")

    if (
        not isinstance(email, str)
        or permission not in ("read", "edit")
    ):
        return jsonify({
            "success": False,
            "error": (
                "Provide a registered user's email and "
                "permission 'read' or 'edit'."
            ),
        }), 400

    email = email.strip().lower()

    if not email:
        return jsonify({
            "success": False,
            "error": "A registered user's email is required.",
        }), 400

    connection = get_db_connection()

    try:
        document = connection.execute(
            """
            SELECT owner_id
            FROM documents
            WHERE id = ?
            """,
            (document_id,),
        ).fetchone()

        if not document or document["owner_id"] != user["id"]:
            log_denied_attempt(
                actor_id=user["id"],
                action="permission_grant_denied",
                document_id=document_id,
                details={
                    "method": request.method,
                    "path": request.path,
                    "reason": "owner_access_required",
                },
            )

            return jsonify({
                "success": False,
                "error": "Document not found.",
            }), 404

        target = connection.execute(
            """
            SELECT id, email
            FROM users
            WHERE email = ?
            """,
            (email,),
        ).fetchone()
        if not target:
            write_audit_log(
                connection,
                actor_id=user["id"],
                action="permission_grant_denied",
                outcome="denied",
                document_id=document_id,
                details={
                    "reason": "recipient_not_found",
                    "requested_email": email,
                    "permission": permission,
                },
            )
            connection.commit()

            return jsonify({
                "success": False,
                "error": "Registered user not found.",
            }), 404
        if target["id"] == user["id"]:
            write_audit_log(
                connection,
                actor_id=user["id"],
                action="permission_grant_denied",
                outcome="denied",
                document_id=document_id,
                target_user_id=target["id"],
                details={
                    "reason": "owner_cannot_grant_permission_to_self",
                    "permission": permission,
                },
            )
            connection.commit()

            return jsonify({
                "success": False,
                "error": "You already own this document.",
            }), 400
        # Create or update the user's permission.
        # Check whether this user already has permission.
        existing_permission = connection.execute(
            """
            SELECT permission
            FROM document_permissions
            WHERE document_id = ? AND user_id = ?
            """,
            (document_id, target["id"]),
        ).fetchone()
        previous_permission = (
            existing_permission["permission"]
            if existing_permission
            else None
        )

        # Create or update the user's permission.
        connection.execute(
            """
            INSERT INTO document_permissions
                (document_id, user_id, permission, granted_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(document_id, user_id)
            DO UPDATE SET
                permission = excluded.permission,
                granted_by = excluded.granted_by,
                created_at = CURRENT_TIMESTAMP
            """,
            (
                document_id,
                target["id"],
                permission,
                user["id"],
            ),
        )

        # Record what changed in the same transaction.
        action = (
            "permission_granted"
            if previous_permission is None
            else "permission_updated"
        )

        write_audit_log(
            connection,
            actor_id=user["id"],
            action=action,
            outcome="success",
            document_id=document_id,
            target_user_id=target["id"],
            details={
                "previous_permission": previous_permission,
                "new_permission": permission,
            },
        )

        connection.commit()

        return jsonify({
            "success": True,
            "message": (
                "Document access granted."
                if previous_permission is None
                else "Document permission updated."
            ),
            "permission": {
                "document_id": document_id,
                "user_id": target["id"],
                "email": target["email"],
                "permission": permission,
            },
        }), 200

    except Exception:
        connection.rollback()

        logger.exception("Could not grant document permission")

        return jsonify({
            "success": False,
            "error": "Could not update document permissions.",
        }), 500

    finally:
        connection.close()

# --------------------------------------------------
# REVOKE DOCUMENT PERMISSION
# Only the document owner can revoke access.
# --------------------------------------------------

@app.route(
    "/api/documents/<int:document_id>/permissions/<int:target_user_id>",
    methods=["DELETE"],
)
@login_required
def revoke_document_permission(document_id, target_user_id):
    user = current_user()

    if not user:
        return jsonify({
            "success": False,
            "error": "Authentication required.",
        }), 401

    connection = get_db_connection()

    try:
        document = connection.execute(
            """
            SELECT owner_id
            FROM documents
            WHERE id = ?
            """,
            (document_id,),
        ).fetchone()

        if not document or document["owner_id"] != user["id"]:
            log_denied_attempt(
                actor_id=user["id"],
                action="permission_revoke_denied",
                document_id=document_id,
                target_user_id=target_user_id,
                details={
                    "method": request.method,
                    "path": request.path,
                    "reason": "owner_access_required",
                },
            )

            return jsonify({
                "success": False,
                "error": "Document not found.",
            }), 404

        cursor = connection.execute(
            """
            DELETE FROM document_permissions
            WHERE document_id = ?
              AND user_id = ?
            """,
            (document_id, target_user_id),
        )

        if cursor.rowcount == 0:
            connection.rollback()

            log_denied_attempt(
                actor_id=user["id"],
                action="permission_revoke_denied",
                document_id=document_id,
                target_user_id=target_user_id,
                details={
                    "method": request.method,
                    "path": request.path,
                    "reason": "permission_not_found",
                },
            )

            return jsonify({
                "success": False,
                "error": "Permission not found.",
            }), 404

        write_audit_log(
            connection,
            actor_id=user["id"],
            action="permission_revoked",
            outcome="success",
            document_id=document_id,
            target_user_id=target_user_id,
        )

        connection.commit()

        return jsonify({
            "success": True,
            "message": "Document access revoked.",
        }), 200

    except Exception:
        connection.rollback()

        logger.exception("Could not revoke document permission")

        return jsonify({
            "success": False,
            "error": "Could not revoke document access.",
        }), 500

    finally:
        connection.close()


def validate_file_content(filename, file_bytes):
    """Check whether file content matches its permitted extension."""

    if not file_bytes:
        return False

    extension = Path(filename).suffix.lower()

    try:
        detected_type = magic.from_buffer(
            file_bytes[:8192],
            mime=True,
        )
    except Exception:
        logger.exception("Could not identify uploaded file type")
        return False

    if extension == ".pdf":
        return detected_type == "application/pdf"

    if extension in (".jpg", ".jpeg"):
        return detected_type == "image/jpeg"

    if extension == ".png":
        return detected_type == "image/png"

    if extension == ".txt":
        # Text files should contain valid UTF-8 text and no null bytes.
        try:
            return b"\x00" not in file_bytes and (
                file_bytes.decode("utf-8") is not None
            )
        except UnicodeDecodeError:
            return False

    if extension == ".docx":
        # A DOCX file is a ZIP package containing Word document files.
        try:
            with zipfile.ZipFile(BytesIO(file_bytes)) as archive:
                names = archive.namelist()
                return (
                    "[Content_Types].xml" in names
                    and "word/document.xml" in names
                )
        except (zipfile.BadZipFile, OSError):
            return False

    if extension == ".doc":
        # Legacy Word documents use the OLE compound-file format.
        return detected_type in (
            "application/x-ole-storage",
            "application/CDFV2",
        )

    return False

# --------------------------------------------------
# UPLOAD DOCUMENT
# --------------------------------------------------


@app.route("/api/documents/upload", methods=["POST"])
@login_required
def upload_document():
    user = current_user()

    if not user:
        return jsonify({
            "success": False,
            "error": "Authentication required.",
        }), 401

    uploaded_file = request.files.get("file")

    if not uploaded_file or not uploaded_file.filename:
        return jsonify({
            "success": False,
            "error": "Please select a file to upload.",
        }), 400

    original_filename = secure_filename(uploaded_file.filename)

    if not original_filename:
        return jsonify({
            "success": False,
            "error": "Invalid filename.",
        }), 400

    if not allowed_file(original_filename):
        return jsonify({
            "success": False,
            "error": "This file type is not allowed.",
        }), 400

    # Read the uploaded content before saving it.
    file_bytes = uploaded_file.read()

    if not file_bytes:
        return jsonify({
            "success": False,
            "error": "Empty files cannot be uploaded.",
        }), 400

    if not validate_file_content(original_filename, file_bytes):
        return jsonify({
            "success": False,
            "error": (
                "File content does not match an accepted file format."
            ),
        }), 400

    category = request.form.get("category", "General")
    category = category.strip()[:80] or "General"

    upload_folder = Path(get_upload_folder())
    upload_folder.mkdir(parents=True, exist_ok=True)

    stored_filename = create_stored_filename(original_filename)
    stored_path = upload_folder / stored_filename

    try:
        # Save only after the content has passed validation.
        stored_path.write_bytes(file_bytes)

        connection = get_db_connection()

        try:
            cursor = connection.execute(
                """
                INSERT INTO documents
                    (owner_id, filename, stored_filename, category)
                VALUES (?, ?, ?, ?)
                """,
                (
                    user["id"],
                    original_filename,
                    stored_filename,
                    category,
                ),
            )

            document_id = cursor.lastrowid

            write_audit_log(
                connection,
                actor_id=user["id"],
                action="document_uploaded",
                outcome="success",
                document_id=document_id,
                details={
                    "filename": original_filename,
                    "category": category,
                },
            )

            connection.commit()

        finally:
            connection.close()

    except Exception:
        logger.exception(
            "Document upload failed for user_id=%s",
            user["id"],
        )

        try:
            if stored_path.exists():
                stored_path.unlink()
        except OSError:
            logger.exception("Could not clean up failed upload")

        return jsonify({
            "success": False,
            "error": "The document could not be uploaded.",
        }), 500

    return jsonify({
        "success": True,
        "message": "Document uploaded successfully.",
        "document": {
            "id": document_id,
            "filename": original_filename,
            "category": category,
        },
    }), 201

# --------------------------------------------------
# LIST ACCESSIBLE DOCUMENTS
# --------------------------------------------------


@app.route("/api/documents", methods=["GET"])
@login_required
def list_documents():
    user = current_user()

    if not user:
        return jsonify({
            "success": False,
            "error": "Authentication required.",
        }), 401

    # Optional search filters.
    name = request.args.get("name", "").strip()
    category = request.args.get("category", "").strip()
    owner = request.args.get("owner", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    # Validate that dates use YYYY-MM-DD and are real calendar dates.
    for date_value in (date_from, date_to):
        if date_value:
            try:
                datetime.strptime(date_value, "%Y-%m-%d")
            except ValueError:
                return jsonify({
                    "success": False,
                    "error": "Dates must be valid dates in YYYY-MM-DD format."
                }), 400

            # Reject dates that do not exactly match YYYY-MM-DD.
            if len(date_value) != 10 or date_value[4] != "-" or date_value[7] != "-":
                return jsonify({
                    "success": False,
                    "error": "Dates must be valid dates in YYYY-MM-DD format."
                }), 400

    # The start date must not be later than the end date.
    if date_from and date_to and date_from > date_to:
        return jsonify({
            "success": False,
            "error": "date_from cannot be later than date_to."
        }), 400
    
    # Build filters using SQL parameters, not string concatenation.
    conditions = [
        "(d.owner_id = ? OR p.user_id = ?)"
    ]
    parameters = [user["id"], user["id"]]

    if name:
        conditions.append("d.filename LIKE ?")
        parameters.append(f"%{name}%")

    if category:
        conditions.append("d.category = ?")
        parameters.append(category)

    if owner:
        conditions.append("u.username LIKE ?")
        parameters.append(f"%{owner}%")

    if date_from:
        conditions.append("date(d.uploaded_at) >= date(?)")
        parameters.append(date_from)

    if date_to:
        conditions.append("date(d.uploaded_at) <= date(?)")
        parameters.append(date_to)

    query = f"""
        SELECT DISTINCT
            d.id,
            d.owner_id,
            d.filename,
            d.category,
            d.uploaded_at,
            u.username AS owner_username,
            CASE
                WHEN d.owner_id = ? THEN 'owner'
                ELSE p.permission
            END AS access_level
        FROM documents AS d
        JOIN users AS u
            ON u.id = d.owner_id
        LEFT JOIN document_permissions AS p
            ON p.document_id = d.id
            AND p.user_id = ?
        WHERE {" AND ".join(conditions)}
        ORDER BY d.uploaded_at DESC
    """

    # These two parameters are used by the CASE and JOIN.
    parameters = [user["id"], user["id"]] + parameters

    connection = get_db_connection()

    try:
        rows = connection.execute(
            query,
            parameters,
        ).fetchall()

        return jsonify({
            "success": True,
            "count": len(rows),
            "documents": [dict(row) for row in rows],
        }), 200

    finally:
        connection.close()


# --------------------------------------------------
# EDIT TEXT DOCUMENT
# Only the owner or a user with edit permission can edit.
# --------------------------------------------------

@app.route(
    "/api/documents/<int:document_id>/edit",
    methods=["PUT"],
)
@login_required
def edit_text_document(document_id):
    user = current_user()

    if not user:
        return jsonify({
            "success": False,
            "error": "Authentication required.",
        }), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "A valid JSON request body is required.",
        }), 400

    content = data.get("content")
    if not isinstance(content, str):
        return jsonify({
            "success": False,
            "error": "Document content must be text.",
        }), 400

    content_bytes = content.encode("utf-8")
    if len(content_bytes) > 1024 * 1024:
        return jsonify({
            "success": False,
            "error": "Edited text cannot exceed 1 MB.",
        }), 413

    document, permission = get_document_access(document_id, user)
    if not document:
        log_denied_attempt(
            actor_id=user["id"],
            action="document_edit_denied",
            document_id=document_id,
            details={
                "method": request.method,
                "path": request.path,
                "reason": "document_access_denied",
            },
        )
        return jsonify({
            "success": False,
            "error": "Document not found.",
        }), 404

    if permission not in ("owner", "edit"):
        log_denied_attempt(
            actor_id=user["id"],
            action="document_edit_denied",
            document_id=document_id,
            details={
                "method": request.method,
                "path": request.path,
                "reason": "edit_permission_required",
            },
        )
        return jsonify({
            "success": False,
            "error": "Edit permission is required.",
        }), 403

    if Path(document["filename"]).suffix.lower() != ".txt":
        return jsonify({
            "success": False,
            "error": "Only .txt documents can be edited in the browser.",
        }), 400

    upload_folder = Path(get_upload_folder()).resolve()
    file_path = upload_folder / document["stored_filename"]
    temporary_path = upload_folder / (document["stored_filename"] + ".tmp")
    backup_path = upload_folder / (document["stored_filename"] + ".bak")

    connection = None
    original_bytes = None
    file_replaced = False

    try:
        # Confirm the stored path cannot escape the uploads directory.
        if file_path.resolve().parent != upload_folder:
            return jsonify({
                "success": False,
                "error": "Invalid stored document path.",
            }), 400

        if not file_path.is_file():
            return jsonify({
                "success": False,
                "error": "Stored document is unavailable.",
            }), 404

        # Hold a write lock so a permission revocation cannot race this edit.
        connection = get_db_connection()
        connection.execute("BEGIN IMMEDIATE")

        # Re-check permission inside the transaction using the same connection.
        fresh_document = connection.execute(
            "SELECT id, owner_id, filename, stored_filename FROM documents WHERE id = ?",
            (document_id,),
        ).fetchone()

        if not fresh_document:
            connection.rollback()
            log_denied_attempt(
                actor_id=user["id"],
                action="document_edit_denied",
                document_id=document_id,
                details={
                    "method": request.method,
                    "path": request.path,
                    "reason": "document_missing_during_edit",
                },
            )
            return jsonify({
                "success": False,
                "error": "Document not found.",
            }), 404

        if fresh_document["owner_id"] == user["id"]:
            fresh_permission = "owner"
        else:
            permission_row = connection.execute(
                "SELECT permission FROM document_permissions WHERE document_id = ? AND user_id = ?",
                (document_id, user["id"]),
            ).fetchone()
            fresh_permission = permission_row["permission"] if permission_row else None

        if fresh_permission not in ("owner", "edit"):
            connection.rollback()
            log_denied_attempt(
                actor_id=user["id"],
                action="document_edit_denied",
                document_id=document_id,
                details={
                    "method": request.method,
                    "path": request.path,
                    "reason": "permission_revoked_or_changed",
                },
            )
            return jsonify({
                "success": False,
                "error": "Edit permission is required.",
            }), 403

        # Preserve the original bytes so a failed audit/commit can restore them.
        original_bytes = file_path.read_bytes()
        temporary_path.write_bytes(content_bytes)
        backup_path.write_bytes(original_bytes)

        write_audit_log(
            connection,
            actor_id=user["id"],
            action="document_edited",
            outcome="success",
            document_id=document_id,
            details={
                "filename": fresh_document["filename"],
                "bytes_written": len(content_bytes),
            },
        )

        # Replace while the DB write transaction is held. If commit fails,
        # the exception handler restores the saved original content.
        temporary_path.replace(file_path)
        file_replaced = True
        connection.commit()

        try:
            backup_path.unlink(missing_ok=True)
        except OSError:
            logger.exception("Could not remove edit backup for document_id=%s", document_id)

    except Exception:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                logger.exception("Could not roll back document edit transaction")

        if file_replaced and original_bytes is not None:
            try:
                restore_path = upload_folder / (document["stored_filename"] + ".restore.tmp")
                restore_path.write_bytes(original_bytes)
                restore_path.replace(file_path)
            except OSError:
                logger.exception(
                    "CRITICAL: could not restore original document after failed edit; document_id=%s",
                    document_id,
                )

        for cleanup_path in (temporary_path, backup_path):
            try:
                cleanup_path.unlink(missing_ok=True)
            except OSError:
                logger.exception("Could not clean up temporary edit file: %s", cleanup_path)

        logger.exception(
            "Text document edit failed for document_id=%s",
            document_id,
        )
        return jsonify({
            "success": False,
            "error": "The document could not be edited.",
        }), 500

    finally:
        if connection is not None:
            connection.close()

    return jsonify({
        "success": True,
        "message": "Document updated successfully.",
    }), 200


# --------------------------------------------------
# DOWNLOAD DOCUMENT
# --------------------------------------------------

@app.route(
    "/api/documents/<int:document_id>/download",
    methods=["GET"],
)
@login_required
def download_document(document_id):
    user = current_user()

    if not user:
        return jsonify({
            "success": False,
            "error": "Authentication required.",
        }), 401

    document, permission = get_document_access(document_id, user)

    if not document:
        log_denied_attempt(
            actor_id=user["id"],
            action="document_download_denied",
            document_id=document_id,
            details={
                "method": request.method,
                "path": request.path,
                "reason": "document_access_denied",
            },
        )

        # Do not reveal whether another user's document exists.
        return jsonify({
            "success": False,
            "error": "Document not found.",
        }), 404

    upload_folder = Path(get_upload_folder())
    file_path = upload_folder / document["stored_filename"]

    if not file_path.is_file():
        return jsonify({
            "success": False,
            "error": "Stored document is unavailable.",
        }), 404

    # Record the download before sending the file.
    connection = get_db_connection()

    try:
        write_audit_log(
            connection,
            actor_id=user["id"],
            action="document_downloaded",
            outcome="success",
            document_id=document_id,
            details={
                "filename": document["filename"],
            },
        )

        connection.commit()

    except Exception:
        connection.rollback()

        logger.exception(
            "Could not record document download audit event"
        )

        return jsonify({
            "success": False,
            "error": "The download could not be recorded.",
        }), 500

    finally:
        connection.close()

    return send_from_directory(
        str(upload_folder),
        document["stored_filename"],
        as_attachment=True,
        download_name=document["filename"],
    )


# --------------------------------------------------
# DELETE DOCUMENT
# Only the document owner can delete it.
# --------------------------------------------------

@app.route(
    "/api/documents/<int:document_id>",
    methods=["DELETE"],
)
@login_required
def delete_document(document_id):
    user = current_user()

    if not user:
        return jsonify({
            "success": False,
            "error": "Authentication required.",
        }), 401

    connection = get_db_connection()

    try:
        document = connection.execute(
            """
            SELECT
                id,
                owner_id,
                filename,
                stored_filename
            FROM documents
            WHERE id = ?
            """,
            (document_id,),
        ).fetchone()

        # Only the owner can delete a document.
        if not document or document["owner_id"] != user["id"]:
            log_denied_attempt(
                actor_id=user["id"],
                action="document_delete_denied",
                document_id=document_id,
                details={
                    "method": request.method,
                    "path": request.path,
                    "reason": "document_access_denied",
                },
            )

            return jsonify({
                "success": False,
                "error": "Document not found.",
            }), 404

        # Record the deletion before removing the database row.
        write_audit_log(
            connection,
            actor_id=user["id"],
            action="document_deleted",
            outcome="success",
            document_id=document_id,
            details={
                "filename": document["filename"],
            },
        )

        connection.execute(
            "DELETE FROM documents WHERE id = ?",
            (document_id,),
        )

        connection.commit()

    except Exception:
        connection.rollback()

        logger.exception("Document deletion failed")

        return jsonify({
            "success": False,
            "error": "The document could not be deleted.",
        }), 500

    finally:
        connection.close()

    # Remove the stored file after the database transaction.
    stored_path = (
        Path(get_upload_folder())
        / document["stored_filename"]
    )

    try:
        if stored_path.is_file():
            stored_path.unlink()

    except OSError:
        logger.exception(
            "Deleted document file could not be removed"
        )

        return jsonify({
            "success": False,
            "error": (
                "The document record was deleted, but stored-file "
                "cleanup failed. Administrator attention is required."
            ),
        }), 500

    return jsonify({
        "success": True,
        "message": "Document deleted successfully.",
    }), 200



# --------------------------------------------------
# ADMIN AUDIT API
# --------------------------------------------------


def require_admin():
    """Return the current user only when they are an administrator."""
    user = current_user()

    if not user:
        log_denied_attempt(
            actor_id=None,
            action="admin_audit_access_denied",
            details={
                "method": request.method,
                "path": request.path,
                "reason": "authentication_required",
            },
        )

        return None, (
            jsonify({
                "success": False,
                "error": "Authentication required.",
            }),
            401,
        )

    if user["role"] != "admin":
        log_denied_attempt(
            actor_id=user["id"],
            action="admin_audit_access_denied",
            details={
                "method": request.method,
                "path": request.path,
                "reason": "administrator_role_required",
            },
        )

        return None, (
            jsonify({
                "success": False,
                "error": "Administrator access required.",
            }),
            403,
        )

    return user, None


@app.route("/api/admin/audit-logs", methods=["GET"])
def admin_audit_logs():
    """Return paginated audit entries to administrators only."""
    user, error_response = require_admin()

    if error_response:
        return error_response

    try:
        page = max(1, int(request.args.get("page", "1")))
        per_page = int(request.args.get("per_page", "25"))
    except (TypeError, ValueError):
        return jsonify({
            "success": False,
            "error": "Page and per_page must be integers.",
        }), 400

    per_page = min(max(per_page, 1), 100)
    offset = (page - 1) * per_page

    connection = get_db_connection()

    try:
        total = connection.execute(
            "SELECT COUNT(*) FROM audit_logs"
        ).fetchone()[0]

        rows = connection.execute(
            """
            SELECT
                id,
                actor_id,
                action,
                document_id,
                target_user_id,
                outcome,
                details,
                created_at,
                previous_hash,
                entry_hash
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (per_page, offset),
        ).fetchall()

        return jsonify({
            "success": True,
            "page": page,
            "per_page": per_page,
            "total": total,
            "audit_logs": [dict(row) for row in rows],
        }), 200

    finally:
        connection.close()


@app.route("/api/admin/audit-logs/verify", methods=["GET"])
def admin_verify_audit_chain():
    """Verify the audit hash chain; administrators only."""
    user, error_response = require_admin()

    if error_response:
        return error_response

    connection = get_db_connection()

    try:
        result = verify_audit_chain(connection)
        status_code = 200 if result["valid"] else 409

        return jsonify({
            "success": result["valid"],
            "verification": result,
        }), status_code

    finally:
        connection.close()

# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=False)
