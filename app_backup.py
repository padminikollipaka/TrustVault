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
from audit import write_audit_log


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
@login_required
def list_document_permissions(document_id):

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
            return jsonify({
                "success": False,
                "error": "Registered user not found.",
            }), 404

        if target["id"] == user["id"]:
            return jsonify({
                "success": False,
                "error": "You already own this document.",
            }), 400

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

        # Record the permission change in the audit log.
        # Both operations commit together.
        write_audit_log(
            connection,
            actor_id=user["id"],
            action="permission_granted",
            outcome="success",
            document_id=document_id,
            target_user_id=target["id"],
            details={
                "permission": permission,
            },
        )

        connection.commit()

        return jsonify({
            "success": True,
            "message": "Document access granted.",
            "permission": {
                "document_id": document_id,
                "user_id": target["id"],
                "email": target["email"],
                "permission": permission,
            },
        }), 200

    except Exception:
        connection.rollback()

        logger.exception(
            "Could not grant document permission"
        )

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
def revoke_document_permission(
    document_id,
    target_user_id,
):

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

            return jsonify({
                "success": False,
                "error": "Permission not found.",
            }), 404

        # Record the revocation in the audit log.
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

        logger.exception(
            "Could not revoke document permission"
        )

        return jsonify({
            "success": False,
            "error": "Could not revoke document access.",
        }), 500

    finally:
        connection.close()


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

    original_filename = secure_filename(
        uploaded_file.filename
    )

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

    category = request.form.get(
        "category",
        "General",
    )

    if not isinstance(category, str):
        category = "General"

    category = category.strip()[:80] or "General"

    upload_folder = Path(get_upload_folder())
    upload_folder.mkdir(
        parents=True,
        exist_ok=True,
    )

    stored_filename = create_stored_filename(
        original_filename
    )

    stored_path = upload_folder / stored_filename

    try:
        uploaded_file.save(stored_path)

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

            # Record the upload in the audit log.
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
            logger.exception(
                "Could not clean up failed upload"
            )

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
# Users see their own documents and documents shared
# explicitly with them.
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

    connection = get_db_connection()

    try:
        rows = connection.execute(
            """
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
            WHERE d.owner_id = ?
               OR p.user_id = ?
            ORDER BY d.uploaded_at DESC
            """,
            (
                user["id"],
                user["id"],
                user["id"],
                user["id"],
            ),
        ).fetchall()

        return jsonify({
            "success": True,
            "documents": [
                dict(row) for row in rows
            ],
        }), 200

    finally:
        connection.close()


# --------------------------------------------------
# DOWNLOAD DOCUMENT
# The server checks permission before returning a file.
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

    document, permission = get_document_access(
        document_id,
        user,
    )

    if not document:
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
            return jsonify({
                "success": False,
                "error": "Document not found.",
            }), 404

        # Write the audit entry before deleting the database row.
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
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=False)