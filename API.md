# TrustVault - API Documentation

## 1. Overview

TrustVault is a secure document-sharing application built with Flask and SQLite. It provides session-based authentication, document management, permission controls, and tamper-evident audit logging.

**Local base URL:** `http://127.0.0.1:5000`

**Authentication:** Session-based authentication using a session cookie.

**Content types:**
- JSON for registration, login, permission changes, and text editing.
- `multipart/form-data` for document uploads.
- File download responses for document downloads.

## 2. Authentication

### POST `/api/register`

Register a new user account.

**Authentication:** Not required.

**Request body:**

```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "StrongPass1!"
}
```

**Rules:**
- Username, email, and password are required.
- Passwords must contain at least 8 characters, including uppercase and lowercase letters, a number, and a special character.
- New public registrations receive the default owner role. Users cannot select their own role during registration.
- Duplicate usernames or email addresses are rejected.

**Success response — `201 Created`:**

```json
{
  "success": true,
  "message": "User registered successfully."
}
```

**Common errors:** `400 Bad Request` for invalid input; `409 Conflict` when the username or email already exists.

### POST `/api/login`

Authenticate a user and establish a session.

**Authentication:** Not required.

**Request body:**

```json
{
  "email": "alice@example.com",
  "password": "StrongPass1!"
}
```

**Success response — `200 OK`:**

```json
{
  "success": true,
  "message": "Login successful.",
  "user": {
    "id": 1,
    "username": "alice",
    "email": "alice@example.com",
    "role": "owner"
  }
}
```

The actual user ID and role depend on the database. A successful login starts a fresh session.

**Common errors:** `400 Bad Request` for missing or invalid input; `401 Unauthorized` for invalid credentials.

### GET `/api/me`

Return the current session status.

**Authentication:** Not required.

**Logged-in response — `200 OK`:**

```json
{
  "success": true,
  "logged_in": true,
  "user": {}
}
```

The `user` object contains the current user's information.

**Logged-out response — `200 OK`:**

```json
{
  "success": true,
  "logged_in": false
}
```

### POST `/api/logout`

Clear the current session.

**Authentication:** The route clears the session without requiring an active login.

**Success response — `200 OK`:**

```json
{
  "success": true,
  "message": "Logged out successfully."
}
```

## 3. Document permissions

### GET `/api/documents/<document_id>/permissions`

List permissions for a document.

**Authentication:** Required. Only the document owner can list its permissions.

**Success response — `200 OK`:**

```json
{
  "success": true,
  "permissions": [
    {
      "user_id": 2,
      "username": "bob",
      "email": "bob@example.com",
      "permission": "read",
      "created_at": "..."
    }
  ]
}
```

The example is illustrative; actual values and timestamps come from the database.

**Common errors:** `401 Unauthorized` when not logged in; `404 Not Found` when the document is unavailable to the requester or the requester is not its owner.

### POST `/api/documents/<document_id>/permissions`

Grant or update another registered user's access.

**Authentication:** Required. Only the document owner can manage permissions.

**Request body:**

```json
{
  "email": "bob@example.com",
  "permission": "read"
}
```

Allowed permission values:
- `read` — access to view/download the document.
- `edit` — access to edit supported text documents and download them.

Use `edit` instead of `read` to upgrade an existing permission. Use `read` to reduce an existing edit permission.

**Success response — `200 OK`:**

```json
{
  "success": true,
  "message": "Document access granted.",
  "permission": {
    "document_id": 1,
    "user_id": 2,
    "email": "bob@example.com",
    "permission": "read"
  }
}
```

Updating an existing permission returns the message `Document permission updated.`

**Common errors:** `400 Bad Request` for invalid permission input or attempting to grant permission to yourself; `401 Unauthorized` when not logged in; `404 Not Found` when the document or registered recipient cannot be found; `500 Internal Server Error` if the update fails.

### DELETE `/api/documents/<document_id>/permissions/<target_user_id>`

Revoke another user's permission.

**Authentication:** Required. Only the document owner can revoke access.

**Success response — `200 OK`:**

```json
{
  "success": true,
  "message": "Document access revoked."
}
```

**Common errors:** `401 Unauthorized`; `404 Not Found` if the document or permission is unavailable; `500 Internal Server Error` if revocation fails.

Revoked users should no longer be able to access the document through protected application routes. Authorization must be checked server-side on every request.

## 4. Upload documents

### POST `/api/documents/upload`

Upload a document.

**Authentication:** Required.

**Content type:** `multipart/form-data`

**Form fields:**

| Field | Required | Description |
|---|---|---|
| `file` | Yes | File to upload |
| `category` | No | Category; defaults to `General` and is limited to 80 characters |

The file must have an accepted extension and matching content. Empty files and invalid file formats are rejected. The maximum upload size is 10 MB.

**Success response — `201 Created`:**

```json
{
  "success": true,
  "message": "Document uploaded successfully.",
  "document": {
    "id": 1,
    "filename": "notes.txt",
    "category": "General"
  }
}
```

**Common errors:** `400 Bad Request` for missing files, invalid filenames, disallowed formats, empty files, or mismatched content; `401 Unauthorized`; `500 Internal Server Error` if the upload fails.

## 5. List and search documents

### GET `/api/documents`

List documents that the authenticated user owns or has permission to access.

**Authentication:** Required.

**Optional query parameters:**

| Parameter | Description |
|---|---|
| `name` | Partial match against the filename |
| `category` | Exact category match |
| `owner` | Partial match against the owner's username |
| `date_from` | Earliest upload date, inclusive |
| `date_to` | Latest upload date, inclusive |

Dates must use `YYYY-MM-DD` and represent valid calendar dates. `date_from` cannot be later than `date_to`.

**Example:**

`GET /api/documents?name=notes&category=General&date_from=2026-01-01&date_to=2026-12-31`

**Success response — `200 OK`:**

```json
{
  "success": true,
  "count": 1,
  "documents": [
    {
      "id": 1,
      "owner_id": 1,
      "filename": "notes.txt",
      "category": "General",
      "uploaded_at": "...",
      "owner_username": "alice",
      "access_level": "owner"
    }
  ]
}
```

The document list includes an `access_level` such as `owner`, `read`, or `edit`, as applicable.

**Common errors:** `400 Bad Request` for invalid dates; `401 Unauthorized` when not logged in.

## 6. Edit a text document

### PUT `/api/documents/<document_id>/edit`

Update the contents of a supported text document.

**Authentication:** Required. The owner or a user with `edit` permission may edit.

**Request body:**

```json
{
  "content": "Updated document text."
}
```

**Rules:**
- Only `.txt` documents can be edited through this endpoint.
- Content must be a string.
- Edited content cannot exceed 1 MB when encoded as UTF-8.
- Access is checked again during the database write transaction to help prevent permission revocation from racing with an edit.

**Success response — `200 OK`:**

```json
{
  "success": true,
  "message": "Document updated successfully."
}
```

**Common errors:** `400 Bad Request` for invalid JSON, non-text content, or unsupported file types; `401 Unauthorized`; `403 Forbidden` if edit permission is missing or revoked; `404 Not Found` if the document is unavailable; `413 Content Too Large` if the edited text exceeds 1 MB; `500 Internal Server Error` if the edit fails.

## 7. Download documents

### GET `/api/documents/<document_id>/download`

Download a document as an attachment.

**Authentication:** Required. The owner and users with an active document permission can download.

**Success response:** The stored file is returned as an attachment with its original filename.

**Common errors:** `401 Unauthorized`; `404 Not Found` when the requester lacks access or the stored file is unavailable; `500 Internal Server Error` if the download cannot be recorded in the audit log.

Successful download events are recorded in the audit log before the file is sent.

## 8. Delete documents

### DELETE `/api/documents/<document_id>`

Delete a document and its stored file.

**Authentication:** Required. Only the document owner can delete it.

**Success response — `200 OK`:**

```json
{
  "success": true,
  "message": "Document deleted successfully."
}
```

**Common errors:** `401 Unauthorized`; `404 Not Found` when the document is unavailable to the requester; `500 Internal Server Error` if deletion fails. A file-cleanup failure may occur after the database record has already been deleted and requires administrator attention.

A successful deletion is recorded in the audit log.

## 9. Administrator audit APIs

These endpoints require an authenticated user whose role is `admin`.

### GET `/api/admin/audit-logs`

Retrieve audit entries using pagination.

**Optional query parameters:**

| Parameter | Default | Rules |
|---|---:|---|
| `page` | `1` | Integer; values below 1 are normalized to 1 |
| `per_page` | `25` | Integer, limited to 1–100 |

**Example:**

`GET /api/admin/audit-logs?page=1&per_page=25`

**Success response — `200 OK`:**

```json
{
  "success": true,
  "page": 1,
  "per_page": 25,
  "total": 44,
  "audit_logs": []
}
```

The example total is illustrative. Each returned audit entry can include its ID, actor, action, document, target user, outcome, details, timestamp, previous hash, and entry hash.

**Common errors:** `400 Bad Request` if pagination parameters are not integers; `401 Unauthorized` if not logged in; `403 Forbidden` if the user is not an administrator.

### GET `/api/admin/audit-logs/verify`

Verify the audit-log hash chain.

**Authentication:** Required. Administrators only.

**Success response — `200 OK`:**

```json
{
  "success": true,
  "verification": {
    "valid": true
  }
}
```

The verification object contains the verification details produced by the application.

**Common errors:** `401 Unauthorized`; `403 Forbidden`; `409 Conflict` if verification detects an invalid chain.

## 10. Common HTTP status codes

| Status | Meaning |
|---|---|
| `200 OK` | Request completed successfully |
| `201 Created` | Account or document created successfully |
| `400 Bad Request` | Invalid request data |
| `401 Unauthorized` | Authentication is required or credentials are invalid |
| `403 Forbidden` | Authenticated user lacks the required permission |
| `404 Not Found` | Resource is unavailable or intentionally concealed |
| `409 Conflict` | Duplicate registration or failed audit-chain verification |
| `413 Content Too Large` | Edited text exceeds the allowed size |
| `500 Internal Server Error` | An unexpected server-side operation failed |

Not every endpoint returns every status code in this table.

## 11. Security notes

- Authentication and authorization are enforced on protected server routes.
- New public registrations cannot choose an administrator role.
- Document access is limited to owners and users with the appropriate active permissions.
- Uploads are checked for accepted extensions and matching file content.
- Document names are sanitized, and stored filenames are generated separately.
- SQL queries use parameters for user-provided values.
- Denied access and permission-management attempts are logged where implemented.
- Audit-log updates and deletions are protected by SQLite triggers.
- The audit chain can be checked through the administrator verification endpoint.
- Production deployment should use HTTPS, a securely generated secret key, secure session-cookie settings, and appropriate server configuration.

## 12. Local development and testing

Start the application using the project's documented setup instructions, then use:

`http://127.0.0.1:5000`

Run the automated tests from the project root with:

```powershell
python -m pytest -q
```

**Last recorded test result:** 44 tests passed in 3.53 seconds. Rerun the suite after changes to confirm the current result.

For setup instructions, threat analysis, and AI usage documentation, see `README.md`, `THREATS.md`, and `PROMPTS.md`.
