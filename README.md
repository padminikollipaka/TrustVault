# TrustVault - Secure Document Sharing Platform
TrustVault is a Flask-based web application for storing, managing, and sharing confidential documents with controlled access.

The project focuses on document-level permissions, role-based administration, secure file handling, and auditable security events.

## Features

- User registration and login with session-based authentication.
- Document upload, listing, search, download, text editing, and deletion.
- Document-level read and edit permissions.
- Permission granting and revocation.
- File extension and content validation.
- Maximum upload size of 10 MB.
- Audit logging for security-relevant activities.
- Administrator-only audit-log access and hash-chain verification.
- Automated authorization and security regression tests.

**Editing limitation:** The edit endpoint is intended for supported text documents, not arbitrary binary document editing.

## Technology Stack

- **Backend:** Python and Flask
- **Database:** SQLite
- **Authentication:** Flask sessions and password hashing
- **Frontend:** HTML, CSS, and JavaScript
- **File validation:** `python-magic-bin`
- **Testing:** pytest
- **Configuration:** Environment variables loaded from `.env`

## Project Structure


TrustVault/
|-- app.py
|-- auth.py
|-- config.py
|-- database.py
|-- documents.py
|-- models.py
|-- audit.py
|-- create_admin.py
|-- migrate_db.py
|-- requirements.txt
|-- API.md
|-- THREATS.md
|-- PROMPTS.md
|-- templates/
|-- static/
|-- tests/
|-- uploads/       (local uploaded files; do not commit)
`-- instance/      (local database; do not commit)

The `.env` file contains private configuration and must not be committed. The `.venv` directory contains the local Python environment and should also remain untracked.
## Requirements

- Python 3.10 or newer, compatible with the installed dependencies
- pip
- Git, if cloning the repository

## Local Setup on Windows PowerShell

### 1. Clone the repository

After publishing the repository, replace the placeholder with your actual GitHub URL:

```powershell
git clone YOUR_GITHUB_REPOSITORY_URL
cd TrustVault
```

If you already have the project locally, open its folder in VS Code and skip this step.

### 2. Create and activate a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Configure the secret key

Create a local `.env` file in the project root. Use `.env.example` as a template, then replace the placeholder with a private, randomly generated secret key.

Never commit `.env`, passwords, session cookies, or real secret values.

### 5. Initialize or migrate the database

With the virtual environment active, run:

```powershell
python migrate_db.py
```

The script calls `create_tables()` to create the required tables and apply the supported schema migrations. Existing user and document records are intended to be preserved.

### 6. Create an administrator

Run:

```powershell
python create_admin.py
```

Follow the prompts to enter an administrator username, email, and password. Password input is hidden in the terminal. Keep the credentials private.

Do not run this command repeatedly with the same username or email; duplicate accounts are rejected.

### 7. Start the application

```powershell
python app.py
```

Open the local address:

`http://127.0.0.1:5000`

This is a local development setup, not a production deployment.

## Run Automated Tests

With the virtual environment activated, run:

```powershell
python -m pytest -v
```

The latest verified result recorded during development is **44 passed**. Rerun the suite after code changes and update this number when the verified result changes.

## Documentation

- `API.md` - endpoint reference and API behavior
- `THREATS.md` - threat model, mitigations, and limitations
- `PROMPTS.md` - AI usage log and development notes

## Security Notes

- Enforce document authorization on the server for every protected operation.
- Check current permissions when a document is accessed; revoked access must not remain effective for future requests.
- Keep confidential uploads outside public static directories.
- Store secret configuration in environment variables.
- Restrict administrator audit functions to authorized administrators.
- Treat audit-chain verification as evidence of integrity, not proof against an attacker who can modify the database and recompute the chain.
- Do not claim malware scanning unless it is implemented and verified.
- Do not publish real secrets, local databases, or confidential uploads.

## Deployment Limitations

The application currently configures `SESSION_COOKIE_SECURE = False` for local HTTP development. A deployment behind HTTPS must enable secure cookies and use appropriate production secret management and server configuration.

Before public release, verify clean installation, production cookie settings, HTTPS, database and upload persistence, authorization coverage, backup and recovery, and the deployment environment.

The current test result does not prove that every possible security threat has been eliminated. Do not describe the application as production-ready until the required deployment and security checks have been completed.

## License

Choose and add an appropriate license before allowing others to reuse or distribute this project.
