# TrustVault - Threat Model

## 1. Project Overview

TrustVault is a confidential document-sharing platform built with Python, Flask, and SQLite. It supports user authentication, document storage, document-level permissions, and audit logging.

The main security goal is to prevent unauthorized users from accessing confidential documents and to maintain evidence of important security-related actions.

## 2. Assets to Protect

- Confidential documents uploaded by users
- User accounts and password hashes
- Authentication sessions
- Document ownership and sharing permissions
- Audit logs and their integrity
- Application configuration and secret keys
- Database records and uploaded files

## 3. Threats and Mitigations

### Threat 1: Unauthorized Document Access

**Risk:** A user attempts to view or download another user's private document.

**Mitigation:** Require authentication and check document ownership or explicit document permissions on the server for every protected request.

**Verification needed:** Test access using two different user accounts.

### Threat 2: Unauthorized Permission Changes

**Risk:** A user attempts to grant, modify, or revoke permissions without authorization.

**Mitigation:** Restrict permission-management operations to authorized document owners or other explicitly permitted roles.

**Verification needed:** Test permission changes by owners, viewers, and unrelated users.

### Threat 3: Access After Permission Revocation

**Risk:** A previously authorized user continues accessing a document after their permission has been revoked.

**Mitigation:** Check current permissions when each protected document operation is requested.

**Verification needed:** Grant access, revoke it, and confirm that subsequent requests are denied.

### Threat 4: Malicious or Invalid File Uploads

**Risk:** An attacker uploads a file with a misleading extension, invalid content, or an excessive size.

**Mitigation:** Check allowed extensions, validate file content, reject empty files, and enforce the 10 MB upload limit.

**Verification needed:** Test invalid file content, unsupported extensions, oversized files, and malformed documents.

### Threat 5: File Path Manipulation

**Risk:** An attacker attempts to use a filename or document identifier to access files outside the intended storage directory.

**Mitigation:** Use server-generated stored filenames and resolve file paths within the configured upload directory.

**Verification needed:** Test path traversal attempts and confirm that no request can read or modify files outside the permitted directory.

### Threat 6: Password Compromise

**Risk:** Stored passwords are exposed if the database is compromised.

**Mitigation:** Store password hashes rather than plaintext passwords and enforce password requirements during registration.

**Verification needed:** Inspect password storage and test the registration and login validation rules.

### Threat 7: Audit Log Tampering

**Risk:** A user attempts to alter or delete audit records to hide activity.

**Mitigation:** Maintain audit records, use hash-chain integrity checks, and apply database protections against audit record updates and deletions.

**Verification needed:** Test unauthorized modifications, deletions, and audit-chain verification after tampering.

### Threat 8: Unauthenticated Administrative Access

**Risk:** An unauthenticated user or a regular user attempts to access administrator audit functions.

**Mitigation:** Check authentication and administrator privileges on protected administrative endpoints, and record denied attempts where possible.

**Verification needed:** Confirm that unauthenticated requests receive an appropriate denial and regular users cannot access administrator functions.

### Threat 9: Secret or Private File Exposure Through Git

**Risk:** Configuration secrets, the local database, or confidential uploads are committed to a public repository.

**Mitigation:** Use `.gitignore` to exclude `.env`, the local database directory, uploaded documents, and virtual-environment files. Keep `.env.example` limited to safe placeholders.

**Verification needed:** Inspect tracked files and Git history before publishing the repository. Ignoring a file does not remove it from previous commits.

### Threat 10: Database and File Inconsistency

**Risk:** A failed upload, edit, or deletion leaves the database and stored files inconsistent.

**Mitigation:** Use database transactions and cleanup or restoration logic where applicable.

**Verification needed:** Simulate failures during file operations and confirm that the database and file storage remain consistent.

## 4. Security Assumptions

- Users may attempt to access documents they do not own.
- Client-supplied document IDs, filenames, roles, and permissions cannot be trusted.
- All authorization decisions must be enforced on the server.
- Local development success does not prove production security.
- Audit logs are security evidence, but they do not replace access controls.

## 5. Known Limitations and Remaining Work

- Complete cross-user authorization testing.
- Verify immediate permission revocation.
- Review every protected endpoint for missing authorization checks.
- Test malformed uploads and file-path manipulation.
- Verify audit-chain behavior after attempted tampering.
- Review production cookie settings, secret management, HTTPS, and deployment configuration.
- Assess protection against excessive requests and resource-exhaustion attacks.
- Review backup, recovery, and database consistency procedures.

## 6. Security Testing Evidence

Automated test suite result recorded on 23 October 2026: **44 tests passed in 3.53 seconds**.

This result confirms that the tests present in the suite passed at that time. It does not establish that every threat listed in this document has been tested or eliminated.

Update this section as additional security tests are implemented and executed.
