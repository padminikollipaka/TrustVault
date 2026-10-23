# TrustVault — AI Usage Log

This document records AI assistance used during the development of TrustVault. Entries describe the development work and verification evidence available at the time of writing.

## Entry 1 — Project Structure and Authentication

**Date:** 2026-10-23

**Goal:** Build the foundation of a confidential document-sharing application.

**AI assistance:** Used AI guidance while developing the Flask application, authentication helpers, database setup, and user registration and login functionality.

**Issues and limitations:** Generated code must be reviewed to ensure authentication and authorization are enforced on the server.

**What I did:** Worked with the generated code in VS Code and ran the automated test suite.

**Verification:** The latest recorded test run reported 32 passed in 2.99 seconds.

**Related commit:** `91bf6a0` — Set up TrustVault document security and tests.

## Entry 2 — Upload Size Validation

**Date:** 2026-10-23

**Goal:** Limit upload size and test how the application handles oversized files.

**AI assistance:** Used AI guidance to implement upload-size handling and tests for file-size limits.

**Issues and limitations:** A size limit alone does not establish that uploaded files are safe.

**What I did:** Installed the required file-validation dependency, tested the implementation, and recorded the changes in Git.

**Verification:** The upload-size-limit work was committed.

**Related commit:** `923d36a` — Handle oversized uploads and test file size limits.

## Entry 3 — Administrator Audit Routes

**Date:** 2026-10-23

**Goal:** Provide protected administrator endpoints for viewing and verifying audit records.

**AI assistance:** Used AI guidance to restore the administrator audit routes.

**Issues and limitations:** Administrative routes must reject unauthenticated users and users without the administrator role.

**What I did:** Applied the route changes and committed them.

**Verification:** The routes are present in the recorded project history. Further endpoint-specific security testing remains part of the project.

**Related commit:** `848e1ca` — Restore administrator audit routes.

## Entry 4 — Testing Denied Audit Access

**Date:** 2026-10-23

**Goal:** Ensure unauthenticated access to administrator audit functions is denied and recorded.

**AI assistance:** Used AI guidance to add a regression test for unauthenticated administrator audit access.

**Issues and limitations:** Denying a request is not sufficient if the expected audit evidence is missing.

**What I did:** Added a regression test and committed the change.

**Verification:** The regression test is included in the recorded project work. The latest full test run reported 32 passed in 2.99 seconds.

**Related commit:** `1424b44` — Test audit logging for unauthenticated admin access.

## Entry 5 — Security Threat Documentation

**Date:** 2026-10-23

**Goal:** Document the security threats TrustVault must address.

**AI assistance:** Used AI guidance to draft a threat model covering unauthorized document access, permission abuse, malicious uploads, path manipulation, audit tampering, and secret exposure.

**Issues and limitations:** A documented mitigation is not proof that the threat has been eliminated.

**What I did:** Reviewed and saved the threat-model document as `THREATS.md`.

**Verification:** The file was saved in the project root. The individual threat scenarios still require appropriate testing.

**Related commit:** Add the Git commit hash after committing this documentation.

## Responsible AI Use

- AI-generated code and documentation are reviewed as part of development.
- Test results are used as evidence, not as a guarantee of complete security.
- Known limitations and unfinished work are documented rather than described as completed.
- Git history is used to track changes.
- Commit references should be checked against the actual repository history.

## Remaining Work

- Add entries for future AI-assisted changes.
- Record important errors and the corrections made.
- Add verified commit hashes for documentation changes.
- Update test evidence whenever the suite changes.
- Document any AI-generated code that was rejected or substantially rewritten, where applicable.