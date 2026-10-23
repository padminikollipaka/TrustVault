
/* =========================================================
   TRUSTVAULT — COMPLETE FRONTEND
   Connects navigation, authentication, documents, uploads,
   search, filters, toast notifications and session handling.
   ========================================================= */

const API = "";

let authMode = "login";
let allDocuments = [];
let toastTimer = null;

// -------------------- ELEMENTS --------------------

const authSection = document.getElementById("auth-section");
const dashboard = document.getElementById("dashboard");
const authForm = document.getElementById("auth-form");
const authTitle = document.getElementById("auth-title");
const authSubtitle = document.getElementById("auth-subtitle");
const authSubmit = document.getElementById("auth-submit");
const authMessage = document.getElementById("auth-message");

const usernameGroup = document.getElementById("username-group");
const usernameInput = document.getElementById("username");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");

const uploadForm = document.getElementById("upload-form");
const documentFile = document.getElementById("document-file");
const fileLabel = document.getElementById("file-label");
const uploadMessage = document.getElementById("upload-message");

const documentsList = document.getElementById("documents-list");
const overviewDocuments = document.getElementById("overview-documents");

const searchInput = document.getElementById("document-search");
const filterSelect = document.getElementById("document-filter");
const toast = document.getElementById("toast");

const allowedExtensions = [
    "pdf", "txt", "doc", "docx", "png", "jpg", "jpeg"
];

const MAX_FILE_SIZE = 10 * 1024 * 1024;

// -------------------- MESSAGES --------------------

function showMessage(element, message, type = "") {
    if (!element) return;

    element.textContent = message;
    element.className = "message";

    if (type) {
        element.classList.add(type);
    }
}

function showToast(message, type = "success") {
    if (!toast) return;

    clearTimeout(toastTimer);

    toast.textContent = message;
    toast.classList.remove("hidden", "success", "error");
    toast.classList.add(type);

    toastTimer = setTimeout(() => {
        toast.classList.add("hidden");
    }, 3200);
}

// -------------------- PAGE NAVIGATION --------------------

function showView(viewName) {
    const validViews = [
        "overview",
        "documents",
        "upload",
        "security"
    ];

    if (!validViews.includes(viewName)) return;

    // Display only the selected page.
    document.querySelectorAll(".app-view").forEach((view) => {
        const isActive = view.dataset.page === viewName;

        view.classList.toggle("active", isActive);
        view.setAttribute("aria-hidden", String(!isActive));
    });

    // Highlight the selected sidebar button.
    document.querySelectorAll(".nav-item").forEach((button) => {
        const isActive = button.dataset.view === viewName;

        button.classList.toggle("active", isActive);

        if (isActive) {
            button.setAttribute("aria-current", "page");
        } else {
            button.removeAttribute("aria-current");
        }
    });

    // CSS uses this value to change the page's accent color.
    document.body.dataset.page = viewName;

    if (viewName === "documents") {
        renderDocuments();
    }

    if (viewName === "overview") {
        renderOverviewDocuments();
    }

    // Keep the new page visible, especially on mobile.
    window.scrollTo({
        top: 0,
        behavior: "smooth"
    });
}

// Sidebar navigation.
document.querySelectorAll(".nav-item").forEach((button) => {
    button.addEventListener("click", () => {
        showView(button.dataset.view);
    });
});

// Buttons and links that open another page.
document.querySelectorAll("[data-go]").forEach((button) => {
    button.addEventListener("click", () => {
        showView(button.dataset.go);
    });
});

// -------------------- LOGIN / REGISTRATION --------------------

function setAuthMode(mode) {
    authMode = mode;

    const registering = mode === "register";

    document.getElementById("login-tab")
        .classList.toggle("active", !registering);

    document.getElementById("register-tab")
        .classList.toggle("active", registering);

    usernameGroup.classList.toggle("hidden", !registering);
    usernameInput.required = registering;

    authTitle.textContent = registering
        ? "Create your account"
        : "Welcome back";

    authSubtitle.textContent = registering
        ? "Create an account to start your private vault."
        : "Log in to access your documents.";

    authSubmit.textContent = registering
        ? "Create account"
        : "Log in securely";

    passwordInput.autocomplete = registering
        ? "new-password"
        : "current-password";

    showMessage(authMessage, "");
}

document.getElementById("login-tab").addEventListener("click", () => {
    setAuthMode("login");
});

document.getElementById("register-tab").addEventListener("click", () => {
    setAuthMode("register");
});

authForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const email = emailInput.value.trim();
    const password = passwordInput.value;

    const payload = { email, password };

    if (authMode === "register") {
        payload.username = usernameInput.value.trim();

        if (!payload.username) {
            showMessage(authMessage, "Please enter a username.", "error");
            usernameInput.focus();
            return;
        }

        if (password.length < 8) {
            showMessage(
                authMessage,
                "Your password must contain at least 8 characters.",
                "error"
            );
            passwordInput.focus();
            return;
        }
    }

    authSubmit.disabled = true;

    showMessage(
        authMessage,
        authMode === "register"
            ? "Creating your account..."
            : "Signing in..."
    );

    try {
        const endpoint = authMode === "register"
            ? "/api/register"
            : "/api/login";

        const response = await fetch(`${API}${endpoint}`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });

        const data = await readJsonResponse(response);

        if (!response.ok) {
            throw new Error(
                data.message || data.error ||
                (authMode === "register"
                    ? "Registration failed."
                    : "Login failed.")
            );
        }

        if (authMode === "register") {
            setAuthMode("login");

            emailInput.value = email;
            passwordInput.value = "";

            showMessage(
                authMessage,
                "Account created successfully. Please log in.",
                "success"
            );

            showToast("Your account was created successfully.");
        } else {
            await showDashboard(data.user?.username || "User");
            showToast("Welcome to your private workspace.");
        }
    } catch (error) {
        showMessage(
            authMessage,
            error.message || "Unable to connect to TrustVault.",
            "error"
        );
    } finally {
        authSubmit.disabled = false;
    }
});

// Safely handle responses that are not valid JSON.
async function readJsonResponse(response) {
    try {
        return await response.json();
    } catch {
        return {};
    }
}

// -------------------- DASHBOARD --------------------

async function showDashboard(username) {
    authSection.classList.add("hidden");
    dashboard.classList.remove("hidden");

    document.getElementById("welcome-message").textContent =
        `Welcome, ${username}. Your documents are ready.`;

    showMessage(authMessage, "");

    showView("overview");
    await loadDocuments();
}

function showLogin() {
    dashboard.classList.add("hidden");
    authSection.classList.remove("hidden");

    allDocuments = [];

    if (documentsList) {
        documentsList.replaceChildren();
    }

    if (overviewDocuments) {
        overviewDocuments.replaceChildren();
    }

    authForm.reset();
    uploadForm.reset();

    fileLabel.textContent = "Choose a file from your device";

    showMessage(uploadMessage, "");
    showMessage(authMessage, "");

    setAuthMode("login");

    window.scrollTo({
        top: 0,
        behavior: "smooth"
    });
}

// -------------------- DOCUMENT LOADING --------------------

async function loadDocuments() {
    if (documentsList) {
        documentsList.textContent = "Loading your documents...";
    }

    if (overviewDocuments) {
        overviewDocuments.textContent = "Loading recent documents...";
    }

    try {
        const response = await fetch(`${API}/api/documents`, {
            method: "GET",
            credentials: "same-origin"
        });

        const data = await readJsonResponse(response);

        if (response.status === 401) {
            showLogin();
            showToast("Please log in to continue.", "error");
            return;
        }

        if (!response.ok) {
            throw new Error(
                data.error || "Could not load your documents."
            );
        }

        allDocuments = Array.isArray(data.documents)
            ? data.documents
            : [];

        renderDocuments();
        renderOverviewDocuments();
    } catch (error) {
        const message =
            error.message || "Unable to load your documents.";

        if (documentsList) {
            documentsList.textContent = message;
        }

        if (overviewDocuments) {
            overviewDocuments.textContent = message;
        }
    }
}

// -------------------- FILE TYPE HELPERS --------------------

function getExtension(filename) {
    const parts = String(filename || "").split(".");
    return parts.length > 1
        ? parts.pop().toLowerCase()
        : "";
}

function getFileCategory(filename) {
    const extension = getExtension(filename);

    if (extension === "pdf") {
        return "pdf";
    }

    if (["png", "jpg", "jpeg"].includes(extension)) {
        return "image";
    }

    if (["doc", "docx"].includes(extension)) {
        return "document";
    }

    if (extension === "txt") {
        return "text";
    }

    return "other";
}

function getFileSymbol(filename) {
    const category = getFileCategory(filename);

    const symbols = {
        pdf: "▤",
        image: "▧",
        document: "▤",
        text: "≡",
        other: "◇"
    };

    return symbols[category] || "◇";
}

function formatUploadDate(value) {
    if (!value) return "Upload date unavailable";

    // Preserve the backend's date format if it cannot be parsed.
    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return `Uploaded: ${value}`;
    }

    return `Uploaded: ${date.toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric"
    })}`;
}

// -------------------- DOCUMENT LIBRARY SEARCH --------------------

function getFilteredDocuments() {
    const searchTerm = searchInput
        ? searchInput.value.trim().toLowerCase()
        : "";

    const selectedType = filterSelect
        ? filterSelect.value
        : "all";

    return allDocuments.filter((doc) => {
        const filename = String(doc.filename || "").toLowerCase();

        const matchesSearch = filename.includes(searchTerm);

        const matchesType =
            selectedType === "all" ||
            getFileCategory(doc.filename) === selectedType;

        return matchesSearch && matchesType;
    });
}

function renderDocuments() {
    if (!documentsList) return;

    documentsList.replaceChildren();

    const filteredDocuments = getFilteredDocuments();

    if (allDocuments.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty-state";

        const title = document.createElement("strong");
        title.textContent = "Your vault is ready for its first file.";

        const description = document.createElement("p");
        description.textContent =
            "Upload a document to begin building your collection.";

        const button = document.createElement("button");
        button.type = "button";
        button.className = "button primary";
        button.textContent = "Upload your first file";
        button.addEventListener("click", () => showView("upload"));

        empty.append(title, description, button);
        documentsList.appendChild(empty);
        return;
    }

    if (filteredDocuments.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty-state";
        empty.textContent =
            "No files match your search or selected file type.";

        documentsList.appendChild(empty);
        return;
    }

    filteredDocuments.forEach((doc) => {
        documentsList.appendChild(createDocumentRow(doc, true));
    });
}

// -------------------- RECENT DOCUMENTS --------------------
// The Overview shows recent files without repeating the
// library's download and delete controls.

function renderOverviewDocuments() {
    if (!overviewDocuments) return;

    overviewDocuments.replaceChildren();

    if (allDocuments.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty-state";
        empty.textContent =
            "No documents yet. Your recent files will appear here after your first upload.";

        overviewDocuments.appendChild(empty);
        return;
    }

    const recentDocuments = [...allDocuments]
        .sort((a, b) => {
            return String(b.uploaded_at || "")
                .localeCompare(String(a.uploaded_at || ""));
        })
        .slice(0, 3);

    recentDocuments.forEach((doc) => {
        const row = document.createElement("div");
        row.className = "document-row";

        const info = document.createElement("div");
        info.className = "document-info";

        const icon = document.createElement("span");
        icon.className = "document-file-icon";
        icon.setAttribute("aria-hidden", "true");
        icon.textContent = getFileSymbol(doc.filename);

        const details = document.createElement("div");

        const name = document.createElement("div");
        name.className = "document-name";
        name.textContent = doc.filename || "Untitled document";

        const date = document.createElement("div");
        date.className = "document-date";
        date.textContent = formatUploadDate(doc.uploaded_at);

        details.append(name, date);
        info.append(icon, details);
        row.appendChild(info);

        overviewDocuments.appendChild(row);
    });
}

// -------------------- CREATE A DOCUMENT ROW --------------------

function createDocumentRow(doc, includeActions) {
    const row = document.createElement("div");
    row.className = "document-row";

    const info = document.createElement("div");
    info.className = "document-info";

    const icon = document.createElement("span");
    icon.className = "document-file-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = getFileSymbol(doc.filename);

    const details = document.createElement("div");

    const name = document.createElement("div");
    name.className = "document-name";
    name.textContent = doc.filename || "Untitled document";

    const date = document.createElement("div");
    date.className = "document-date";
    date.textContent = formatUploadDate(doc.uploaded_at);

    details.append(name, date);
    info.append(icon, details);
    row.appendChild(info);

    if (includeActions) {
        const actions = document.createElement("div");
        actions.className = "document-actions";

        const downloadButton = document.createElement("button");
        downloadButton.type = "button";
        downloadButton.className = "button secondary";
        downloadButton.textContent = "↓ Download";

        downloadButton.addEventListener("click", () => {
            downloadDocument(doc.id, doc.filename);
        });

        const deleteButton = document.createElement("button");
        deleteButton.type = "button";
        deleteButton.className = "button danger";
        deleteButton.textContent = "Delete";

        deleteButton.addEventListener("click", () => {
            deleteDocument(doc.id, doc.filename, deleteButton);
        });

        actions.append(downloadButton, deleteButton);
        row.appendChild(actions);
    }

    return row;
}

// Search and filter update the library immediately.
if (searchInput) {
    searchInput.addEventListener("input", renderDocuments);
}

if (filterSelect) {
    filterSelect.addEventListener("change", renderDocuments);
}

document.getElementById("refresh-button")
    .addEventListener("click", async () => {
        const button = document.getElementById("refresh-button");

        button.disabled = true;
        button.textContent = "Refreshing...";

        await loadDocuments();

        button.disabled = false;
        button.textContent = "↻ Refresh";

        showToast("Your document list has been refreshed.");
    });

// -------------------- DOWNLOAD DOCUMENT --------------------

async function downloadDocument(documentId, filename) {
    try {
        const response = await fetch(
            `${API}/api/documents/${documentId}/download`,
            {
                method: "GET",
                credentials: "same-origin"
            }
        );

        if (response.status === 401) {
            showLogin();
            showToast("Please log in to continue.", "error");
            return;
        }

        if (!response.ok) {
            const data = await readJsonResponse(response);

            throw new Error(
                data.error || "Download failed. Please try again."
            );
        }

        const blob = await response.blob();
        const url = URL.createObjectURL(blob);

        const link = document.createElement("a");
        link.href = url;
        link.download = filename || getDownloadFilename(response) || "document";

        document.body.appendChild(link);
        link.click();
        link.remove();

        setTimeout(() => URL.revokeObjectURL(url), 1000);

        showToast("Your download has started.");
    } catch (error) {
        showToast(
            error.message || "Unable to download the document.",
            "error"
        );
    }
}

function getDownloadFilename(response) {
    const disposition =
        response.headers.get("Content-Disposition") || "";

    const match = disposition.match(/filename="?([^";]+)"?/i);

    return match ? match[1] : "";
}

// -------------------- DELETE DOCUMENT --------------------

async function deleteDocument(documentId, filename, deleteButton) {
    const confirmed = window.confirm(
        `Delete "${filename}"?\n\nThis action cannot be undone.`
    );

    if (!confirmed) return;

    deleteButton.disabled = true;
    deleteButton.textContent = "Deleting...";

    try {
        const response = await fetch(
            `${API}/api/documents/${documentId}`,
            {
                method: "DELETE",
                credentials: "same-origin"
            }
        );

        const data = await readJsonResponse(response);

        if (response.status === 401) {
            showLogin();
            showToast("Please log in to continue.", "error");
            return;
        }

        if (!response.ok) {
            throw new Error(
                data.error || "Could not delete this document."
            );
        }

        // Update the visible collection immediately.
        allDocuments = allDocuments.filter(
            (doc) => String(doc.id) !== String(documentId)
        );

        renderDocuments();
        renderOverviewDocuments();

        showMessage(
            uploadMessage,
            data.message || "Document deleted successfully.",
            "success"
        );

        showToast("Document deleted successfully.");
    } catch (error) {
        showToast(
            error.message || "Unable to delete the document.",
            "error"
        );

        deleteButton.disabled = false;
        deleteButton.textContent = "Delete";
    }
}

// -------------------- FILE SELECTION --------------------

documentFile.addEventListener("change", () => {
    const file = documentFile.files[0];

    fileLabel.textContent = file
        ? file.name
        : "Choose a file from your device";

    if (!file) {
        showMessage(uploadMessage, "");
        return;
    }

    const extension = getExtension(file.name);

    if (!allowedExtensions.includes(extension)) {
        showMessage(
            uploadMessage,
            "This file type is not supported.",
            "error"
        );
        documentFile.value = "";
        fileLabel.textContent = "Choose a file from your device";
        return;
    }

    if (file.size > MAX_FILE_SIZE) {
        showMessage(
            uploadMessage,
            "The maximum file size is 10 MB.",
            "error"
        );
        documentFile.value = "";
        fileLabel.textContent = "Choose a file from your device";
        return;
    }

    showMessage(uploadMessage, "");
});

// -------------------- UPLOAD DOCUMENT --------------------

uploadForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const file = documentFile.files[0];

    if (!file) {
        showMessage(
            uploadMessage,
            "Please choose a file first.",
            "error"
        );
        return;
    }

    if (!allowedExtensions.includes(getExtension(file.name))) {
        showMessage(
            uploadMessage,
            "This file type is not supported.",
            "error"
        );
        return;
    }

    if (file.size > MAX_FILE_SIZE) {
        showMessage(
            uploadMessage,
            "The maximum file size is 10 MB.",
            "error"
        );
        return;
    }

    const formData = new FormData();
    formData.append("file", file);

    const uploadButton = uploadForm.querySelector(
        "button[type='submit']"
    );

    uploadButton.disabled = true;
    uploadButton.textContent = "Uploading...";

    showMessage(uploadMessage, "Uploading your document...");

    try {
        const response = await fetch(`${API}/api/documents/upload`, {
            method: "POST",
            body: formData,
            credentials: "same-origin"
        });

        const data = await readJsonResponse(response);

        if (response.status === 401) {
            showLogin();
            showToast("Please log in to continue.", "error");
            return;
        }

        if (!response.ok) {
            throw new Error(
                data.error || data.message || "Upload failed."
            );
        }

        uploadForm.reset();
        fileLabel.textContent = "Choose a file from your device";

        showMessage(
            uploadMessage,
            data.message || "Document uploaded successfully!",
            "success"
        );

        // Refresh both the library and the overview.
        await loadDocuments();

        showToast("Your document was added to TrustVault.");

        // Stay on the upload page so the user sees confirmation.
    } catch (error) {
        showMessage(
            uploadMessage,
            error.message || "Unable to upload the document.",
            "error"
        );
    } finally {
        uploadButton.disabled = false;
        uploadButton.textContent = "Upload document securely";
    }
});

// -------------------- LOGOUT --------------------

document.getElementById("logout-button")
    .addEventListener("click", async () => {
        const button = document.getElementById("logout-button");

        button.disabled = true;
        button.textContent = "Logging out...";

        try {
            const response = await fetch(`${API}/api/logout`, {
                method: "POST",
                credentials: "same-origin"
            });

            if (!response.ok) {
                showToast(
                    "Logout could not be confirmed. Please try again.",
                    "error"
                );
                return;
            }

            showLogin();
            showToast("You have logged out.");
        } catch {
            showToast("Unable to contact the server.", "error");
        } finally {
            button.disabled = false;
            button.textContent = "↗ Log out";
        }
    });

// -------------------- CHECK EXISTING SESSION --------------------

async function checkExistingSession() {
    try {
        const response = await fetch(`${API}/api/me`, {
            method: "GET",
            credentials: "same-origin"
        });

        if (!response.ok) return;

        const data = await readJsonResponse(response);

        if (data.logged_in) {
            await showDashboard(data.username || "User");
        }
    } catch {
        showMessage(
            authMessage,
            "Cannot connect to the server. Please try again.",
            "error"
        );
    }
}

// -------------------- INITIALIZE --------------------

document.body.dataset.page = "overview";
checkExistingSession();
