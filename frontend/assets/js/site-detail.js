import {
    apiFetch,
    consumeTokenFromHash,
    escapeHtml,
    formatDate,
    renderTopNav,
    requireToken,
} from "/assets/js/api.js";

const title = document.querySelector("#site-title");
const description = document.querySelector("#site-description");
const meta = document.querySelector("#site-meta");
const schema = document.querySelector("#site-schema");
const usersList = document.querySelector("#users-list");

function currentWebsiteId() {
    const parts = window.location.pathname.split("/").filter(Boolean);
    return parts[1] || "";
}

function renderSchemaFields(userSchema = {}) {
    const entries = Object.entries(userSchema);
    if (!entries.length) {
        return `<div class="empty-state">No schema fields defined.</div>`;
    }

    return `
        <div class="schema-list">
            ${entries.map(([key, value]) => `
                <div class="schema-item">
                    <strong>${escapeHtml(key)}</strong>
                    <div class="muted">${escapeHtml(value.label || "No label")}</div>
                    <div class="inline-list">
                        <span class="pill">type: ${escapeHtml(value.type)}</span>
                        <span class="pill">required: ${escapeHtml(String(Boolean(value.required)))}</span>
                        ${value.system ? '<span class="pill">system</span>' : ""}
                    </div>
                </div>
            `).join("")}
        </div>
    `;
}

function renderUsers(users) {
    if (!users.length) {
        usersList.innerHTML = `<div class="empty-state">No users have been registered for this website yet.</div>`;
        return;
    }

    usersList.innerHTML = users.map((user) => {
        const identity = user.identity_data || {};
        return `
            <article class="user-card">
                <h3>${escapeHtml(identity.display_name || user.full_name || user.email)}</h3>
                <div class="data-grid">
                    <div class="data-item"><span class="label">Email</span>${escapeHtml(user.email)}</div>
                    <div class="data-item"><span class="label">Full Name</span>${escapeHtml(user.full_name || "Not set")}</div>
                    <div class="data-item"><span class="label">Display Name</span>${escapeHtml(identity.display_name || "Not set")}</div>
                    <div class="data-item"><span class="label">First Name</span>${escapeHtml(identity.first_name || "Not set")}</div>
                    <div class="data-item"><span class="label">Last Name</span>${escapeHtml(identity.last_name || "Not set")}</div>
                    <div class="data-item"><span class="label">Status</span>${user.is_active ? "Active" : "Inactive"}</div>
                    <div class="data-item"><span class="label">Joined</span>${escapeHtml(formatDate(user.created_at))}</div>
                </div>
            </article>
        `;
    }).join("");
}

async function loadWebsite() {
    const websiteId = currentWebsiteId();
    if (!websiteId) {
        throw new Error("Website id is missing from the URL");
    }

    const [website, users] = await Promise.all([
        apiFetch(`/websites/${websiteId}`),
        apiFetch(`/websites/${websiteId}/users`),
    ]);

    title.textContent = website.name;
    description.textContent = website.description || "Inspect the schema and registered users for this website.";

    meta.innerHTML = `
        <div class="stack">
            <div class="section-header">
                <h2>Metadata</h2>
                <a class="ghost-button" href="/sites">Back to websites</a>
            </div>
            <div class="data-grid">
                <div class="data-item"><span class="label">Slug</span><span class="mono">${escapeHtml(website.slug)}</span></div>
                <div class="data-item"><span class="label">Created</span>${escapeHtml(formatDate(website.created_at))}</div>
                <div class="data-item"><span class="label">User limit</span>${escapeHtml(String(website.max_users))}</div>
                <div class="data-item"><span class="label">Registered users</span>${escapeHtml(String(users.length))}</div>
            </div>
        </div>
    `;

    schema.innerHTML = `
        <div class="stack">
            <h2>User schema</h2>
            ${renderSchemaFields(website.user_schema)}
        </div>
    `;

    renderUsers(users);
}

async function init() {
    consumeTokenFromHash();
    renderTopNav("sites");
    requireToken();

    document.querySelector("#refresh-users")?.addEventListener("click", () => window.location.reload());

    try {
        await loadWebsite();
    } catch (error) {
        meta.innerHTML = `<div class="status error">${escapeHtml(error.message)}</div>`;
        schema.innerHTML = "";
        usersList.innerHTML = "";
    }
}

init();
