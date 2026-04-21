import {
    apiFetch,
    attachStatus,
    consumeTokenFromHash,
    escapeHtml,
    formatDate,
    renderTopNav,
    requireToken,
} from "/assets/js/api.js";

const list = document.querySelector("#sites-list");
const summary = document.querySelector("#sites-summary");
const createClientBtn = document.querySelector("#create-client-btn");
const createClientModal = document.querySelector("#create-client-modal");
const createClientForm = document.querySelector("#create-client-form");
const closeModalBtn = document.querySelector("#close-modal");
const cancelCreateBtn = document.querySelector("#cancel-create");

function renderSummary(clients, userCounts) {
    const totalUsers = Object.values(userCounts).reduce((sum, count) => sum + count, 0);
    summary.innerHTML = `
        <div class="stack">
            <h2>Portfolio summary</h2>
            <div class="metric-grid">
                <div class="metric">
                    <div class="metric-label">Clients</div>
                    <div class="metric-value">${clients.length}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Registered users</div>
                    <div class="metric-value">${totalUsers}</div>
                </div>
            </div>
        </div>
    `;
}

function openModal() {
    createClientModal?.showModal();
}

function closeModal() {
    createClientModal?.close();
    createClientForm?.reset();
    const status = document.querySelector("#create-status");
    if (status) {
        status.innerHTML = "";
    }
}

function setupModalHandlers() {
    createClientBtn?.addEventListener("click", openModal);
    closeModalBtn?.addEventListener("click", closeModal);
    cancelCreateBtn?.addEventListener("click", closeModal);

    // Close modal when clicking outside
    createClientModal?.addEventListener("click", (event) => {
        if (event.target === createClientModal) {
            closeModal();
        }
    });
}

function setupFormHandler() {
    createClientForm?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const formData = new FormData(createClientForm);
        const status = document.querySelector("#create-status");
        attachStatus(status, "Creating...");
        try {
            await apiFetch("/websites", {
                method: "POST",
                json: {
                    name: String(formData.get("name") || ""),
                    source_url: String(formData.get("source_url") || ""),
                    callback_url: String(formData.get("callback_url") || ""),
                    description: String(formData.get("description") || "") || null,
                },
            });
            attachStatus(status, "Client created.", "success");
            window.setTimeout(() => {
                closeModal();
                window.location.reload();
            }, 500);
        } catch (error) {
            attachStatus(status, error.message, "error");
        }
    });
}

async function loadClients() {
    const clients = await apiFetch("/websites");
    const usersByClient = {};
    await Promise.all(clients.map(async (client) => {
        const users = await apiFetch(`/websites/${client.id}/users`);
        usersByClient[client.id] = users.length;
    }));

    renderSummary(clients, usersByClient);

    if (!clients.length) {
        list.innerHTML = `<div class="empty-state">No clients registered yet.</div>`;
        return;
    }

    list.innerHTML = clients.map((client) => `
        <article class="site-card">
            <div class="section-header">
                <div>
                    <h3>${escapeHtml(client.name)}</h3>
                    <p class="muted">${escapeHtml(client.description || "No description provided.")}</p>
                </div>
                <a class="secondary-button" href="/sites/${encodeURIComponent(client.id)}">Open client</a>
            </div>
            <div class="data-grid">
                <div class="data-item"><span class="label">Slug</span><span class="mono">${escapeHtml(client.slug)}</span></div>
                <div class="data-item"><span class="label">Created</span>${escapeHtml(formatDate(client.created_at))}</div>
                <div class="data-item"><span class="label">User limit</span>${escapeHtml(String(client.max_users))}</div>
                <div class="data-item"><span class="label">Registered users</span>${escapeHtml(String(usersByClient[client.id] || 0))}</div>
            </div>
        </article>
    `).join("");
}

async function init() {
    consumeTokenFromHash();
    renderTopNav("sites");
    requireToken();
    setupModalHandlers();
    setupFormHandler();
    document.querySelector("#refresh-sites")?.addEventListener("click", () => window.location.reload());

    try {
        await loadClients();
    } catch (error) {
        list.innerHTML = `<div class="status error">${escapeHtml(error.message)}</div>`;
    }
}

init();