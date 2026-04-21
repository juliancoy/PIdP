import {
    apiFetch,
    attachStatus,
    consumeTokenFromHash,
    escapeHtml,
    getSessionBundle,
    renderIdentitySummary,
    renderTopNav,
    requireToken,
} from "/assets/js/api.js";

const summary = document.querySelector("#profile-summary");
const form = document.querySelector("#profile-form");

function field(label, name, value = "", type = "text") {
    return `
        <div class="field">
            <label for="${name}">${label}</label>
            ${type === "textarea"
                ? `<textarea id="${name}" name="${name}">${escapeHtml(value)}</textarea>`
                : `<input id="${name}" name="${name}" type="${type}" value="${escapeHtml(value)}">`}
        </div>
    `;
}

function renderForm(me, websites) {
    const identity = me.identity_data || {};
    summary.innerHTML = `
        <div class="stack">
            <div class="section-header">
                <h2>Current profile</h2>
                <a class="ghost-button" href="/sites">View websites</a>
            </div>
            ${renderIdentitySummary(me)}
            <div class="metric-grid">
                <div class="metric">
                    <div class="metric-label">Owned websites</div>
                    <div class="metric-value">${websites.length}</div>
                </div>
            </div>
        </div>
    `;

    form.innerHTML = `
        <div class="section-header">
            <h2>Edit profile</h2>
            <div id="profile-status"></div>
        </div>
        <div class="field-grid">
            ${field("Full Name", "full_name", me.full_name || "")}
            ${field("Display Name", "display_name", identity.display_name || "")}
            ${field("First Name", "first_name", identity.first_name || "")}
            ${field("Last Name", "last_name", identity.last_name || "")}
            ${field("City", "city", identity.city || "")}
            ${field("State", "state", identity.state || "")}
            ${field("Avatar URL", "avatar_url", identity.avatar_url || "", "url")}
            ${field("Organizations", "organizations", Array.isArray(identity.organizations) ? identity.organizations.join(", ") : "")}
        </div>
        ${field("Bio", "bio", identity.bio || "", "textarea")}
        <div class="button-row">
            <button class="primary-button" type="submit">Save profile</button>
        </div>
    `;

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const formData = new FormData(form);
        const status = document.querySelector("#profile-status");
        attachStatus(status, "Saving...");

        const organizations = String(formData.get("organizations") || "")
            .split(",")
            .map((item) => item.trim())
            .filter(Boolean);

        try {
            const updated = await apiFetch("/auth/me", {
                method: "PUT",
                json: {
                    full_name: String(formData.get("full_name") || ""),
                    display_name: String(formData.get("display_name") || ""),
                    first_name: String(formData.get("first_name") || ""),
                    last_name: String(formData.get("last_name") || ""),
                    city: String(formData.get("city") || ""),
                    state: String(formData.get("state") || ""),
                    avatar_url: String(formData.get("avatar_url") || ""),
                    bio: String(formData.get("bio") || ""),
                    organizations,
                },
            });
            summary.innerHTML = renderIdentitySummary(updated);
            attachStatus(status, "Profile saved.", "success");
            window.setTimeout(() => window.location.reload(), 500);
        } catch (error) {
            attachStatus(status, error.message, "error");
        }
    });
}

async function init() {
    consumeTokenFromHash();
    renderTopNav("profile");
    requireToken();

    try {
        const { me, websites } = await getSessionBundle();
        renderForm(me, websites);
    } catch (error) {
        summary.innerHTML = `<div class="status error">${escapeHtml(error.message)}</div>`;
    }
}

init();
