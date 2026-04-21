import {
    apiFetch,
    attachStatus,
    buildSocialLoginUrl,
    consumeTokenFromHash,
    escapeHtml,
    formatDate,
    getSessionBundle,
    getToken,
    loginWithPassword,
    registerAccount,
    renderIdentitySummary,
    renderTopNav,
} from "/assets/js/api.js";

const sessionCard = document.querySelector("#session-card");
const authPanel = document.querySelector("#auth-panel");
const overviewPanel = document.querySelector("#overview-panel");

function renderLoggedOut(configuration = {}) {
    renderTopNav("home");

    sessionCard.innerHTML = `
        <div class="stack">
            <h2>Account access</h2>
            <p class="muted">Use email and password or start a social sign-in flow. Social login returns directly to this page.</p>
            <div class="button-row">
                ${configuration.google_client_id ? `<a class="primary-button" href="${buildSocialLoginUrl("google")}">Continue with Google</a>` : ""}
                ${configuration.github_client_id ? `<a class="secondary-button" href="${buildSocialLoginUrl("github")}">Continue with GitHub</a>` : ""}
            </div>
        </div>
    `;

    authPanel.innerHTML = `
        <div class="stack">
            <h2>Sign in</h2>
            <form id="login-form" class="stack">
                <div class="field">
                    <label for="login-email">Email</label>
                    <input id="login-email" name="email" type="email" autocomplete="email" required>
                </div>
                <div class="field">
                    <label for="login-password">Password</label>
                    <input id="login-password" name="password" type="password" autocomplete="current-password" required>
                </div>
                <div class="button-row">
                    <button class="primary-button" type="submit">Sign in</button>
                    <div id="login-status"></div>
                </div>
            </form>
        </div>
    `;

    overviewPanel.innerHTML = `
        <div class="stack">
            <h2>Create account</h2>
            <form id="register-form" class="stack">
                <div class="field-grid">
                    <div class="field">
                        <label for="register-name">Full name</label>
                        <input id="register-name" name="full_name" type="text" autocomplete="name">
                    </div>
                    <div class="field">
                        <label for="register-email">Email</label>
                        <input id="register-email" name="email" type="email" autocomplete="email" required>
                    </div>
                </div>
                <div class="field">
                    <label for="register-password">Password</label>
                    <input id="register-password" name="password" type="password" autocomplete="new-password" required>
                </div>
                <div class="button-row">
                    <button class="secondary-button" type="submit">Create account</button>
                    <div id="register-status"></div>
                </div>
            </form>
        </div>
    `;

    document.querySelector("#login-form")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const form = new FormData(event.currentTarget);
        const status = document.querySelector("#login-status");
        attachStatus(status, "Signing in...");
        try {
            await loginWithPassword(form.get("email"), form.get("password"));
            window.location.reload();
        } catch (error) {
            attachStatus(status, error.message, "error");
        }
    });

    document.querySelector("#register-form")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const form = new FormData(event.currentTarget);
        const status = document.querySelector("#register-status");
        attachStatus(status, "Creating account...");
        try {
            await registerAccount({
                email: form.get("email"),
                password: form.get("password"),
                full_name: form.get("full_name") || null,
            });
            await loginWithPassword(form.get("email"), form.get("password"));
            window.location.reload();
        } catch (error) {
            attachStatus(status, error.message, "error");
        }
    });
}

function renderLoggedIn(me, websites) {
    renderTopNav("home");

    sessionCard.innerHTML = `
        <div class="stack">
            <h2>Signed in</h2>
            ${renderIdentitySummary(me)}
        </div>
    `;

    authPanel.innerHTML = `
        <div class="stack">
            <div class="section-header">
                <h2>Profile snapshot</h2>
                <a class="ghost-button" href="/profile">Edit profile</a>
            </div>
            <div class="metric-grid">
                <div class="metric">
                    <div class="metric-label">Owned websites</div>
                    <div class="metric-value">${websites.length}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Provider</div>
                    <div class="metric-value">${escapeHtml(me.provider || "Local")}</div>
                </div>
            </div>
            <div class="callout">
                <strong>Basic fields</strong><br>
                Display name, first name, last name, avatar URL, and other basic profile fields are available on your profile page.
            </div>
        </div>
    `;

    if (!websites.length) {
        overviewPanel.innerHTML = `
            <div class="stack">
                <h2>No websites yet</h2>
                <p class="empty-state">This account has not registered any websites. Create one from the websites page.</p>
                <a class="primary-button" href="/sites">Open websites</a>
            </div>
        `;
        return;
    }

    overviewPanel.innerHTML = `
        <div class="stack">
            <div class="section-header">
                <h2>Your websites</h2>
                <a class="ghost-button" href="/sites">View all</a>
            </div>
            ${websites.slice(0, 3).map((website) => `
                <article class="site-card">
                    <h3>${escapeHtml(website.name)}</h3>
                    <p class="muted">${escapeHtml(website.description || "No description provided.")}</p>
                    <div class="data-grid">
                        <div class="data-item"><span class="label">Slug</span><span class="mono">${escapeHtml(website.slug)}</span></div>
                        <div class="data-item"><span class="label">Max users</span>${escapeHtml(String(website.max_users))}</div>
                        <div class="data-item"><span class="label">Created</span>${escapeHtml(formatDate(website.created_at))}</div>
                    </div>
                    <div class="card-actions">
                        <a class="secondary-button" href="/sites/${encodeURIComponent(website.id)}">View users</a>
                    </div>
                </article>
            `).join("")}
        </div>
    `;
}

async function init() {
    consumeTokenFromHash();

    if (!getToken()) {
        const configuration = await apiFetch("/configuration", { token: null }).catch(() => ({}));
        renderLoggedOut(configuration);
        return;
    }

    try {
        const { me, websites } = await getSessionBundle();
        renderLoggedIn(me, websites);
    } catch (error) {
        renderLoggedOut({});
        attachStatus(authPanel, error.message, "error");
    }
}

init();
