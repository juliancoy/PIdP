const TOKEN_STORAGE_KEY = "pidp_access_token";

export function getToken() {
    return window.localStorage.getItem(TOKEN_STORAGE_KEY);
}

export function setToken(token) {
    window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
}

export function clearToken() {
    window.localStorage.removeItem(TOKEN_STORAGE_KEY);
}

export function consumeTokenFromHash() {
    const fragment = window.location.hash.startsWith("#") ? window.location.hash.slice(1) : window.location.hash;
    if (!fragment) {
        return false;
    }
    const params = new URLSearchParams(fragment);
    const token = params.get("token") || params.get("access_token");
    if (!token) {
        return false;
    }
    setToken(token);
    const cleaned = `${window.location.pathname}${window.location.search}`;
    window.history.replaceState({}, document.title, cleaned);
    return true;
}

export function parseErrorMessage(error) {
    if (error instanceof Error) {
        return error.message;
    }
    return String(error || "Unknown error");
}

export async function apiFetch(path, options = {}) {
    const headers = new Headers(options.headers || {});
    const token = options.token ?? getToken();

    if (token && !headers.has("Authorization")) {
        headers.set("Authorization", `Bearer ${token}`);
    }

    if (options.json && !headers.has("Content-Type")) {
        headers.set("Content-Type", "application/json");
    }

    const response = await fetch(path, {
        method: options.method || "GET",
        headers,
        body: options.json ? JSON.stringify(options.json) : options.body,
        credentials: "same-origin",
    });

    if (response.status === 401 && token) {
        clearToken();
    }

    const contentType = response.headers.get("content-type") || "";
    const payload = contentType.includes("application/json")
        ? await response.json()
        : await response.text();

    if (!response.ok) {
        const detail = typeof payload === "object" && payload?.detail
            ? payload.detail
            : response.statusText || "Request failed";
        throw new Error(detail);
    }

    return payload;
}

export async function loginWithPassword(email, password) {
    const body = new URLSearchParams();
    body.set("username", email);
    body.set("password", password);

    const result = await apiFetch("/auth/token", {
        method: "POST",
        body,
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
        token: null,
    });

    setToken(result.access_token);
    return result;
}

export async function registerAccount(payload) {
    return apiFetch("/auth/register", {
        method: "POST",
        json: payload,
        token: null,
    });
}

export async function getSessionBundle() {
    const [me, websites, configuration] = await Promise.all([
        apiFetch("/auth/me"),
        apiFetch("/websites"),
        apiFetch("/configuration").catch(() => ({})),
    ]);
    return { me, websites, configuration };
}

export function requireToken() {
    const token = getToken();
    if (!token) {
        window.location.assign("/");
        throw new Error("Authentication required");
    }
    return token;
}

export function buildSocialLoginUrl(provider, nextPath = "/") {
    const nextUrl = new URL(nextPath, window.location.origin);
    return `/auth/${provider}/login?next=${encodeURIComponent(nextUrl.toString())}`;
}

export function renderTopNav(activePage) {
    const nav = document.querySelector("#topnav");
    if (!nav) {
        return;
    }

    const token = getToken();
    const links = token
        ? [
            { href: "/", label: "Dashboard", key: "home" },
            { href: "/profile", label: "Profile", key: "profile" },
            { href: "/sites", label: "Clients", key: "sites" },
        ]
        : [{ href: "/", label: "Home", key: "home" }];

    nav.innerHTML = links
        .map((link) => `<a class="nav-link ${link.key === activePage ? "active" : ""}" href="${link.href}">${link.label}</a>`)
        .join("");

    if (token) {
        const button = document.createElement("button");
        button.className = "nav-button";
        button.type = "button";
        button.textContent = "Sign out";
        button.addEventListener("click", () => {
            clearToken();
            window.location.assign("/");
        });
        nav.appendChild(button);
    }
}

export function formatDate(value) {
    if (!value) {
        return "Unknown";
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return value;
    }
    return new Intl.DateTimeFormat(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
    }).format(date);
}

export function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

export function renderIdentitySummary(user) {
    const identity = user.identity_data || {};
    const displayName = identity.display_name || user.full_name || user.email;
    const avatar = identity.avatar_url
        ? `<img class="avatar" src="${escapeHtml(identity.avatar_url)}" alt="${escapeHtml(displayName)} avatar">`
        : `<div class="avatar" aria-hidden="true"></div>`;

    return `
        <div class="identity-card">
            <div class="identity-top">
                ${avatar}
                <div>
                    <div class="identity-name">${escapeHtml(displayName)}</div>
                    <div class="muted">${escapeHtml(user.email)}</div>
                </div>
            </div>
            <div class="data-grid">
                <div class="data-item"><span class="label">Full Name</span>${escapeHtml(user.full_name || "Not set")}</div>
                <div class="data-item"><span class="label">Display Name</span>${escapeHtml(identity.display_name || "Not set")}</div>
                <div class="data-item"><span class="label">First Name</span>${escapeHtml(identity.first_name || "Not set")}</div>
                <div class="data-item"><span class="label">Last Name</span>${escapeHtml(identity.last_name || "Not set")}</div>
                <div class="data-item"><span class="label">Provider</span>${escapeHtml(user.provider || "Local account")}</div>
                <div class="data-item"><span class="label">Joined</span>${escapeHtml(formatDate(user.created_at))}</div>
            </div>
        </div>
    `;
}

export function attachStatus(container, message, kind = "") {
    if (!container) {
        return;
    }
    container.innerHTML = `<div class="status ${kind}">${escapeHtml(message)}</div>`;
}
