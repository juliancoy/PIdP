import type { WebsiteSchemaField } from "./types";
import { PROFILE_LINK_FIELDS, SYSTEM_SCHEMA_FIELDS, schemaWithSystemFields } from "./normalize";
import QRCode from "qrcode";

const INTERNAL_PROFILE_FIELDS = new Set([
  "sub",
  "id",
  "email_verified",
  "verified_email",
  "provider",
  "provider_account_id",
  "avatar_object_key",
  "avatar_source",
  "picture",
  "raw",
  "roles",
  "is_sysadmin",
]);

const CONTACT_FIELD_LABELS: Record<string, string> = {
  contact_email: "Email",
  public_email: "Email",
  phone_number: "Phone",
  mobile_number: "Mobile",
  work_phone: "Work phone",
  fax_number: "Fax",
  sms_number: "SMS",
  whatsapp_number: "WhatsApp",
  telegram_username: "Telegram",
  signal_username: "Signal",
};

const LINK_FIELD_LABELS: Record<string, string> = {
  website_url: "Website",
  github_url: "GitHub",
  linkedin_url: "LinkedIn",
  x_url: "X",
  twitter_url: "Twitter",
  instagram_url: "Instagram",
  facebook_url: "Facebook",
  youtube_url: "YouTube",
  tiktok_url: "TikTok",
  threads_url: "Threads",
  bluesky_url: "Bluesky",
  mastodon_url: "Mastodon",
  discord_url: "Discord",
  twitch_url: "Twitch",
  snapchat_url: "Snapchat",
  pinterest_url: "Pinterest",
  reddit_url: "Reddit",
  medium_url: "Medium",
  substack_url: "Substack",
  linktree_url: "Linktree",
};

interface LinkItem {
  label: string;
  href: string;
  text: string;
}

interface InfoItem {
  label: string;
  value: string;
}

export interface ProfilePageInput {
  id: string;
  email?: string | null;
  fullName?: string | null;
  identity: Record<string, unknown>;
  schema?: Record<string, WebsiteSchemaField>;
  titleSuffix?: string;
  profileUrl?: string;
  qrSvg?: string;
  qrDownloadUrl?: string;
}

export async function renderProfileQrSvg(profileUrl: string): Promise<string> {
  return QRCode.toString(profileUrl, {
    type: "svg",
    errorCorrectionLevel: "M",
    margin: 2,
    width: 224,
    color: {
      dark: "#18201f",
      light: "#ffffff",
    },
  });
}

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function normalizeUrl(value: string): string | null {
  const raw = value.trim();
  if (!raw) return null;
  if (/^mailto:/i.test(raw) || /^tel:/i.test(raw) || /^sms:/i.test(raw)) return raw;
  if (/^https?:\/\//i.test(raw)) return raw;
  if (/^[a-z0-9.-]+\.[a-z]{2,}([/?#].*)?$/i.test(raw)) return `https://${raw}`;
  return null;
}

function telHref(value: string, scheme = "tel"): string {
  const compact = value.replace(/[^\d+]/g, "");
  return compact ? `${scheme}:${compact}` : value;
}

function handleHref(field: string, value: string): string {
  if (field.endsWith("_email")) return value.startsWith("mailto:") ? value : `mailto:${value}`;
  if (["phone_number", "mobile_number", "work_phone", "fax_number", "whatsapp_number"].includes(field)) return telHref(value);
  if (field === "sms_number") return telHref(value, "sms");
  if (field === "telegram_username") return value.startsWith("http") ? value : `https://t.me/${value.replace(/^@/, "")}`;
  return normalizeUrl(value) || value;
}

function collectLinks(identity: Record<string, unknown>): LinkItem[] {
  const links: LinkItem[] = [];
  for (const field of PROFILE_LINK_FIELDS) {
    const value = identity[field];
    if (field === "website_urls" && Array.isArray(value)) {
      for (const [index, item] of value.entries()) {
        const url = normalizeUrl(String(item || ""));
        if (url) links.push({ label: `Website ${index + 2}`, href: url, text: String(item) });
      }
      continue;
    }
    if (!(field in LINK_FIELD_LABELS)) continue;
    const text = String(value || "").trim();
    const href = normalizeUrl(text);
    if (href) links.push({ label: LINK_FIELD_LABELS[field], href, text });
  }
  return links;
}

function collectContacts(identity: Record<string, unknown>): LinkItem[] {
  const contacts: LinkItem[] = [];
  for (const [field, label] of Object.entries(CONTACT_FIELD_LABELS)) {
    const text = String(identity[field] || "").trim();
    if (!text) continue;
    contacts.push({ label, href: handleHref(field, text), text });
  }
  return contacts;
}

function collectInfo(identity: Record<string, unknown>, schema: Record<string, WebsiteSchemaField>): InfoItem[] {
  const blocked = new Set([...PROFILE_LINK_FIELDS, ...Object.keys(SYSTEM_SCHEMA_FIELDS), ...INTERNAL_PROFILE_FIELDS]);
  const info: InfoItem[] = [];
  for (const [field, value] of Object.entries(identity)) {
    if (blocked.has(field) || value == null || value === "") continue;
    if (typeof value === "object") continue;
    const label = schema[field]?.label || field.replaceAll("_", " ").replace(/\b\w/g, (char) => char.toUpperCase());
    info.push({ label, value: String(value) });
  }
  return info.sort((a, b) => a.label.localeCompare(b.label));
}

export function renderProfilePage(input: ProfilePageInput): string {
  const schema = schemaWithSystemFields(input.schema || {});
  const identity = input.identity || {};
  const displayName = String(identity.display_name || input.fullName || input.email || "Profile");
  const subtitle = String(identity.bio || input.email || input.titleSuffix || "").trim();
  const avatarUrl = normalizeUrl(String(identity.avatar_url || "")) || "";
  const contacts = collectContacts(identity);
  const links = collectLinks(identity);
  const info = collectInfo(identity, schema);
  const initials = displayName.split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]?.toUpperCase()).join("") || "P";
  const qrDownloadUrl = input.qrDownloadUrl || "";
  const qrSvg = input.qrSvg || "";

  const contactHtml = contacts.map((item) => `
        <a class="link contact" href="${escapeHtml(item.href)}">
          <span>${escapeHtml(item.label)}</span>
          <strong>${escapeHtml(item.text)}</strong>
        </a>`).join("");
  const linkHtml = links.map((item) => `
        <a class="link" href="${escapeHtml(item.href)}" rel="me noopener noreferrer" target="_blank">
          <span>${escapeHtml(item.label)}</span>
          <strong>${escapeHtml(item.text)}</strong>
        </a>`).join("");
  const infoHtml = info.map((item) => `
        <div class="info-row">
          <span>${escapeHtml(item.label)}</span>
          <strong>${escapeHtml(item.value)}</strong>
        </div>`).join("");
  const qrHtml = input.profileUrl && qrSvg ? `
      <section class="qr-section">
        <h2>QR Code</h2>
        <div class="qr-card">
          <div class="qr-image" aria-label="QR code for ${escapeHtml(displayName)}">${qrSvg}</div>
          <div class="qr-actions">
            <strong>${escapeHtml(displayName)}</strong>
            <a class="qr-download" href="${escapeHtml(qrDownloadUrl)}" download>Download SVG</a>
          </div>
        </div>
      </section>` : "";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(displayName)}</title>
  <meta name="description" content="${escapeHtml(subtitle || `Profile for ${displayName}`)}">
  <style>
    :root { color-scheme: light; --ink:#18201f; --muted:#5d6966; --line:#d9e0dd; --paper:#ffffff; --bg:#f6f4ef; --accent:#0f766e; --accent2:#8b5cf6; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: radial-gradient(circle at top left, rgba(15,118,110,.14), transparent 30%), linear-gradient(135deg, #f6f4ef 0%, #eef5f3 52%, #f7f2fb 100%); color: var(--ink); }
    main { width: min(720px, calc(100% - 32px)); margin: 0 auto; padding: 48px 0; }
    header { text-align: center; margin-bottom: 28px; }
    .avatar { width: 112px; height: 112px; border-radius: 28px; display: inline-grid; place-items: center; overflow: hidden; background: linear-gradient(135deg, var(--accent), var(--accent2)); color: white; font-size: 34px; font-weight: 800; box-shadow: 0 16px 48px rgba(24,32,31,.16); }
    .avatar img { width: 100%; height: 100%; object-fit: cover; display: block; }
    h1 { margin: 18px 0 8px; font-size: clamp(2rem, 7vw, 3.75rem); line-height: .95; letter-spacing: 0; }
    .subtitle { margin: 0 auto; max-width: 58ch; color: var(--muted); font-size: 1.05rem; line-height: 1.55; }
    section { margin-top: 18px; }
    h2 { margin: 28px 0 12px; font-size: .78rem; text-transform: uppercase; letter-spacing: .14em; color: var(--muted); }
    .link, .info-row { width: 100%; min-height: 62px; display: flex; gap: 14px; align-items: center; justify-content: space-between; padding: 14px 16px; border: 1px solid var(--line); border-radius: 8px; background: rgba(255,255,255,.82); color: inherit; text-decoration: none; box-shadow: 0 1px 0 rgba(24,32,31,.04); }
    .link + .link, .info-row + .info-row { margin-top: 10px; }
    .link:hover { border-color: rgba(15,118,110,.44); transform: translateY(-1px); }
    .link span, .info-row span { flex: 0 0 auto; color: var(--muted); font-size: .92rem; }
    .link strong, .info-row strong { min-width: 0; overflow-wrap: anywhere; text-align: right; font-size: .98rem; }
    .qr-card { display: grid; grid-template-columns: auto minmax(0, 1fr); align-items: center; gap: 18px; padding: 16px; border: 1px solid var(--line); border-radius: 8px; background: rgba(255,255,255,.82); box-shadow: 0 1px 0 rgba(24,32,31,.04); }
    .qr-image { width: 132px; height: 132px; padding: 8px; border: 1px solid var(--line); border-radius: 8px; background: #fff; }
    .qr-image svg { display: block; width: 100%; height: 100%; }
    .qr-actions { min-width: 0; display: grid; gap: 10px; justify-items: start; }
    .qr-actions strong { overflow-wrap: anywhere; }
    .qr-download { display: inline-flex; align-items: center; justify-content: center; min-height: 42px; padding: 10px 14px; border: 1px solid rgba(15,118,110,.36); border-radius: 8px; background: #fff; color: var(--accent); font-weight: 700; text-decoration: none; }
    .qr-download:hover { border-color: rgba(15,118,110,.62); background: rgba(15,118,110,.08); }
    .empty { padding: 24px; text-align: center; color: var(--muted); border: 1px dashed var(--line); border-radius: 8px; background: rgba(255,255,255,.58); }
    footer { margin-top: 34px; text-align: center; color: var(--muted); font-size: .82rem; }
    @media (max-width: 560px) {
      main { width: min(100% - 24px, 720px); padding: 28px 0; }
      .avatar { width: 92px; height: 92px; border-radius: 22px; }
      .link, .info-row { align-items: flex-start; flex-direction: column; min-height: 76px; }
      .link strong, .info-row strong { text-align: left; }
      .qr-card { grid-template-columns: 1fr; justify-items: center; text-align: center; }
      .qr-actions { justify-items: center; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <div class="avatar">${avatarUrl ? `<img src="${escapeHtml(avatarUrl)}" alt="">` : escapeHtml(initials)}</div>
      <h1>${escapeHtml(displayName)}</h1>
      ${subtitle ? `<p class="subtitle">${escapeHtml(subtitle)}</p>` : ""}
    </header>
    ${contacts.length ? `<section><h2>Contact</h2>${contactHtml}</section>` : ""}
    ${links.length ? `<section><h2>Links</h2>${linkHtml}</section>` : ""}
    ${qrHtml}
    ${info.length ? `<section><h2>Info</h2>${infoHtml}</section>` : ""}
    ${!contacts.length && !links.length && !info.length ? `<div class="empty">No public profile details have been added yet.</div>` : ""}
    <footer>Powered by PIdP</footer>
  </main>
</body>
</html>`;
}
