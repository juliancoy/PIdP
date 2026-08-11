import type { WebsiteSchemaField } from "./types";
import { fail } from "./http";

export const MAX_WEBSITES_PER_OWNER = 5;
export const DEFAULT_MAX_USERS_PER_WEBSITE = 10;

export const PROFILE_LINK_FIELDS = [
  "contact_email",
  "public_email",
  "phone_number",
  "mobile_number",
  "work_phone",
  "fax_number",
  "sms_number",
  "whatsapp_number",
  "telegram_username",
  "signal_username",
  "website_url",
  "website_urls",
  "github_url",
  "linkedin_url",
  "x_url",
  "twitter_url",
  "instagram_url",
  "facebook_url",
  "youtube_url",
  "tiktok_url",
  "threads_url",
  "bluesky_url",
  "mastodon_url",
  "discord_url",
  "twitch_url",
  "snapchat_url",
  "pinterest_url",
  "reddit_url",
  "medium_url",
  "substack_url",
  "linktree_url",
] as const;

export const SYSTEM_SCHEMA_FIELDS: Record<string, Required<WebsiteSchemaField>> = {
  display_name: {
    type: "string",
    required: false,
    label: "Display Name",
    description: "Public-facing name for the website user.",
    system: true,
  },
  avatar_url: {
    type: "string",
    required: false,
    label: "Profile Image",
    description: "Public profile image for the website user.",
    system: true,
  },
  first_name: {
    type: "string",
    required: false,
    label: "First Name",
    description: "Given name stored for the website user.",
    system: true,
  },
  last_name: {
    type: "string",
    required: false,
    label: "Last Name",
    description: "Family name stored for the website user.",
    system: true,
  },
  birth_date: {
    type: "string",
    required: false,
    label: "Birthday",
    description: "Birthday stored as YYYY-MM-DD for the website user.",
    system: true,
  },
  contact_email: {
    type: "string",
    required: false,
    label: "Contact Email",
    description: "Preferred public or professional contact email address.",
    system: true,
  },
  public_email: {
    type: "string",
    required: false,
    label: "Public Email",
    description: "Email address that may be shown publicly.",
    system: true,
  },
  phone_number: {
    type: "string",
    required: false,
    label: "Phone",
    description: "Primary contact phone number.",
    system: true,
  },
  mobile_number: {
    type: "string",
    required: false,
    label: "Mobile",
    description: "Mobile phone number.",
    system: true,
  },
  work_phone: {
    type: "string",
    required: false,
    label: "Work Phone",
    description: "Work or office phone number.",
    system: true,
  },
  fax_number: {
    type: "string",
    required: false,
    label: "Fax",
    description: "Fax number.",
    system: true,
  },
  sms_number: {
    type: "string",
    required: false,
    label: "SMS",
    description: "Phone number for SMS messages.",
    system: true,
  },
  whatsapp_number: {
    type: "string",
    required: false,
    label: "WhatsApp",
    description: "WhatsApp phone number.",
    system: true,
  },
  telegram_username: {
    type: "string",
    required: false,
    label: "Telegram",
    description: "Telegram username or contact handle.",
    system: true,
  },
  signal_username: {
    type: "string",
    required: false,
    label: "Signal",
    description: "Signal username or phone number.",
    system: true,
  },
  website_url: {
    type: "string",
    required: false,
    label: "Website",
    description: "Primary personal, professional, or organization website URL.",
    system: true,
  },
  website_urls: {
    type: "array",
    required: false,
    label: "Websites",
    description: "Additional personal, professional, or organization website URLs.",
    system: true,
  },
  github_url: {
    type: "string",
    required: false,
    label: "GitHub",
    description: "GitHub profile URL.",
    system: true,
  },
  linkedin_url: {
    type: "string",
    required: false,
    label: "LinkedIn",
    description: "LinkedIn profile URL.",
    system: true,
  },
  x_url: {
    type: "string",
    required: false,
    label: "X",
    description: "X profile URL.",
    system: true,
  },
  twitter_url: {
    type: "string",
    required: false,
    label: "Twitter",
    description: "Twitter profile URL.",
    system: true,
  },
  instagram_url: {
    type: "string",
    required: false,
    label: "Instagram",
    description: "Instagram profile URL.",
    system: true,
  },
  facebook_url: {
    type: "string",
    required: false,
    label: "Facebook",
    description: "Facebook profile URL.",
    system: true,
  },
  youtube_url: {
    type: "string",
    required: false,
    label: "YouTube",
    description: "YouTube channel URL.",
    system: true,
  },
  tiktok_url: {
    type: "string",
    required: false,
    label: "TikTok",
    description: "TikTok profile URL.",
    system: true,
  },
  threads_url: {
    type: "string",
    required: false,
    label: "Threads",
    description: "Threads profile URL.",
    system: true,
  },
  bluesky_url: {
    type: "string",
    required: false,
    label: "Bluesky",
    description: "Bluesky profile URL.",
    system: true,
  },
  mastodon_url: {
    type: "string",
    required: false,
    label: "Mastodon",
    description: "Mastodon profile URL.",
    system: true,
  },
  discord_url: {
    type: "string",
    required: false,
    label: "Discord",
    description: "Discord profile, invite, or server URL.",
    system: true,
  },
  twitch_url: {
    type: "string",
    required: false,
    label: "Twitch",
    description: "Twitch channel URL.",
    system: true,
  },
  snapchat_url: {
    type: "string",
    required: false,
    label: "Snapchat",
    description: "Snapchat profile URL.",
    system: true,
  },
  pinterest_url: {
    type: "string",
    required: false,
    label: "Pinterest",
    description: "Pinterest profile URL.",
    system: true,
  },
  reddit_url: {
    type: "string",
    required: false,
    label: "Reddit",
    description: "Reddit profile URL.",
    system: true,
  },
  medium_url: {
    type: "string",
    required: false,
    label: "Medium",
    description: "Medium profile URL.",
    system: true,
  },
  substack_url: {
    type: "string",
    required: false,
    label: "Substack",
    description: "Substack publication or profile URL.",
    system: true,
  },
  linktree_url: {
    type: "string",
    required: false,
    label: "Linktree",
    description: "Linktree or link-in-bio URL.",
    system: true,
  },
};

export function normalizeSlug(value: string): string {
  let slug = value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").replace(/-{2,}/g, "-");
  if (!slug) fail(422, "Website slug is invalid");
  if (slug.length > 120) slug = slug.slice(0, 120).replace(/-+$/g, "");
  return slug;
}

export function normalizeHost(value: unknown): string | null {
  let raw = String(value || "").trim().toLowerCase();
  if (!raw) return null;
  if (raw.includes("://")) {
    try {
      raw = new URL(raw).host.toLowerCase();
    } catch {
      return null;
    }
  }
  if (raw.includes(":") && !raw.startsWith("[")) {
    const [host, port] = raw.split(":", 2);
    raw = port && /^\d+$/.test(port) ? host : raw;
  }
  raw = raw.replace(/\.+$/g, "");
  return raw || null;
}

export function normalizeOrigin(value: unknown): string | null {
  const raw = String(value || "").trim();
  if (!raw.startsWith("http://") && !raw.startsWith("https://")) return null;
  try {
    const url = new URL(raw);
    const host = normalizeHost(url.host);
    if (!host) return null;
    const defaultPort = (url.protocol === "https:" && ["", "443"].includes(url.port)) || (url.protocol === "http:" && ["", "80"].includes(url.port));
    return `${url.protocol}//${host}${url.port && !defaultPort ? `:${url.port}` : ""}`;
  } catch {
    return null;
  }
}

export function normalizeHostList(values: unknown): string[] {
  const out: string[] = [];
  for (const item of Array.isArray(values) ? values : []) {
    const host = normalizeHost(item);
    if (host && !out.includes(host)) out.push(host);
  }
  return out;
}

export function normalizeOriginList(values: unknown): string[] {
  const out: string[] = [];
  for (const item of Array.isArray(values) ? values : []) {
    const origin = normalizeOrigin(item);
    if (origin && !out.includes(origin)) out.push(origin);
  }
  return out;
}

function safeText(value: unknown, maxLength: number): string {
  return String(value || "").trim().slice(0, maxLength);
}

function hexColor(value: unknown): string {
  const text = String(value || "").trim();
  return /^#[0-9a-fA-F]{6}$/.test(text) ? text.toLowerCase() : "";
}

export function normalizeBranding(raw: Record<string, unknown> | null | undefined): Record<string, string> {
  const data = raw || {};
  const allowedBackgrounds = new Set(["default", "gradient-warm", "gradient-ocean", "gradient-slate"]);
  const background = safeText(data.background_style, 32);
  return {
    logo_url: safeText(data.logo_url, 1024),
    hero_eyebrow: safeText(data.hero_eyebrow, 120),
    hero_title: safeText(data.hero_title, 200),
    hero_subtitle: safeText(data.hero_subtitle, 360),
    primary_button_label: safeText(data.primary_button_label, 60),
    accent_color: hexColor(data.accent_color),
    accent_deep_color: hexColor(data.accent_deep_color),
    accent_soft_color: hexColor(data.accent_soft_color),
    background_style: allowedBackgrounds.has(background) ? background : "default",
  };
}

export function normalizeWebsiteSchema(fields: Record<string, WebsiteSchemaField> | null | undefined): Record<string, WebsiteSchemaField> {
  const normalized: Record<string, WebsiteSchemaField> = {};
  for (const [name, field] of Object.entries(fields || {})) {
    const key = name.trim();
    if (!/^[a-zA-Z][a-zA-Z0-9_]{0,62}$/.test(key)) fail(422, `Schema field '${name}' is invalid`);
    if (key in SYSTEM_SCHEMA_FIELDS) {
      const system = SYSTEM_SCHEMA_FIELDS[key];
      if ((field.type || "string") !== system.type || Boolean(field.required) !== system.required) {
        fail(422, `Field '${key}' is reserved and cannot be redefined`);
      }
      continue;
    }
    normalized[key] = {
      type: field.type || "string",
      required: Boolean(field.required),
      label: field.label ?? null,
      description: field.description ?? null,
      system: Boolean(field.system),
    };
  }
  return { ...normalized, ...SYSTEM_SCHEMA_FIELDS };
}

export function schemaWithSystemFields(fields: Record<string, WebsiteSchemaField> | null | undefined): Record<string, WebsiteSchemaField> {
  return { ...(fields || {}), ...SYSTEM_SCHEMA_FIELDS };
}

export function validateIdentityData(identityData: unknown, schemaFields: Record<string, WebsiteSchemaField>): Record<string, unknown> {
  const payload = identityData && typeof identityData === "object" && !Array.isArray(identityData) ? { ...(identityData as Record<string, unknown>) } : {};
  const allowed = new Set(Object.keys(schemaFields));
  const unknown = Object.keys(payload).filter((key) => !allowed.has(key)).sort();
  if (unknown.length) fail(422, `Unknown identity fields: ${unknown.join(", ")}`);
  for (const [fieldName, definition] of Object.entries(schemaFields)) {
    if (definition.required && !(fieldName in payload)) fail(422, `Missing required identity field: ${fieldName}`);
    if (!(fieldName in payload)) continue;
    const value = payload[fieldName];
    const type = definition.type || "string";
    if (type === "string" && typeof value !== "string") fail(422, `${fieldName} must be a string`);
    if (type === "number" && typeof value !== "number") fail(422, `${fieldName} must be a number`);
    if (type === "boolean" && typeof value !== "boolean") fail(422, `${fieldName} must be a boolean`);
    if (type === "array" && !Array.isArray(value)) fail(422, `${fieldName} must be an array`);
    if (type === "object" && (!value || typeof value !== "object" || Array.isArray(value))) fail(422, `${fieldName} must be an object`);
  }
  return payload;
}
