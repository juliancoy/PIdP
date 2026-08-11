import type { Env } from "./types";
import { decryptString, encryptString } from "./crypto";
import { fail } from "./http";
import { first, nowIso } from "./db";

export type MicrosoftCalendarConnectionRow = {
  owner_user_id: string;
  microsoft_user_id: string;
  microsoft_email: string | null;
  calendar_id: string;
  refresh_token_encrypted: string;
  scope: string;
  created_at: string;
  updated_at: string;
};

type MicrosoftCalendarEventLinkRow = {
  owner_user_id: string;
  external_event_id: string;
  calendar_id: string;
  microsoft_event_id: string;
  summary: string | null;
  created_at: string;
  updated_at: string;
};

type MicrosoftTokenResponse = {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
};

type MicrosoftUserProfile = {
  id: string;
  mail?: string | null;
  userPrincipalName?: string | null;
};

export type MicrosoftCalendarStatus = {
  connected: boolean;
  microsoft_email: string | null;
  calendar_id: string | null;
  updated_at: string | null;
};

export type MicrosoftCalendarListItem = {
  id: string;
  summary: string;
  description: string | null;
  location: string | null;
  web_link: string | null;
  starts_at: string | null;
  ends_at: string | null;
};

export type CreatePortalEventMicrosoftCalendarInput = {
  owner_user_id: string;
  external_event_id: string;
  summary: string;
  description: string;
  starts_at: string;
  ends_at: string;
  location: string | null;
  source_url: string | null;
};

const MICROSOFT_CALENDAR_SCOPES = [
  "offline_access",
  "openid",
  "profile",
  "email",
  "User.Read",
  "Calendars.ReadWrite",
];

function requireMicrosoftClient(env: Env) {
  if (!env.MICROSOFT_CLIENT_ID || !env.MICROSOFT_CLIENT_SECRET) fail(400, "Microsoft OAuth is not configured");
}

export function microsoftCalendarScopes(): string[] {
  return [...MICROSOFT_CALENDAR_SCOPES];
}

export async function microsoftCalendarConnection(db: D1Database, ownerUserId: string) {
  return first<MicrosoftCalendarConnectionRow>(
    db.prepare("SELECT * FROM microsoft_calendar_connections WHERE owner_user_id = ?").bind(ownerUserId),
  );
}

export async function microsoftCalendarStatus(db: D1Database, ownerUserId: string): Promise<MicrosoftCalendarStatus> {
  const row = await microsoftCalendarConnection(db, ownerUserId);
  if (!row) return { connected: false, microsoft_email: null, calendar_id: null, updated_at: null };
  return {
    connected: true,
    microsoft_email: row.microsoft_email,
    calendar_id: row.calendar_id,
    updated_at: row.updated_at,
  };
}

export async function upsertMicrosoftCalendarConnection(
  env: Env,
  ownerUserId: string,
  profile: MicrosoftUserProfile,
  refreshToken: string,
  scope: string,
) {
  const existing = await microsoftCalendarConnection(env.DB, ownerUserId);
  const now = nowIso();
  const encryptedRefresh = await encryptString(env, refreshToken);
  const email = profile.mail || profile.userPrincipalName || null;
  if (existing) {
    await env.DB.prepare(
      `UPDATE microsoft_calendar_connections
          SET microsoft_user_id = ?, microsoft_email = ?, calendar_id = 'primary',
              refresh_token_encrypted = ?, scope = ?, updated_at = ?
        WHERE owner_user_id = ?`,
    ).bind(profile.id, email, encryptedRefresh, scope, now, ownerUserId).run();
  } else {
    await env.DB.prepare(
      `INSERT INTO microsoft_calendar_connections
        (owner_user_id, microsoft_user_id, microsoft_email, calendar_id, refresh_token_encrypted, scope, created_at, updated_at)
       VALUES (?, ?, ?, 'primary', ?, ?, ?, ?)`,
    ).bind(ownerUserId, profile.id, email, encryptedRefresh, scope, now, now).run();
  }
}

export async function disconnectMicrosoftCalendar(db: D1Database, ownerUserId: string) {
  await db.batch([
    db.prepare("DELETE FROM microsoft_calendar_event_links WHERE owner_user_id = ?").bind(ownerUserId),
    db.prepare("DELETE FROM microsoft_calendar_connections WHERE owner_user_id = ?").bind(ownerUserId),
  ]);
  return { disconnected: true };
}

export async function exchangeMicrosoftCalendarCode(env: Env, code: string, redirectUri: string): Promise<MicrosoftTokenResponse> {
  requireMicrosoftClient(env);
  const response = await fetch("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: env.MICROSOFT_CLIENT_ID || "",
      client_secret: env.MICROSOFT_CLIENT_SECRET || "",
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
      scope: MICROSOFT_CALENDAR_SCOPES.join(" "),
    }),
  });
  const payload = await response.json().catch(() => ({})) as MicrosoftTokenResponse & { error?: string; error_description?: string };
  if (!response.ok || !payload.access_token) fail(400, payload.error_description || payload.error || "Microsoft Calendar connection failed");
  return payload;
}

export async function fetchMicrosoftUserProfile(accessToken: string): Promise<MicrosoftUserProfile> {
  const response = await fetch("https://graph.microsoft.com/v1.0/me?$select=id,mail,userPrincipalName", {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  const payload = await response.json().catch(() => ({ id: "" })) as MicrosoftUserProfile & { error?: { message?: string } };
  if (!response.ok || !payload.id) fail(400, payload.error?.message || "Unable to verify Microsoft account");
  return payload;
}

async function refreshMicrosoftAccessToken(env: Env, connection: MicrosoftCalendarConnectionRow): Promise<string> {
  requireMicrosoftClient(env);
  const refreshToken = await decryptString(env, connection.refresh_token_encrypted);
  const response = await fetch("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.MICROSOFT_CLIENT_ID || "",
      client_secret: env.MICROSOFT_CLIENT_SECRET || "",
      refresh_token: refreshToken,
      grant_type: "refresh_token",
      scope: MICROSOFT_CALENDAR_SCOPES.join(" "),
    }),
  });
  const payload = await response.json().catch(() => ({})) as MicrosoftTokenResponse & { error?: string; error_description?: string };
  if (!response.ok || !payload.access_token) fail(400, payload.error_description || payload.error || "Microsoft Calendar authorization expired");
  return payload.access_token;
}

async function microsoftGraphRequest<T>(
  env: Env,
  ownerUserId: string,
  path: string,
  init?: RequestInit,
): Promise<T> {
  const connection = await microsoftCalendarConnection(env.DB, ownerUserId);
  if (!connection) fail(404, "Microsoft Calendar is not connected");
  const accessToken = await refreshMicrosoftAccessToken(env, connection);
  const response = await fetch(`https://graph.microsoft.com/v1.0${path}`, {
    ...init,
    headers: {
      accept: "application/json",
      authorization: `Bearer ${accessToken}`,
      ...(init?.body ? { "content-type": "application/json" } : {}),
      ...(init?.headers || {}),
    },
  });
  const payload = await response.json().catch(() => ({})) as T & { error?: { message?: string } };
  if (!response.ok) fail(400, payload.error?.message || "Microsoft Calendar request failed");
  return payload as T;
}

export async function listMicrosoftCalendarEvents(env: Env, ownerUserId: string, limit = 12) {
  const connection = await microsoftCalendarConnection(env.DB, ownerUserId);
  if (!connection) return { connected: false, calendar_id: null, events: [] as MicrosoftCalendarListItem[] };
  const maxResults = Math.max(1, Math.min(Number.isFinite(limit) ? Math.trunc(limit) : 12, 25));
  const start = new Date().toISOString();
  const end = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
  const params = new URLSearchParams({
    startDateTime: start,
    endDateTime: end,
    "$top": String(maxResults),
    "$orderby": "start/dateTime",
    "$select": "id,subject,bodyPreview,location,webLink,start,end",
  });
  const payload = await microsoftGraphRequest<{
    value?: Array<{
      id?: string;
      subject?: string;
      bodyPreview?: string;
      location?: { displayName?: string };
      webLink?: string;
      start?: { dateTime?: string };
      end?: { dateTime?: string };
    }>;
  }>(
    env,
    ownerUserId,
    `/me/calendarView?${params.toString()}`,
    { headers: { Prefer: 'outlook.timezone="UTC"' } },
  );
  const events = Array.isArray(payload.value)
    ? payload.value
      .filter((item) => item?.id)
      .map((item) => ({
        id: String(item.id),
        summary: String(item.subject || "Untitled event"),
        description: item.bodyPreview || null,
        location: item.location?.displayName || null,
        web_link: item.webLink || null,
        starts_at: item.start?.dateTime || null,
        ends_at: item.end?.dateTime || null,
      }))
    : [];
  return { connected: true, calendar_id: connection.calendar_id, events };
}

function microsoftPortalEventBody(input: CreatePortalEventMicrosoftCalendarInput) {
  const details = [
    input.description.trim(),
    input.source_url ? `Source: ${input.source_url}` : "",
    "Saved from Code Collective portal.",
  ].filter(Boolean).join("\n\n");
  return {
    subject: input.summary,
    body: {
      contentType: "text",
      content: details,
    },
    location: input.location ? { displayName: input.location } : undefined,
    start: { dateTime: input.starts_at, timeZone: "UTC" },
    end: { dateTime: input.ends_at, timeZone: "UTC" },
  };
}

export async function createMicrosoftCalendarPortalEvent(env: Env, input: CreatePortalEventMicrosoftCalendarInput) {
  const connection = await microsoftCalendarConnection(env.DB, input.owner_user_id);
  if (!connection) return { connected: false, event_id: null, web_link: null };
  const existing = await first<MicrosoftCalendarEventLinkRow>(
    env.DB.prepare("SELECT * FROM microsoft_calendar_event_links WHERE owner_user_id = ? AND external_event_id = ?")
      .bind(input.owner_user_id, input.external_event_id),
  );
  const body = microsoftPortalEventBody(input);
  let eventId = existing?.microsoft_event_id || null;
  let webLink: string | null = null;
  if (eventId) {
    try {
      const updated = await microsoftGraphRequest<{ id: string; webLink?: string }>(
        env,
        input.owner_user_id,
        `/me/events/${encodeURIComponent(eventId)}`,
        { method: "PATCH", body: JSON.stringify(body) },
      );
      eventId = updated.id;
      webLink = updated.webLink || null;
    } catch {
      eventId = null;
    }
  }
  if (!eventId) {
    const created = await microsoftGraphRequest<{ id: string; webLink?: string }>(
      env,
      input.owner_user_id,
      "/me/events",
      { method: "POST", body: JSON.stringify(body) },
    );
    eventId = created.id;
    webLink = created.webLink || null;
  }
  const now = nowIso();
  await env.DB.prepare(
    `INSERT INTO microsoft_calendar_event_links
      (owner_user_id, external_event_id, calendar_id, microsoft_event_id, summary, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(owner_user_id, external_event_id) DO UPDATE SET
       calendar_id = excluded.calendar_id,
       microsoft_event_id = excluded.microsoft_event_id,
       summary = excluded.summary,
       updated_at = excluded.updated_at`,
  ).bind(input.owner_user_id, input.external_event_id, connection.calendar_id, eventId, input.summary, now, now).run();
  return { connected: true, event_id: eventId, web_link: webLink || null };
}
