import type { Env } from "./types";
import { decryptString, encryptString } from "./crypto";
import { fail } from "./http";
import { first, nowIso } from "./db";

export type GoogleCalendarConnectionRow = {
  owner_user_id: string;
  google_user_id: string;
  google_email: string | null;
  calendar_id: string;
  refresh_token_encrypted: string;
  scope: string;
  sync_busy: number;
  created_at: string;
  updated_at: string;
};

type GoogleCalendarServiceLinkRow = {
  owner_user_id: string;
  external_service_id: string;
  calendar_id: string;
  google_event_id: string;
  summary: string | null;
  created_at: string;
  updated_at: string;
};

type GoogleTokenResponse = {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
};

type GoogleUserProfile = {
  sub: string;
  email?: string;
};

export type GoogleCalendarStatus = {
  connected: boolean;
  google_email: string | null;
  calendar_id: string | null;
  sync_busy: boolean;
  updated_at: string | null;
};

export type PublishAvailabilityInput = {
  owner_user_id: string;
  external_service_id: string;
  summary: string;
  description: string;
  timezone: string;
  weekdays: number[];
  starts_at: string;
  ends_at: string;
};

export type CreateBookingInput = {
  owner_user_id: string;
  external_service_id: string;
  service_name: string;
  service_description: string;
  starts_at: string;
  ends_at: string;
  attendee_name: string;
  attendee_email: string | null;
};

export type GoogleCalendarListItem = {
  id: string;
  summary: string;
  description: string | null;
  location: string | null;
  html_link: string | null;
  status: string | null;
  starts_at: string | null;
  ends_at: string | null;
};

export type CreatePortalEventCalendarInput = {
  owner_user_id: string;
  external_event_id: string;
  summary: string;
  description: string;
  starts_at: string;
  ends_at: string;
  location: string | null;
  source_url: string | null;
};

const GOOGLE_CALENDAR_EVENTS_SCOPE = "https://www.googleapis.com/auth/calendar.events";
const GOOGLE_CALENDAR_FREEBUSY_SCOPE = "https://www.googleapis.com/auth/calendar.freebusy";
const GOOGLE_CALENDAR_SCOPES = [GOOGLE_CALENDAR_EVENTS_SCOPE, GOOGLE_CALENDAR_FREEBUSY_SCOPE];

function requireGoogleClient(env: Env) {
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) fail(400, "Google OAuth is not configured");
}

export function googleCalendarScopes(): string[] {
  return [...GOOGLE_CALENDAR_SCOPES];
}

export async function googleCalendarConnection(db: D1Database, ownerUserId: string) {
  return first<GoogleCalendarConnectionRow>(
    db.prepare("SELECT * FROM google_calendar_connections WHERE owner_user_id = ?").bind(ownerUserId),
  );
}

export async function googleCalendarStatus(db: D1Database, ownerUserId: string): Promise<GoogleCalendarStatus> {
  const row = await googleCalendarConnection(db, ownerUserId);
  if (!row) return { connected: false, google_email: null, calendar_id: null, sync_busy: false, updated_at: null };
  return {
    connected: true,
    google_email: row.google_email,
    calendar_id: row.calendar_id,
    sync_busy: Boolean(row.sync_busy),
    updated_at: row.updated_at,
  };
}

export async function upsertGoogleCalendarConnection(
  env: Env,
  ownerUserId: string,
  profile: GoogleUserProfile,
  refreshToken: string,
  scope: string,
) {
  const existing = await googleCalendarConnection(env.DB, ownerUserId);
  const now = nowIso();
  const encryptedRefresh = await encryptString(env, refreshToken);
  if (existing) {
    await env.DB.prepare(
      `UPDATE google_calendar_connections
          SET google_user_id = ?, google_email = ?, calendar_id = 'primary',
              refresh_token_encrypted = ?, scope = ?, updated_at = ?
        WHERE owner_user_id = ?`,
    ).bind(profile.sub, profile.email || null, encryptedRefresh, scope, now, ownerUserId).run();
  } else {
    await env.DB.prepare(
      `INSERT INTO google_calendar_connections
        (owner_user_id, google_user_id, google_email, calendar_id, refresh_token_encrypted, scope, sync_busy, created_at, updated_at)
       VALUES (?, ?, ?, 'primary', ?, ?, 1, ?, ?)`,
    ).bind(ownerUserId, profile.sub, profile.email || null, encryptedRefresh, scope, now, now).run();
  }
}

export async function setGoogleCalendarSyncBusy(db: D1Database, ownerUserId: string, syncBusy: boolean) {
  const now = nowIso();
  const result = await db.prepare(
    "UPDATE google_calendar_connections SET sync_busy = ?, updated_at = ? WHERE owner_user_id = ?",
  ).bind(syncBusy ? 1 : 0, now, ownerUserId).run();
  if (!Number(result.meta?.changes || 0)) fail(404, "Google Calendar is not connected");
  return googleCalendarStatus(db, ownerUserId);
}

export async function disconnectGoogleCalendar(db: D1Database, ownerUserId: string) {
  await db.batch([
    db.prepare("DELETE FROM google_calendar_service_links WHERE owner_user_id = ?").bind(ownerUserId),
    db.prepare("DELETE FROM google_calendar_connections WHERE owner_user_id = ?").bind(ownerUserId),
  ]);
  return { disconnected: true };
}

export async function exchangeGoogleCalendarCode(env: Env, code: string, redirectUri: string): Promise<GoogleTokenResponse> {
  requireGoogleClient(env);
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID || "",
      client_secret: env.GOOGLE_CLIENT_SECRET || "",
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
    }),
  });
  const payload = await response.json().catch(() => ({})) as GoogleTokenResponse & { error?: string; error_description?: string };
  if (!response.ok || !payload.access_token) fail(400, payload.error_description || payload.error || "Google Calendar connection failed");
  return payload;
}

export async function fetchGoogleUserProfile(accessToken: string): Promise<GoogleUserProfile> {
  const response = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  const payload = await response.json().catch(() => ({ sub: "" })) as GoogleUserProfile & { error?: string };
  if (!response.ok || !payload.sub) fail(400, payload.error || "Unable to verify Google account");
  return payload;
}

async function refreshGoogleAccessToken(env: Env, connection: GoogleCalendarConnectionRow): Promise<string> {
  requireGoogleClient(env);
  const refreshToken = await decryptString(env, connection.refresh_token_encrypted);
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID || "",
      client_secret: env.GOOGLE_CLIENT_SECRET || "",
      refresh_token: refreshToken,
      grant_type: "refresh_token",
    }),
  });
  const payload = await response.json().catch(() => ({})) as GoogleTokenResponse & { error?: string; error_description?: string };
  if (!response.ok || !payload.access_token) fail(400, payload.error_description || payload.error || "Google Calendar authorization expired");
  return payload.access_token;
}

async function googleCalendarRequest<T>(
  env: Env,
  ownerUserId: string,
  path: string,
  init?: RequestInit,
): Promise<T> {
  const connection = await googleCalendarConnection(env.DB, ownerUserId);
  if (!connection) fail(404, "Google Calendar is not connected");
  const accessToken = await refreshGoogleAccessToken(env, connection);
  const response = await fetch(`https://www.googleapis.com/calendar/v3${path}`, {
    ...init,
    headers: {
      accept: "application/json",
      authorization: `Bearer ${accessToken}`,
      ...(init?.body ? { "content-type": "application/json" } : {}),
      ...(init?.headers || {}),
    },
  });
  const payload = await response.json().catch(() => ({})) as T & { error?: { message?: string } };
  if (!response.ok) fail(400, payload.error?.message || "Google Calendar request failed");
  return payload as T;
}

function weekdayToken(weekday: number): string {
  return ["SU", "MO", "TU", "WE", "TH", "FR", "SA"][weekday] || "MO";
}

function nextOccurrenceIso(weekdays: number[], startsAt: string, now = new Date()): string {
  const [hour, minute] = startsAt.split(":").map((value) => Number(value));
  const sorted = [...weekdays].sort((left, right) => left - right);
  for (let offset = 0; offset < 14; offset += 1) {
    const candidate = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + offset, hour, minute, 0, 0));
    if (!sorted.includes(candidate.getUTCDay())) continue;
    if (candidate.getTime() <= now.getTime()) continue;
    return candidate.toISOString();
  }
  const fallback = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 7, hour, minute, 0, 0));
  return fallback.toISOString();
}

function recurringAvailabilityBody(input: PublishAvailabilityInput) {
  const firstStart = nextOccurrenceIso(input.weekdays, input.starts_at);
  const startDate = new Date(firstStart);
  const [endHour, endMinute] = input.ends_at.split(":").map((value) => Number(value));
  const endDate = new Date(Date.UTC(
    startDate.getUTCFullYear(),
    startDate.getUTCMonth(),
    startDate.getUTCDate(),
    endHour,
    endMinute,
    0,
    0,
  ));
  const until = new Date(startDate.getTime() + 370 * 24 * 60 * 60 * 1000).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  return {
    summary: `Portal availability: ${input.summary}`,
    description: `${input.description}\n\nPublished from Code Collective portal recurring availability.`,
    start: { dateTime: firstStart, timeZone: input.timezone },
    end: { dateTime: endDate.toISOString(), timeZone: input.timezone },
    recurrence: [`RRULE:FREQ=WEEKLY;BYDAY=${input.weekdays.map(weekdayToken).join(",")};UNTIL=${until}`],
    transparency: "transparent",
    extendedProperties: {
      private: {
        source: "codecollective-portal",
        external_service_id: input.external_service_id,
      },
    },
  };
}

export async function publishGoogleCalendarAvailability(env: Env, input: PublishAvailabilityInput) {
  const connection = await googleCalendarConnection(env.DB, input.owner_user_id);
  if (!connection) fail(409, "Connect Google Calendar before publishing synced availability");
  const existing = await first<GoogleCalendarServiceLinkRow>(
    env.DB.prepare("SELECT * FROM google_calendar_service_links WHERE owner_user_id = ? AND external_service_id = ?").bind(input.owner_user_id, input.external_service_id),
  );
  const body = recurringAvailabilityBody(input);
  let eventId = existing?.google_event_id || null;
  if (eventId) {
    try {
      await googleCalendarRequest(
        env,
        input.owner_user_id,
        `/calendars/${encodeURIComponent(connection.calendar_id)}/events/${encodeURIComponent(eventId)}`,
        { method: "PUT", body: JSON.stringify(body) },
      );
    } catch {
      eventId = null;
    }
  }
  if (!eventId) {
    const created = await googleCalendarRequest<{ id: string }>(
      env,
      input.owner_user_id,
      `/calendars/${encodeURIComponent(connection.calendar_id)}/events`,
      { method: "POST", body: JSON.stringify(body) },
    );
    eventId = created.id;
  }
  const now = nowIso();
  await env.DB.prepare(
    `INSERT INTO google_calendar_service_links
      (owner_user_id, external_service_id, calendar_id, google_event_id, summary, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(owner_user_id, external_service_id) DO UPDATE SET
       calendar_id = excluded.calendar_id,
       google_event_id = excluded.google_event_id,
       summary = excluded.summary,
       updated_at = excluded.updated_at`,
  ).bind(input.owner_user_id, input.external_service_id, connection.calendar_id, eventId, input.summary, now, now).run();
  return { connected: true, calendar_id: connection.calendar_id, google_event_id: eventId };
}

export async function googleCalendarBusy(env: Env, ownerUserId: string, startsAt: string, endsAt: string) {
  const connection = await googleCalendarConnection(env.DB, ownerUserId);
  if (!connection) return { connected: false, busy: false, sync_busy: false };
  if (!connection.sync_busy) return { connected: true, busy: false, sync_busy: false };
  const payload = await googleCalendarRequest<{ calendars?: Record<string, { busy?: Array<{ start: string; end: string }> }> }>(
    env,
    ownerUserId,
    "/freeBusy",
    {
      method: "POST",
      body: JSON.stringify({
        timeMin: startsAt,
        timeMax: endsAt,
        items: [{ id: connection.calendar_id }],
      }),
    },
  );
  const entries = payload.calendars?.[connection.calendar_id]?.busy || [];
  return { connected: true, busy: entries.length > 0, sync_busy: true };
}

export async function createGoogleCalendarBooking(env: Env, input: CreateBookingInput) {
  const connection = await googleCalendarConnection(env.DB, input.owner_user_id);
  if (!connection) return { connected: false };
  const body = {
    summary: `${input.service_name} with ${input.attendee_name}`,
    description: `${input.service_description}\n\nBooked through Code Collective portal.${input.attendee_email ? `\nAttendee: ${input.attendee_name} <${input.attendee_email}>` : `\nAttendee: ${input.attendee_name}`}`,
    start: { dateTime: input.starts_at, timeZone: "UTC" },
    end: { dateTime: input.ends_at, timeZone: "UTC" },
    attendees: input.attendee_email ? [{ email: input.attendee_email, displayName: input.attendee_name }] : [],
    extendedProperties: {
      private: {
        source: "codecollective-portal",
        external_service_id: input.external_service_id,
      },
    },
  };
  const created = await googleCalendarRequest<{ id: string; htmlLink?: string }>(
    env,
    input.owner_user_id,
    `/calendars/${encodeURIComponent(connection.calendar_id)}/events`,
    { method: "POST", body: JSON.stringify(body) },
  );
  return { connected: true, event_id: created.id, html_link: created.htmlLink || null };
}

export async function listGoogleCalendarEvents(env: Env, ownerUserId: string, limit = 12) {
  const connection = await googleCalendarConnection(env.DB, ownerUserId);
  if (!connection) return { connected: false, calendar_id: null, events: [] as GoogleCalendarListItem[] };
  const maxResults = Math.max(1, Math.min(Number.isFinite(limit) ? Math.trunc(limit) : 12, 25));
  const query = new URLSearchParams({
    singleEvents: "true",
    orderBy: "startTime",
    timeMin: new Date().toISOString(),
    maxResults: String(maxResults),
  });
  const payload = await googleCalendarRequest<{
    items?: Array<{
      id?: string;
      summary?: string;
      description?: string;
      location?: string;
      htmlLink?: string;
      status?: string;
      start?: { dateTime?: string; date?: string };
      end?: { dateTime?: string; date?: string };
    }>;
  }>(
    env,
    ownerUserId,
    `/calendars/${encodeURIComponent(connection.calendar_id)}/events?${query.toString()}`,
  );
  const events = Array.isArray(payload.items)
    ? payload.items
      .filter((item) => item?.id)
      .map((item) => ({
        id: String(item.id),
        summary: String(item.summary || "Untitled event"),
        description: item.description || null,
        location: item.location || null,
        html_link: item.htmlLink || null,
        status: item.status || null,
        starts_at: item.start?.dateTime || item.start?.date || null,
        ends_at: item.end?.dateTime || item.end?.date || null,
      }))
    : [];
  return { connected: true, calendar_id: connection.calendar_id, events };
}

function portalEventBody(input: CreatePortalEventCalendarInput) {
  const details = [
    input.description.trim(),
    input.location ? `Location: ${input.location}` : "",
    input.source_url ? `Source: ${input.source_url}` : "",
    "Saved from Code Collective portal.",
  ].filter(Boolean);
  return {
    summary: input.summary,
    description: details.join("\n\n"),
    location: input.location || undefined,
    start: { dateTime: input.starts_at, timeZone: "UTC" },
    end: { dateTime: input.ends_at, timeZone: "UTC" },
    extendedProperties: {
      private: {
        source: "codecollective-portal-event",
        external_event_id: input.external_event_id,
      },
    },
  };
}

export async function createGoogleCalendarPortalEvent(env: Env, input: CreatePortalEventCalendarInput) {
  const connection = await googleCalendarConnection(env.DB, input.owner_user_id);
  if (!connection) return { connected: false, event_id: null, html_link: null };
  const existing = await first<GoogleCalendarServiceLinkRow>(
    env.DB.prepare("SELECT * FROM google_calendar_service_links WHERE owner_user_id = ? AND external_service_id = ?")
      .bind(input.owner_user_id, input.external_event_id),
  );
  const body = portalEventBody(input);
  let eventId = existing?.google_event_id || null;
  let htmlLink: string | null = null;
  if (eventId) {
    try {
      const updated = await googleCalendarRequest<{ id: string; htmlLink?: string }>(
        env,
        input.owner_user_id,
        `/calendars/${encodeURIComponent(connection.calendar_id)}/events/${encodeURIComponent(eventId)}`,
        { method: "PUT", body: JSON.stringify(body) },
      );
      eventId = updated.id;
      htmlLink = updated.htmlLink || null;
    } catch {
      eventId = null;
    }
  }
  if (!eventId) {
    const created = await googleCalendarRequest<{ id: string; htmlLink?: string }>(
      env,
      input.owner_user_id,
      `/calendars/${encodeURIComponent(connection.calendar_id)}/events`,
      { method: "POST", body: JSON.stringify(body) },
    );
    eventId = created.id;
    htmlLink = created.htmlLink || null;
  }
  const now = nowIso();
  await env.DB.prepare(
    `INSERT INTO google_calendar_service_links
      (owner_user_id, external_service_id, calendar_id, google_event_id, summary, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(owner_user_id, external_service_id) DO UPDATE SET
       calendar_id = excluded.calendar_id,
       google_event_id = excluded.google_event_id,
       summary = excluded.summary,
       updated_at = excluded.updated_at`,
  ).bind(input.owner_user_id, input.external_event_id, connection.calendar_id, eventId, input.summary, now, now).run();
  return { connected: true, event_id: eventId, html_link: htmlLink || null };
}
