interface Env {
  DB: D1Database;
  AVATARS?: R2Bucket;
  APP_NAME?: string;
  ENV?: string;
  SECRET_KEY: string;
  ACCESS_TOKEN_EXPIRE_MINUTES?: string;
  ALLOWED_ORIGINS?: string;
  ADMIN_EMAILS?: string;
  ADMIN_USER_IDS?: string;
  PUBLIC_R2_BASE_URL?: string;
  FRONTEND_REDIRECT_URL?: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  GOOGLE_REDIRECT_URI?: string;
  GOOGLE_CALENDAR_REDIRECT_URI?: string;
  MICROSOFT_CLIENT_ID?: string;
  MICROSOFT_CLIENT_SECRET?: string;
  MICROSOFT_REDIRECT_URI?: string;
  MICROSOFT_CALENDAR_REDIRECT_URI?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  GITHUB_REDIRECT_URI?: string;
}
