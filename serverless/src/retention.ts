export async function runRetention(db: D1Database, now = Date.now(), dryRun = false) {
  if (!Number.isSafeInteger(now) || now <= 0) throw new Error('Invalid retention clock');
  const cutoff = Math.floor(now / 1000) - 23 * 3600;
  const rules: [string, string, number][] = [
    ['browser_sessions', 'expires_at', Math.floor(now / 1000)],
    ['mcp_oauth_requests', 'expires_at', cutoff],
    ['mcp_oauth_codes', 'expires_at', cutoff],
    ['mcp_oauth_logins', 'expires_at', cutoff],
    ['oauth_states', 'expires_at', cutoff],
    ['portal_sso_requests', 'expires_at', cutoff],
    ['account_identity_link_previews', 'expires_at', cutoff],
    ['account_identity_link_requests', 'expires_at', cutoff],
    ['portal_sso_limits', 'window_start', Math.floor(cutoff / 60)],
    ['mcp_oauth_registration_limits', 'window_start', Math.floor(cutoff / 3600)],
  ];
  const counts: Record<string, number> = {};
  for (const [table, column, value] of rules) {
    if (dryRun) {
      const result = await db.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE ${column} < ?`).bind(value).first<{n:number}>();
      counts[table] = result?.n ?? 0;
    } else {
      const result = await db.prepare(`DELETE FROM ${table} WHERE rowid IN (SELECT rowid FROM ${table} WHERE ${column} < ? ORDER BY rowid LIMIT 500)`).bind(value).run();
      counts[table] = result.meta.changes;
    }
  }
  if(dryRun){const row=await db.prepare('SELECT COUNT(*) n FROM oauth_live_statistics WHERE day<?').bind(new Date(now-29*86400_000).toISOString().slice(0,10)).first<{n:number}>();counts.oauth_live_statistics=row?.n||0}
  else{const result=await db.prepare('DELETE FROM oauth_live_statistics WHERE rowid IN (SELECT rowid FROM oauth_live_statistics WHERE day<? LIMIT 500)').bind(new Date(now-29*86400_000).toISOString().slice(0,10)).run();counts.oauth_live_statistics=result.meta.changes}
  // Refresh replay detection depends on used token hashes. Keep grants/refreshes
  // together; never delete a used refresh token while its grant can still be used.
  return counts;
}
