/** Operator-only helper: use a D1 binding, never execute the SQL statement by statement. */
import {readFileSync} from 'node:fs';
const sql = readFileSync(new URL('../../docs/proposals/0012_shared_orgportal_credentials.sql', import.meta.url), 'utf8');

export async function migrateSharedCredentials(db, {
  appSlug, configuredAppSlug, sharedIdentity, writesPaused = false,
  backupVerified = false, apply = false,
}) {
  if (!appSlug || appSlug !== configuredAppSlug) throw new Error('Target must match configured PORTAL_SSO_APP_SLUG');
  if (sharedIdentity !== false) throw new Error('Shared identity must be disabled');
  const target = await db.prepare('SELECT id FROM websites WHERE slug=?').bind(appSlug).first();
  if (!target) throw new Error('Configured portal application does not exist');
  const counts = await db.prepare(`SELECT count(*) accounts,
    sum(CASE WHEN l.subject IS NULL THEN 1 ELSE 0 END) unlinked
    FROM website_users m LEFT JOIN account_identity_links l
    ON l.website_id=m.website_id AND l.website_user_id=m.id WHERE m.website_id=?`).bind(target.id).first();
  if (!apply) return {app: appSlug, ...counts, applied: false, collisionReview: 'Apply validates collisions atomically; counts alone are not readiness approval'};
  if (!writesPaused || !backupVerified) throw new Error('Pause identity writes and verify the pre-migration backup first');
  const statements = sql.replace(/^--.*$/gm, '').split(';').map(s => s.trim()).filter(Boolean);
  // D1 batch is transactional: any guard or write failure rolls back the entire batch.
  await db.batch(statements.map(statement => db.prepare(statement).bind(appSlug)));
  return {app: appSlug, ...counts, applied: true};
}

// Local operator entrypoint. Remote bindings are deliberately disabled.
if (process.argv[1] && import.meta.url === (await import('node:url')).pathToFileURL(process.argv[1]).href) {
  const {parseArgs} = await import('node:util');
  const {resolve} = await import('node:path');
  const {getPlatformProxy} = await import('wrangler');
  const {values} = parseArgs({options: {
    config: {type:'string'}, state: {type:'string'}, app: {type:'string'},
    apply: {type:'boolean', default:false},
    'writes-paused': {type:'boolean', default:false},
    'backup-verified': {type:'boolean', default:false},
  }});
  if (!values.config || !values.state || !values.app) throw new Error('Required: --config PATH --state PATH --app SLUG');
  const proxy = await getPlatformProxy({configPath:resolve(values.config),
    persist:{path:resolve(values.state)}, remoteBindings:false, envFiles:[]});
  try {
    console.log(JSON.stringify(await migrateSharedCredentials(proxy.env.DB, {
      appSlug:values.app, configuredAppSlug:proxy.env.PORTAL_SSO_APP_SLUG,
      sharedIdentity:proxy.env.PORTAL_SHARED_IDENTITY === 'false' ? false : undefined,
      apply:values.apply, writesPaused:values['writes-paused'], backupVerified:values['backup-verified'],
    })));
  } finally { await proxy.dispose(); }
}
