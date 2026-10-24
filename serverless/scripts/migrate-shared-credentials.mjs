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

// Offline local SQLite copy only: no network or runtime startup is involved.
if (process.argv[1] && import.meta.url === (await import('node:url')).pathToFileURL(process.argv[1]).href) {
  const {parseArgs} = await import('node:util');
  const {resolve} = await import('node:path');
  const {existsSync} = await import('node:fs');
  const {DatabaseSync, backup} = await import('node:sqlite');
  const {stripJsoncComments} = await import('./deploy.mjs');
  const {values} = parseArgs({options: {
    config: {type:'string'}, database: {type:'string'}, app: {type:'string'},
    backup: {type:'string'}, apply: {type:'boolean', default:false},
    'writes-paused': {type:'boolean', default:false},
  }});
  if (!values.config || !values.database || !values.app) throw new Error('Required: --config PATH --database PATH --app SLUG');
  if (!existsSync(values.database)) throw new Error('Database must be an existing offline SQLite copy');
  if (values.apply && (!values['writes-paused'] || !values.backup || existsSync(values.backup))) {
    throw new Error('Apply requires --writes-paused and --backup NEW_PATH');
  }
  const config=JSON.parse(stripJsoncComments(readFileSync(values.config,'utf8')));
  if (!values.app || values.app !== config.vars?.PORTAL_SSO_APP_SLUG || config.vars?.PORTAL_SHARED_IDENTITY !== 'false') {
    throw new Error('Target must match the disabled shared-identity configuration');
  }
  const database=new DatabaseSync(resolve(values.database),{readOnly:!values.apply});
  try {
    database.exec('PRAGMA foreign_keys=ON');
    if (values.apply) {
      const mask=process.umask(0o077);
      try {await backup(database,resolve(values.backup));} finally {process.umask(mask);}
    }
    const db={prepare(query){
      const numbered=query.includes('?1');
      const statement=database.prepare(query.replaceAll('?1','?'));
      return {bind(...args){
        const params=numbered ? Array((query.match(/\?1/g)||[]).length).fill(args[0]) : args;
        return {
          async first(){return statement.get(...params)||null;},
          async run(){return statement.all(...params);},
        };
      }};
    },async batch(statements){
      database.exec('BEGIN IMMEDIATE');
      try {for(const statement of statements)await statement.run();database.exec('COMMIT');}
      catch(error){database.exec('ROLLBACK');throw error;}
    }};
    console.log(JSON.stringify(await migrateSharedCredentials(db, {
      appSlug:values.app, configuredAppSlug:config.vars.PORTAL_SSO_APP_SLUG,
      sharedIdentity:false, apply:values.apply,
      writesPaused:values['writes-paused'], backupVerified:Boolean(values.backup),
    })));
  } finally {database.close();}
}
