// Run with: ~/.bun/bin/bun server.js
import { createPublicKey, verify as cryptoVerify, X509Certificate } from 'crypto';
import { Database } from 'bun:sqlite';
const htmlPath = new URL('./index.html', import.meta.url);

// ── Malware cache (SQLite) ────────────────────────────────────────────────────
const DB_PATH = process.env.MALWARE_DB_PATH || './malware.db';
const db = new Database(DB_PATH);
db.exec('PRAGMA journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS malware (
    package_name TEXT NOT NULL,
    version     TEXT,
    scope       TEXT,
    malid       TEXT,
    source      TEXT,
    blocked_at  TEXT NOT NULL,
    ecosystem   TEXT NOT NULL,
    reason_json TEXT,
    description TEXT,
    PRIMARY KEY (ecosystem, package_name, version, malid, blocked_at)
  );
  CREATE INDEX IF NOT EXISTS idx_malware_blocked_at ON malware(blocked_at DESC);
  CREATE INDEX IF NOT EXISTS idx_malware_package    ON malware(package_name);
  CREATE TABLE IF NOT EXISTS sync_meta (
    key TEXT PRIMARY KEY,
    value TEXT
  );
  CREATE TABLE IF NOT EXISTS sync_windows (
    ecosystem    TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end   TEXT NOT NULL,
    synced_at    TEXT NOT NULL,
    PRIMARY KEY (ecosystem, window_start)
  );
`);

// Migration: add published_at column if not present
{
  const hasPubCol = db.prepare(`SELECT 1 FROM pragma_table_info('malware') WHERE name='published_at'`).get();
  if (!hasPubCol) {
    db.exec(`
      ALTER TABLE malware ADD COLUMN published_at TEXT;
      CREATE INDEX IF NOT EXISTS idx_malware_published ON malware(published_at);
    `);
  }
}

// Ensure compound indexes for common TDD query patterns
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_malware_eco_pub   ON malware(ecosystem, published_at);
  CREATE INDEX IF NOT EXISTS idx_malware_src_pub   ON malware(source, published_at);
  CREATE INDEX IF NOT EXISTS idx_malware_eco_blk   ON malware(ecosystem, blocked_at DESC);
`);

const insertMalware = db.prepare(`
  INSERT INTO malware
    (package_name, version, scope, malid, source, blocked_at, ecosystem, reason_json, description)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  ON CONFLICT(ecosystem, package_name, version, malid, blocked_at) DO UPDATE SET
    scope        = excluded.scope,
    source       = excluded.source,
    reason_json  = excluded.reason_json,
    description  = excluded.description
`);

// ── Malware enrichment (publish-date fetch from registries) ──────────────────
const enrichState = { running: false, done: 0, total: 0, failed: 0, error: null, startedAt: null, finishedAt: null };

async function fetchNpmTimestamps(packageName) {
  const res = await fetch(`https://registry.npmjs.org/${packageName}`);
  if (!res.ok) return null;
  const data = await res.json();
  const time = data.time || {};
  const skip = new Set(['created', 'modified', 'unpublished']);
  const out = {};
  for (const [k, v] of Object.entries(time)) {
    if (!skip.has(k)) out[k] = v;
  }
  out[''] = time.created || null; // for package-wide blocks
  return out;
}

async function fetchPypiTimestamps(packageName) {
  const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`);
  if (!res.ok) return null;
  const data = await res.json();
  const releases = data.releases || {};
  const out = {};
  for (const [ver, files] of Object.entries(releases)) {
    const uploadTime = files?.[0]?.upload_time;
    if (uploadTime) out[ver] = uploadTime.endsWith('Z') ? uploadTime : uploadTime + 'Z';
  }
  const firstDate = Object.values(out).sort()[0] || null;
  out[''] = firstDate;
  return out;
}

async function fetchMavenTimestamps(packageName) {
  const slashIdx = packageName.indexOf('/');
  if (slashIdx < 0) return null;
  const group = packageName.slice(0, slashIdx);
  const artifact = packageName.slice(slashIdx + 1);
  const q = encodeURIComponent(`g:${group} AND a:${artifact}`);
  const res = await fetch(`https://search.maven.org/solrsearch/select?q=${q}&core=gav&rows=200&sort=timestamp+asc&wt=json`);
  if (!res.ok) return null;
  const data = await res.json();
  const docs = data.response?.docs || [];
  const out = {};
  for (const doc of docs) {
    if (doc.v && doc.timestamp) out[doc.v] = new Date(doc.timestamp).toISOString();
  }
  const times = Object.values(out).sort();
  out[''] = times[0] || null;
  return out;
}

async function runMalwareEnrich() {
  if (enrichState.running) throw new Error('Enrichment already in progress');
  enrichState.running = true;
  enrichState.done = 0;
  enrichState.total = 0;
  enrichState.failed = 0;
  enrichState.error = null;
  enrichState.startedAt = new Date().toISOString();
  enrichState.finishedAt = null;

  try {
    const pending = db.prepare(`
      SELECT ecosystem, package_name FROM malware
      WHERE published_at IS NULL
      GROUP BY ecosystem, package_name
      ORDER BY MAX(blocked_at) DESC
    `).all();
    enrichState.total = pending.length;

    const updateStmt = db.prepare(`UPDATE malware SET published_at = ? WHERE ecosystem = ? AND package_name = ? AND version = ?`);

    const BATCH = 50;
    const FETCH_TIMEOUT = 8000;
    const withTimeout = (p) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), FETCH_TIMEOUT))]);

    for (let i = 0; i < pending.length; i += BATCH) {
      const batch = pending.slice(i, i + BATCH);
      await Promise.allSettled(batch.map(async ({ ecosystem, package_name }) => {
        try {
          let timeMap;
          if (ecosystem === 'npm')        timeMap = await withTimeout(fetchNpmTimestamps(package_name));
          else if (ecosystem === 'PyPI')  timeMap = await withTimeout(fetchPypiTimestamps(package_name));
          else                            timeMap = await withTimeout(fetchMavenTimestamps(package_name));

          const versions = db.prepare(
            `SELECT version FROM malware WHERE ecosystem = ? AND package_name = ? AND published_at IS NULL`
          ).all(ecosystem, package_name);

          db.transaction(() => {
            for (const { version } of versions) {
              updateStmt.run(timeMap?.[version] ?? 'NOT_FOUND', ecosystem, package_name, version);
            }
          })();
        } catch {
          db.prepare(`UPDATE malware SET published_at = 'ERROR' WHERE ecosystem = ? AND package_name = ? AND published_at IS NULL`)
            .run(ecosystem, package_name);
          enrichState.failed++;
        }
        enrichState.done++;
      }));
      await new Promise(r => setTimeout(r, 0));
    }
  } catch (err) {
    enrichState.error = err.message;
    throw err;
  } finally {
    enrichState.running = false;
    enrichState.finishedAt = new Date().toISOString();
  }
}

// ── Platform API token (server-side storage + auto-refresh) ───────────────────

// Platform API ecosystem values and their DB names
const PLATFORM_ECOSYSTEMS = [
  { apiName: 'npm',   dbName: 'npm'   },
  { apiName: 'Maven', dbName: 'Maven' },
  { apiName: 'PyPI',  dbName: 'PyPI'  },
];

// One-time cleanup: earlier syncs stored rows under the API's inconsistent ecosystem
// casing (e.g. 'pypi'/'maven'), producing orphan rows the read path never queries.
// Drop anything outside the canonical set (derived here so it can't wipe a real ecosystem).
{
  const canonical = PLATFORM_ECOSYSTEMS.map(e => e.dbName);
  const res = db.prepare(`DELETE FROM malware WHERE ecosystem NOT IN (${canonical.map(() => '?').join(',')})`).run(...canonical);
  if (res.changes) console.log(`[migration] removed ${res.changes} orphan malware row(s) with non-canonical ecosystem casing`);
}

let platformToken = process.env.PLATFORM_API_TOKEN || null;
let platformTokenExpiry = null; // Unix timestamp (ms)
let tokenRefreshTimer = null;

// The malware blocklist API lives behind console-api; a token minted for any
// other audience (e.g. the libraries.cgr.dev registry) is rejected with a
// confusing HTTP 500, so we validate the aud claim up front.
const EXPECTED_TOKEN_AUDIENCE = 'https://console-api.enforce.dev';

function decodePlatformTokenPayload(token) {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
  } catch { return null; }
}

function parsePlatformTokenExpiry(token) {
  const payload = decodePlatformTokenPayload(token);
  return payload?.exp ? payload.exp * 1000 : null;
}

// Returns the aud claim as an array (JWT aud may be a string or array), or null.
function parsePlatformTokenAudiences(token) {
  const aud = decodePlatformTokenPayload(token)?.aud;
  if (!aud) return null;
  return Array.isArray(aud) ? aud : [aud];
}

function tokenAudienceOk(token) {
  const auds = parsePlatformTokenAudiences(token);
  // If we can't read an aud claim, don't block — let the API be the judge.
  return !auds || auds.includes(EXPECTED_TOKEN_AUDIENCE);
}

function setPlatformToken(token) {
  platformToken = token || null;
  platformTokenExpiry = token ? parsePlatformTokenExpiry(token) : null;
  if (token && !tokenAudienceOk(token)) {
    console.warn(`[platform-token] WARNING: token audience is ${JSON.stringify(parsePlatformTokenAudiences(token))}, expected ${EXPECTED_TOKEN_AUDIENCE} — malware sync will fail with HTTP 500`);
  }
  if (tokenRefreshTimer) { clearTimeout(tokenRefreshTimer); tokenRefreshTimer = null; }
  if (platformTokenExpiry) scheduleTokenRefresh();
}

let tokenRefreshInFlight = null;
// Single-flight: concurrent callers (e.g. parallel ecosystem syncs all hitting 401
// at once) share one chainctl mint instead of spawning several.
function refreshPlatformTokenViaChainctl() {
  if (tokenRefreshInFlight) return tokenRefreshInFlight;
  tokenRefreshInFlight = (async () => {
    try {
      const proc = Bun.spawn(['chainctl', 'auth', 'token', '--audience', 'https://console-api.enforce.dev'], {
        stdout: 'pipe', stderr: 'pipe',
      });
      const text = await new Response(proc.stdout).text();
      const code = await proc.exited;
      if (code !== 0) throw new Error(`chainctl exited ${code}`);
      const token = text.trim();
      if (!token) throw new Error('empty token');
      setPlatformToken(token);
      console.log('Platform token refreshed via chainctl, expires', new Date(platformTokenExpiry).toISOString());
      return token;
    } catch (err) {
      console.error('chainctl token refresh failed:', err.message);
      return null;
    }
  })();
  tokenRefreshInFlight.finally(() => { tokenRefreshInFlight = null; });
  return tokenRefreshInFlight;
}

// Proactively refresh if the token is missing or within `minMs` of expiry — called
// before a sync so a long page-through doesn't hit a mid-flight 401 (which can
// truncate pagination). Never throws; best-effort.
async function ensurePlatformTokenFresh(minMs = 10 * 60 * 1000) {
  const needsRefresh = !platformToken || (platformTokenExpiry && platformTokenExpiry - Date.now() < minMs);
  if (needsRefresh) {
    console.log('[malware-sync] platform token missing or near expiry — refreshing before sync');
    await refreshPlatformTokenViaChainctl();
  }
}

function scheduleTokenRefresh() {
  if (!platformTokenExpiry) return;
  const refreshAt = platformTokenExpiry - 5 * 60 * 1000; // 5 min before expiry
  const delay = refreshAt - Date.now();
  // If we're already past the refresh point, don't spin — wait 60s before retrying
  tokenRefreshTimer = setTimeout(async () => {
    await refreshPlatformTokenViaChainctl();
  }, Math.max(60000, delay));
}

// Seed from env var on startup; if none set, try to mint via chainctl
if (platformToken) {
  platformTokenExpiry = parsePlatformTokenExpiry(platformToken);
  if (platformTokenExpiry) scheduleTokenRefresh();
} else {
  refreshPlatformTokenViaChainctl().then(t => {
    if (t) console.log('Platform token auto-minted via chainctl on startup');
    else console.log('No platform token — paste one in Settings or mount chainctl config');
  });
}

// ── Chainguard Libraries registry auth (libraries.cgr.dev) ──────────────────
// Unlike console-api, the registry doesn't want a pre-exchanged token: it takes
// HTTP Basic where username = the assumable identity UIDP and password = the raw
// projected OIDC token (aud=issuer.enforce.dev) — the registry performs the STS
// exchange itself. This is what makes it work under K8s workload identity where
// chainctl can't mint the libraries.cgr.dev audience non-interactively.
//   Set CHAINGUARD_IDENTITY (identity UIDP) + mount the projected token at
//   SA_TOKEN_PATH. A user-supplied Basic credential from Settings still overrides,
//   and CGR_REGISTRY_TOKEN (bearer) / chainctl are kept as fallbacks for other envs.
const CHAINGUARD_IDENTITY = process.env.CHAINGUARD_IDENTITY || '';
const SA_TOKEN_PATH = process.env.SA_TOKEN_PATH || '/var/run/chainguard/oidc/oidc-token';
const REGISTRY_AUDIENCE = 'libraries.cgr.dev';
let registryToken = process.env.CGR_REGISTRY_TOKEN || null;
let registryTokenExpiry = registryToken ? parsePlatformTokenExpiry(registryToken) : null;
let registryHeaderCache = { header: null, refreshAt: 0 }; // Basic(UIDP:oidc), rebuilt every 60s

async function readProjectedToken() {
  try { return (await Bun.file(SA_TOKEN_PATH).text()).trim(); }
  catch { return null; }
}

let registryRefreshInFlight = null;
function refreshRegistryTokenViaChainctl() {
  if (registryRefreshInFlight) return registryRefreshInFlight;
  registryRefreshInFlight = (async () => {
    try {
      const proc = Bun.spawn(['chainctl', 'auth', 'token', '--audience', REGISTRY_AUDIENCE], { stdout: 'pipe', stderr: 'pipe' });
      const [text, errText] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()]);
      const code = await proc.exited;
      if (code !== 0) throw new Error(`chainctl exited ${code}: ${errText.trim().slice(0, 300) || '(no stderr)'}`);
      const token = text.trim();
      if (!token) throw new Error('empty token');
      registryToken = token;
      registryTokenExpiry = parsePlatformTokenExpiry(token);
      return token;
    } catch (err) {
      console.error('chainctl registry token refresh failed:', err.message);
      return null;
    }
  })();
  registryRefreshInFlight.finally(() => { registryRefreshInFlight = null; });
  return registryRefreshInFlight;
}
async function ensureRegistryTokenFresh(minMs = 5 * 60 * 1000) {
  if (!registryToken || (registryTokenExpiry && registryTokenExpiry - Date.now() < minMs)) {
    await refreshRegistryTokenViaChainctl();
  }
  return registryToken;
}

// Authorization header for a libraries.cgr.dev request. Priority:
//   1. user-supplied Basic creds from Settings,
//   2. workload identity: Basic(UIDP : projected OIDC token) — registry does STS,
//   3. bearer from CGR_REGISTRY_TOKEN env or a chainctl-minted registry token.
async function cgrHeaders(req) {
  const user = req.headers.get('x-cgr-user') || '';
  const pass = req.headers.get('x-cgr-pass') || '';
  if (user) return { 'Authorization': 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64') };

  if (CHAINGUARD_IDENTITY) {
    const now = Date.now();
    if (registryHeaderCache.header && now < registryHeaderCache.refreshAt) return { 'Authorization': registryHeaderCache.header };
    const idToken = await readProjectedToken(); // kubelet rotates this file in place
    if (idToken) {
      const header = 'Basic ' + Buffer.from(`${CHAINGUARD_IDENTITY}:${idToken}`).toString('base64');
      registryHeaderCache = { header, refreshAt: now + 60000 };
      return { 'Authorization': header };
    }
    console.warn(`[cgr] CHAINGUARD_IDENTITY set but no projected token at ${SA_TOKEN_PATH}`);
  }

  const token = await ensureRegistryTokenFresh();
  return token ? { 'Authorization': `Bearer ${token}` } : {};
}

// ── Malware sync ──────────────────────────────────────────────────────────────

const syncState = { running: false, fetched: 0, total: 0, error: null, startedAt: null, finishedAt: null, windowsDone: 0, windowsTotal: 0, cancelled: false, expectedTotal: 0 };

// "Warm" once the local mirror holds a usable dataset — either persisted from a
// previous run or filled by a completed sync. While cold (first fill in progress),
// per-package checks are served live so the tool is useful immediately.
let malwareWarm = db.prepare(`SELECT COUNT(*) AS n FROM malware`).get().n > 0;

function malwareStatus() {
  const counts = db.prepare(`SELECT ecosystem, COUNT(*) AS n, MAX(blocked_at) AS latest FROM malware GROUP BY ecosystem`).all();
  const byEco = Object.fromEntries(counts.map(r => [r.ecosystem, { total: r.n, latest: r.latest }]));
  const total = counts.reduce((s, r) => s + r.n, 0);
  const lastSync = db.prepare(`SELECT value FROM sync_meta WHERE key = 'last_sync_at'`).get();
  const tokenStatus = platformToken
    ? { set: true, expiresAt: platformTokenExpiry ? new Date(platformTokenExpiry).toISOString() : null, audienceOk: tokenAudienceOk(platformToken) }
    : { set: false };
  const enrichCounts = db.prepare(`
    SELECT
      COUNT(*) AS total,
      COUNT(CASE WHEN published_at IS NOT NULL AND published_at NOT IN ('NOT_FOUND','ERROR') THEN 1 END) AS enriched,
      COUNT(CASE WHEN published_at IS NULL THEN 1 END) AS pending,
      COUNT(CASE WHEN published_at IN ('NOT_FOUND','ERROR') THEN 1 END) AS unavailable
    FROM malware
  `).get();
  return { total, byEco, lastSyncAt: lastSync?.value || null, sync: { ...syncState }, platformToken: tokenStatus, enrich: { ...enrichCounts, state: { ...enrichState } } };
}

const SCOPE_NORM = { 'MALWARE_SCOPE_VERSION': 'version', 'MALWARE_SCOPE_PACKAGE': 'package', 'MALWARE_SCOPE_UNKNOWN': '' };
function normScope(s) { return SCOPE_NORM[s] ?? s ?? ''; }

function insertItems(items, ecoName) {
  const tx = db.transaction(rows => {
    for (const it of rows) {
      insertMalware.run(
        it.package_name ?? it.packageName,
        it.version ?? '',
        normScope(it.scope),
        it.malid ?? '',
        it.source ?? null,
        it.blocked_at ?? it.blockedAt,
        ecoName, // always the queried ecosystem — the API returns inconsistent casing
                 // (e.g. 'pypi' vs 'PyPI') in the item field, which the read path never matches
        JSON.stringify(it.reason || []),
        it.description ?? null,
      );
    }
  });
  tx(items);
  syncState.fetched += items.length;
}

const CONSOLE_API_BASE = 'https://console-api.enforce.dev';
const MALWARE_API_BASE = `${CONSOLE_API_BASE}/libraries/v1/malware/blocklist`;
const MALWARE_EPOCH = '2026-01-01T00:00:00Z';

// Generic console-api GET with 401→chainctl-refresh and transient-5xx/429 retry.
async function consoleApiGet(path, params, ctx = '') {
  const qs = params ? `?${params}` : '';
  for (let attempt = 1; ; attempt++) {
    let res = await fetch(`${CONSOLE_API_BASE}${path}${qs}`, { headers: { Authorization: `Bearer ${platformToken}` } });
    if (res.status === 401) {
      const refreshed = await refreshPlatformTokenViaChainctl();
      if (!refreshed) throw new Error(`HTTP 401 from console-api (${ctx}) — token refresh failed`);
      res = await fetch(`${CONSOLE_API_BASE}${path}${qs}`, { headers: { Authorization: `Bearer ${platformToken}` } });
    }
    if (res.ok) return res.json();
    if ((res.status >= 500 || res.status === 429) && attempt <= 3) { await new Promise(r => setTimeout(r, 1000 * attempt)); continue; }
    const body = await res.text().catch(() => '');
    throw new Error(`HTTP ${res.status} from console-api (${ctx})${body ? `: ${body.slice(0, 200)}` : ''}`);
  }
}

// ── Libraries cooldown policy ───────────────────────────────────────────────
// Chainguard withholds package versions younger than a per-ecosystem "cooldown"
// window (age_days < cooldown_days). The window comes from the org's policy
// bindings; we resolve it once and cache it so the UI can badge in-cooldown
// versions. Set LIBRARIES_ORG to the org name or group UIDP to enable this;
// when unset the cooldown feature is simply off (no badges).
const LIBRARIES_ORG = process.env.LIBRARIES_ORG || null;
const POLICY_ECO_MAP = { JAVASCRIPT: 'npm', PYTHON: 'pypi', JAVA: 'maven' };
const POLICY_TTL = 5 * 60 * 1000;
let policyCache = { at: 0, data: null };

async function resolveLibrariesParent() {
  if (/^[0-9a-f]{40}$/i.test(LIBRARIES_ORG)) return LIBRARIES_ORG;
  const data = await consoleApiGet('/iam/v1/groups', new URLSearchParams({ name: LIBRARIES_ORG }), 'group resolve');
  return (data.items || []).find(g => g.name === LIBRARIES_ORG)?.id || null;
}

async function librariesPolicyData() {
  if (policyCache.data && Date.now() - policyCache.at < POLICY_TTL) return policyCache.data;
  const result = { enabled: false, org: LIBRARIES_ORG, ecosystems: {} };
  if (!LIBRARIES_ORG) return result; // no org configured → feature off
  if (!platformToken) return result; // no token → feature off (don't cache)
  try {
    const parent = await resolveLibrariesParent();
    if (!parent) { console.warn(`[libraries-policy] could not resolve org '${LIBRARIES_ORG}'`); return result; }
    const [bindings, policies] = await Promise.all([
      consoleApiGet('/libraries/v1/policy-bindings', new URLSearchParams({ parent_id: parent }), 'policy-bindings'),
      consoleApiGet('/libraries/v1/policies', new URLSearchParams({ parent_id: parent }), 'policies'),
    ]);
    const byId = new Map((policies.items || []).map(p => [p.id, p]));
    for (const b of (bindings.items || [])) {
      const eco = POLICY_ECO_MAP[b.ecosystem];
      if (!eco) continue;
      const pol = byId.get(b.policy);
      result.ecosystems[eco] = {
        cooldownDays: pol?.cooldownDays ?? 7, // Chainguard system default when unset; 0 disables
        policyName: pol?.name || null,
        mode: (b.mode || '').replace('LIBRARY_POLICY_BINDING_MODE_', ''),
      };
    }
    result.enabled = true;
    result.parent = parent;
    policyCache = { at: Date.now(), data: result };
  } catch (err) {
    console.error('[libraries-policy] fetch failed:', err.message);
  }
  return result;
}

// Parse a Package URL (purl) -> { type, name, version }; handles percent-encoded
// scoped npm names and maven namespace/name joined with '/'.
function parsePurl(purl) {
  const m = /^pkg:([^/]+)\/(.+)$/.exec(purl || '');
  if (!m) return null;
  const rest = m[2].split('?')[0];
  const at = rest.lastIndexOf('@');
  if (at < 0) return null;
  return { type: m[1], name: decodeURIComponent(rest.slice(0, at)), version: decodeURIComponent(rest.slice(at + 1)) };
}
// Canonicalise a package name so maven's group:artifact and purl's group/artifact compare equal.
const canonName = n => (n || '').replace(/[:/]+/g, '/');

// Authoritative per-version unblock times from the org's own blocked-pull events
// (cooldown reason only). Sparse - only versions the org actually pulled. 60s memo.
const AUTH_COOLDOWN_TTL = 60 * 1000;
const POLICY_ENUM = { npm: 'JAVASCRIPT', pypi: 'PYTHON', maven: 'JAVA' };
const authCooldownCache = new Map(); // `${eco} ${pkg}` -> { at, map }
async function authoritativeCooldown(eco, pkg) {
  if (!LIBRARIES_ORG || !platformToken || !pkg) return {};
  const cacheKey = `${eco} ${pkg}`;
  const hit = authCooldownCache.get(cacheKey);
  if (hit && Date.now() - hit.at < AUTH_COOLDOWN_TTL) return hit.map;
  const map = {};
  try {
    const parent = await resolveLibrariesParent();
    if (!parent) return map;
    const filterName = eco === 'maven' ? pkg.split(':').pop() : pkg; // purl name = artifactId for maven
    const data = await consoleApiGet('/libraries/v1/blocked-packages',
      new URLSearchParams({ parent_id: parent, package_name: filterName, page_size: '1000' }), `blocked ${eco} ${pkg}`);
    const want = canonName(pkg);
    for (const it of (data.items || [])) {
      if (it.reason !== 'cooldown' || !it.unblocksAt) continue;
      if (POLICY_ENUM[eco] && it.ecosystem && it.ecosystem !== POLICY_ENUM[eco]) continue;
      const p = parsePurl(it.purl);
      if (!p || canonName(p.name) !== want) continue;
      map[p.version] = it.unblocksAt;
    }
    authCooldownCache.set(cacheKey, { at: Date.now(), map });
  } catch (err) {
    console.error(`[cooldown] blocked-packages fetch failed for ${eco} ${pkg}: ${err.message}`);
  }
  return map;
}

// Identity key matching the malware PRIMARY KEY (normalised the same way insertItems stores).
const malKey = (pkg, ver, malid, blockedAt) => `${pkg} ${ver ?? ''} ${malid ?? ''} ${blockedAt}`;

// GET one blocklist page with 401→chainctl-refresh and transient-5xx/429 retry. Returns parsed JSON.
async function malwareApiGet(params, ctx = '') {
  for (let attempt = 1; ; attempt++) {
    let res = await fetch(`${MALWARE_API_BASE}?${params}`, { headers: { Authorization: `Bearer ${platformToken}` } });
    if (res.status === 401) {
      console.log(`Token expired mid-sync${ctx ? ` (${ctx})` : ''}, attempting chainctl refresh…`);
      const refreshed = await refreshPlatformTokenViaChainctl();
      if (!refreshed) throw new Error('HTTP 401 from Platform API — token expired and chainctl refresh failed');
      res = await fetch(`${MALWARE_API_BASE}?${params}`, { headers: { Authorization: `Bearer ${platformToken}` } });
    }
    if (res.ok) return res.json();

    // Non-OK: capture body + context so recurrences are diagnosable.
    const bodyText = await res.text().catch(() => '<unreadable body>');
    const reqId = res.headers.get('x-request-id') || res.headers.get('x-amzn-requestid') || res.headers.get('cf-ray') || null;
    console.error(`[malware-sync] HTTP ${res.status} from Platform API — ${ctx}${reqId ? ` reqId=${reqId}` : ''}\n  url:  ${MALWARE_API_BASE}?${params}\n  body: ${bodyText.slice(0, 1000)}`);
    if ((res.status >= 500 || res.status === 429) && attempt <= 3) {
      const backoff = 1000 * attempt;
      console.warn(`[malware-sync] transient ${res.status}, retrying in ${backoff}ms (attempt ${attempt}/3)…`);
      await new Promise(r => setTimeout(r, backoff));
      continue;
    }
    let msg = `HTTP ${res.status} from Platform API`;
    if (bodyText && bodyText !== '<unreadable body>') msg += `: ${bodyText.slice(0, 300)}`;
    throw new Error(msg);
  }
}

// Authoritative count of entries with blocked_at >= since (the API respects `since`, ignores `until`).
async function malwareTotalCountSince(apiName, since) {
  const data = await malwareApiGet(new URLSearchParams({ ecosystem: apiName, pageSize: '1', since }), `${apiName} count ${since.slice(0, 10)}`);
  return Number(data.totalCount || 0);
}

// Page through every entry with blocked_at >= since (newest-first), invoking onPage(items) per page.
async function malwarePageThrough(apiName, since, onPage) {
  let pageToken = null;
  while (!syncState.cancelled) {
    const params = new URLSearchParams({ ecosystem: apiName, pageSize: '500', since });
    if (pageToken) params.set('pageToken', pageToken);
    const data = await malwareApiGet(params, `${apiName} since=${since}`);
    const items = data.items || [];
    onPage(items);
    if (!data.nextPageToken || items.length === 0) break;
    pageToken = data.nextPageToken;
  }
}

// Monthly boundaries [epoch, …, now+1d] used to localise which month(s) changed.
function malwareMonthBoundaries() {
  const bs = [];
  let cursor = new Date(MALWARE_EPOCH);
  const end = new Date(Date.now() + 86400000);
  while (cursor < end) { bs.push(cursor.toISOString()); const n = new Date(cursor); n.setUTCMonth(n.getUTCMonth() + 1); cursor = n; }
  bs.push(end.toISOString());
  return bs;
}

// The delta add-pass only inserts, so upstream REMOVALS (e.g. cleared false positives)
// aren't dropped locally — and the blocklist API has no removal/updated_at feed. We detect
// them by comparing counts within a recent HORIZON window only (removals are recent):
//   - Windowing (not global totals) avoids re-triggering forever on ancient drift and on
//     totalCount noise, which fluctuates ±tens on the live ~351k npm feed.
//   - A small margin absorbs that noise + the add-pass racing the live feed, so only a
//     genuine removal batch (local exceeding upstream in-window beyond the noise) reconciles.
// When it does fire, it re-fetches [horizon → now], upserts (preserves published_at), and
// deletes any local row in-window absent upstream. Older drift is a job for a full resync.
async function reconcileMalwareRemovals(apiName, dbName) {
  const HORIZON_DAYS = 21;
  const horizon = new Date(Date.now() - HORIZON_DAYS * 86400000).toISOString();
  const upstreamRecent = await malwareTotalCountSince(apiName, horizon);
  const localRecent = db.prepare(`SELECT COUNT(*) AS n FROM malware WHERE ecosystem = ? AND blocked_at >= ?`).get(dbName, horizon).n;
  const margin = Math.max(25, Math.round(upstreamRecent * 0.001));
  // local exceeding upstream in-window beyond the noise margin ⇒ real removals to reconcile.
  // Otherwise it's just new adds / count jitter → nothing to do (add-pass handles adds).
  if (localRecent <= upstreamRecent + margin) return;

  const repairFrom = horizon;
  const expected = upstreamRecent;
  console.log(`[${dbName}] reconcile: recent-window local ${localRecent} > upstream ${upstreamRecent} (+${margin} margin) — re-syncing ${repairFrom.slice(0, 10)} → now`);

  // Fetch the repair range. CRITICAL: only proceed to the delete step if the page-through
  // was COMPLETE — an incomplete fetch (e.g. truncated by a mid-flight token refresh) would
  // make us delete rows that actually exist upstream. Verify fetched vs expected; retry on short.
  const tolerance = Math.max(20, Math.round(expected * 0.01));
  let upstreamKeys = null;
  for (let attempt = 1; attempt <= 3 && !syncState.cancelled; attempt++) {
    await ensurePlatformTokenFresh(); // avoid a mid-page-through 401 on long ranges
    const keys = new Set();
    await malwarePageThrough(apiName, repairFrom, (items) => {
      for (const it of items) keys.add(malKey(it.packageName, it.version, it.malid, it.blockedAt));
      insertItems(items, dbName);
    });
    if (syncState.cancelled) return;
    console.log(`[${dbName}] reconcile: fetched ${keys.size} unique keys (expected ~${expected}, gate ${expected - tolerance}) attempt ${attempt}`);
    if (keys.size >= expected - tolerance) { upstreamKeys = keys; break; }
    console.warn(`[${dbName}] reconcile: fetched ${keys.size} < expected ${expected} (attempt ${attempt}/3) — retrying before delete`);
  }
  if (!upstreamKeys) {
    // Never delete against an incomplete set — leave the (already-upserted) adds and bail.
    console.error(`[${dbName}] reconcile: fetch stayed short after retries — skipping delete to avoid over-removal; will retry next sync`);
    return;
  }

  const localRows = db.prepare(`SELECT package_name, version, malid, blocked_at FROM malware WHERE ecosystem = ? AND blocked_at >= ?`).all(dbName, repairFrom);
  const delStmt = db.prepare(`DELETE FROM malware WHERE ecosystem = ? AND package_name = ? AND version = ? AND malid = ? AND blocked_at = ?`);
  let removed = 0;
  db.transaction(() => {
    for (const r of localRows) {
      if (!upstreamKeys.has(malKey(r.package_name, r.version, r.malid, r.blocked_at))) {
        delStmt.run(dbName, r.package_name, r.version, r.malid, r.blocked_at);
        removed++;
      }
    }
  })();
  console.log(`[${dbName}] reconcile: removed ${removed} stale record(s)`);
}

// Lazy per-package reconcile. The blocklist API has no removal feed, so a lone
// cleared entry (below the batch-reconcile noise margin) can linger locally until
// a full resync. But the API filters by packageName, so we can cheaply verify one
// package on demand: fetch its upstream entries, upsert them (ON CONFLICT preserves
// published_at), and drop any local row for that package no longer upstream. This
// self-heals the interactive "I'm looking at package X" case without a full sync.
// Best-effort: throws on API failure so the caller can fall back to local rows.
// A short per-(eco,pkg) TTL avoids hammering the API on repeat views.
const PKG_RECONCILE_TTL = 5 * 60 * 1000;
const pkgReconciledAt = new Map(); // `${ecoDbName} ${pkg}` → last-reconciled epoch ms

// Fetch every upstream blocklist entry for one package (paginated).
async function fetchPackageBlocklist(apiName, pkg) {
  const items = [];
  let pageToken = null;
  do {
    const params = new URLSearchParams({ ecosystem: apiName, packageName: pkg, pageSize: '500' });
    if (pageToken) params.set('pageToken', pageToken);
    const data = await malwareApiGet(params, `pkg-check ${apiName} ${pkg}`);
    for (const it of (data.items || [])) items.push(it);
    pageToken = data.nextPageToken || null;
  } while (pageToken);
  return items;
}

// Live, read-only per-package lookup used while the mirror is cold (first fill in
// progress) so the UI shows correct results immediately instead of sparse local
// data. Returns rows in the same shape as the DB read path. 60s memo.
const LIVE_LOOKUP_TTL = 60 * 1000;
const liveLookupCache = new Map(); // `${dbName} ${pkg}` -> { at, rows }
async function liveMalwareLookup(dbName, apiName, pkg) {
  if (!platformToken || !pkg) return null;
  const key = `${dbName} ${pkg}`;
  const hit = liveLookupCache.get(key);
  if (hit && Date.now() - hit.at < LIVE_LOOKUP_TTL) return hit.rows;
  const items = await fetchPackageBlocklist(apiName, pkg);
  const rows = items.map(it => ({
    package_name: it.packageName, version: it.version ?? '', scope: normScope(it.scope),
    malid: it.malid ?? '', source: it.source ?? null, blocked_at: it.blockedAt,
    reason: it.reason || [], description: it.description ?? null,
  }));
  liveLookupCache.set(key, { at: Date.now(), rows });
  return rows;
}

async function reconcilePackage(ecoDbName, apiName, pkg) {
  // Skip when unauthenticated (avoid a chainctl mint storm on the read path) or
  // mid-sync (the running sync is already rewriting this ecosystem).
  if (!platformToken || !pkg || syncState.running) return;
  const cacheKey = `${ecoDbName} ${pkg}`;
  const last = pkgReconciledAt.get(cacheKey);
  if (last && Date.now() - last < PKG_RECONCILE_TTL) return;

  // Fetch every upstream entry for this package (paginated — single packages are
  // usually one page, but long histories can exceed pageSize).
  const items = await fetchPackageBlocklist(apiName, pkg);
  const upstreamKeys = new Set(items.map(it => malKey(it.packageName, it.version, it.malid, it.blockedAt)));

  // Reached only if the full page-through succeeded (malwareApiGet throws otherwise),
  // so upstreamKeys is complete and safe to delete against.
  const localRows = db.prepare(`SELECT version, malid, blocked_at FROM malware WHERE ecosystem = ? AND package_name = ?`).all(ecoDbName, pkg);
  const delStmt = db.prepare(`DELETE FROM malware WHERE ecosystem = ? AND package_name = ? AND version = ? AND malid = ? AND blocked_at = ?`);
  let inserted = 0, removed = 0;
  db.transaction(() => {
    for (const it of items) {
      const res = insertMalware.run(
        it.packageName, it.version ?? '', normScope(it.scope), it.malid ?? '',
        it.source ?? null, it.blockedAt, ecoDbName,
        JSON.stringify(it.reason || []), it.description ?? null,
      );
      if (res.changes) inserted++;
    }
    for (const r of localRows) {
      if (!upstreamKeys.has(malKey(pkg, r.version, r.malid, r.blocked_at))) {
        delStmt.run(ecoDbName, pkg, r.version, r.malid, r.blocked_at);
        removed++;
      }
    }
  })();
  pkgReconciledAt.set(cacheKey, Date.now());
  if (removed || inserted) console.log(`[pkg-check] reconciled ${ecoDbName} ${pkg}: +${inserted} upserted, -${removed} stale`);
}

async function runMalwareSync({ token, full = false }) {
  if (syncState.running) throw new Error('Sync already in progress');
  if (!token) throw new Error('No platform token available');
  Object.assign(syncState, {
    running: true, fetched: 0, total: 0, error: null,
    startedAt: new Date().toISOString(), finishedAt: null,
    windowsDone: 0, windowsTotal: 0, cancelled: false, expectedTotal: 0,
  });
  await ensurePlatformTokenFresh(); // avoid a mid-sync 401 truncating a page-through

  // For a full/cold rebuild, probe the upstream total up front so /readyz can
  // report a warmup percentage/ETA. Cheap (one pageSize=1 call per ecosystem);
  // skipped for delta syncs where it isn't worth the latency.
  if (full || !malwareWarm) {
    try {
      let expected = 0;
      for (const { apiName } of PLATFORM_ECOSYSTEMS) expected += await malwareTotalCountSince(apiName, MALWARE_EPOCH);
      syncState.expectedTotal = expected;
    } catch { /* best-effort; percentage just stays unknown */ }
  }

  async function syncOneEcosystem({ apiName, dbName }) {
    if (syncState.cancelled) return;
    let savedPubDates = null;
    if (full) {
      savedPubDates = db.prepare(`SELECT package_name, version, published_at FROM malware WHERE ecosystem = ? AND published_at IS NOT NULL`).all(dbName);
      db.prepare(`DELETE FROM malware WHERE ecosystem = ?`).run(dbName);
    }

    // Add-pass: first sync (or full) pulls everything since the epoch; later syncs pull
    // only entries newer than our latest known blocked_at. (API is newest-first, `since`
    // inclusive, `until` ignored.)
    const latest = full ? null : db.prepare(`SELECT MAX(blocked_at) AS m FROM malware WHERE ecosystem = ?`).get(dbName)?.m;
    syncState.windowsTotal += 1;
    await malwarePageThrough(apiName, latest || MALWARE_EPOCH, (items) => insertItems(items, dbName));
    syncState.windowsDone += 1;

    // Reconcile removals (skipped implicitly on `full` since the add-pass already rebuilt the set).
    if (!syncState.cancelled) await reconcileMalwareRemovals(apiName, dbName);

    if (full && savedPubDates?.length) {
      const restoreStmt = db.prepare(`UPDATE malware SET published_at = ? WHERE ecosystem = ? AND package_name = ? AND version = ?`);
      db.transaction(() => { for (const row of savedPubDates) restoreStmt.run(row.published_at, dbName, row.package_name, row.version); })();
    }
  }

  try {
    // Ecosystems run sequentially — the blocklist API's pagination cursors proved
    // unreliable when several page-throughs ran concurrently (crossed/short reads).
    for (const eco of PLATFORM_ECOSYSTEMS) {
      if (syncState.cancelled) break;
      await syncOneEcosystem(eco);
    }
    db.prepare(`INSERT OR REPLACE INTO sync_meta (key, value) VALUES ('last_sync_at', ?)`).run(new Date().toISOString());
    if (!syncState.cancelled) malwareWarm = true; // mirror is now usable from local
    // Always fetch publish dates after a sync — the enrich pass only touches rows
    // with published_at IS NULL, so this is a no-op once everything is enriched.
    // Fire-and-forget; progress is exposed via /api/cgr-malware/enrich/status.
    if (!syncState.cancelled && !enrichState.running) {
      runMalwareEnrich().catch(err => console.error('[malware-sync] auto-enrich failed:', err.message));
    }
  } catch (err) {
    syncState.error = err.message;
    throw err;
  } finally {
    syncState.running = false;
    syncState.finishedAt = new Date().toISOString();
  }
}

// ── Scheduled sync ──────────────────────────────────────────────────────────
// Daily full resync at 03:00 (server-local time; set the TZ env var to control
// the zone). Disable with MALWARE_AUTOSYNC=off.
async function triggerScheduledSync({ full }) {
  const kind = full ? 'full' : 'delta';
  if (syncState.running) { console.log(`[scheduler] ${kind} sync skipped — a sync is already running`); return; }
  await ensurePlatformTokenFresh();
  if (!platformToken) { console.warn(`[scheduler] ${kind} sync skipped — no platform token (chainctl/OIDC or paste one)`); return; }
  try {
    console.log(`[scheduler] starting ${kind} sync`);
    await runMalwareSync({ token: platformToken, full }); // auto-enriches on success
    console.log(`[scheduler] ${kind} sync finished`);
  } catch (err) {
    console.error(`[scheduler] ${kind} sync failed:`, err.message);
  }
}

function scheduleMalwareJobs() {
  if ((process.env.MALWARE_AUTOSYNC || '').toLowerCase() === 'off') {
    console.log('[scheduler] auto-sync disabled (MALWARE_AUTOSYNC=off)');
    return;
  }
  // Daily full resync at 03:00 local time; reschedule after each run so it
  // survives DST shifts and doesn't drift.
  const scheduleDailyFull = () => {
    const now = new Date();
    const next = new Date(now);
    next.setHours(3, 0, 0, 0);
    if (next <= now) next.setDate(next.getDate() + 1);
    const delay = next - now;
    console.log(`[scheduler] next full resync at ${next.toString()} (in ${Math.round(delay / 60000)} min)`);
    setTimeout(async () => {
      await triggerScheduledSync({ full: true });
      scheduleDailyFull();
    }, delay);
  };
  scheduleDailyFull();
}
scheduleMalwareJobs();

const statsCache = new Map(); // key → { result, expiresAt }
const STATS_TTL = 30000; // 30 seconds

Bun.serve({
  port: Number(process.env.PORT) || 3000,
  idleTimeout: 60,
  async fetch(req) {
    const url = new URL(req.url);

    if (url.pathname === '/') {
      return new Response(Bun.file(htmlPath), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    // Readiness / warmup probe. 200 once the mirror is warm (usable from local),
    // 503 while the first fill is still in progress; reports percent/ETA.
    if (url.pathname === '/readyz') {
      const total = db.prepare(`SELECT COUNT(*) AS n FROM malware`).get().n;
      const expected = syncState.expectedTotal || 0;
      const percent = malwareWarm ? 100 : (expected ? Math.min(99, Math.round(syncState.fetched / expected * 100)) : 0);
      let etaSeconds = null;
      if (!malwareWarm && syncState.running && expected && syncState.startedAt) {
        const elapsed = (Date.now() - Date.parse(syncState.startedAt)) / 1000;
        const rate = syncState.fetched / Math.max(1, elapsed); // rows/sec
        if (rate > 0) etaSeconds = Math.round((expected - syncState.fetched) / rate);
      }
      const body = { warm: malwareWarm, syncing: syncState.running, fetched: syncState.fetched, expectedTotal: expected || null, percent, etaSeconds, total };
      return new Response(JSON.stringify(body), { status: malwareWarm ? 200 : 503, headers: { 'Content-Type': 'application/json' } });
    }

    // npm / JS proxy
    if (url.pathname.startsWith('/api/cgr/')) {
      const pkg = url.pathname.slice('/api/cgr/'.length);
      const upstream = `https://libraries.cgr.dev/javascript/${pkg}`;
      const headers = await cgrHeaders(req);
      try {
        const res = await fetch(upstream, { headers });
        const body = await res.text();
        return new Response(body, { status: res.status, headers: { 'Content-Type': 'application/json' } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // CGR authenticated download proxy (streams tarball back as attachment)
    if (url.pathname.startsWith('/api/cgr-download/')) {
      const path = url.pathname.slice('/api/cgr-download/'.length);
      const upstream = `https://libraries.cgr.dev/${path}`;
      const headers = await cgrHeaders(req);
      try {
        const res = await fetch(upstream, { headers });
        const filename = path.split('/').pop() || 'download';
        const respHeaders = {
          'Content-Type': res.headers.get('content-type') || 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${filename}"`,
        };
        const len = res.headers.get('content-length');
        if (len) respHeaders['Content-Length'] = len;
        return new Response(res.body, { status: res.status, headers: respHeaders });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // CGR npm attestations proxy
    if (url.pathname.startsWith('/api/cgr-attestations/')) {
      const path = url.pathname.slice('/api/cgr-attestations/'.length);
      const upstream = `https://libraries.cgr.dev/javascript/-/npm/v1/attestations/${path}`;
      const headers = await cgrHeaders(req);
      try {
        const res = await fetch(upstream, { headers });
        const body = await res.text();
        return new Response(body, { status: res.status, headers: { 'Content-Type': 'application/json' } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // npm attestation verification (fetch + cryptographic verify via sigstore)
    if (url.pathname === '/api/verify-attestation') {
      const pkg = url.searchParams.get('pkg');
      const version = url.searchParams.get('version');
      if (!pkg || !version) return new Response('Missing pkg or version', { status: 400 });
      const cgrAuthHeaders = await cgrHeaders(req);
      const pkgVer = `${pkg}@${version}`;

      function extractCommitFromPayload(payload, predicateType) {
        let commit = null, uri = null;
        if (predicateType === 'https://slsa.dev/provenance/v1') {
          const deps = payload.predicate?.buildDefinition?.resolvedDependencies ?? [];
          for (const dep of deps) {
            if (dep?.digest?.gitCommit && dep?.uri) { commit = dep.digest.gitCommit; uri = dep.uri; break; }
          }
        } else if (predicateType === 'https://slsa.dev/provenance/v0.2') {
          const src = payload.predicate?.invocation?.configSource ?? payload.predicate?.materials?.[0];
          commit = src?.digest?.sha1 ?? src?.digest?.gitCommit ?? null;
          uri = src?.uri ?? null;
        }
        if (!commit || !uri) return { commitUrl: null, shortSha: null };
        let repoUrl = null;
        const purlMatch = uri.match(/^pkg:github\/([^@]+)/);
        if (purlMatch) {
          repoUrl = `https://github.com/${purlMatch[1]}`;
        } else {
          const candidate = uri.replace(/^git\+/, '').replace(/@.*$/, '');
          if (/^https:\/\/(github|gitlab|bitbucket)\.com\//.test(candidate)) repoUrl = candidate;
        }
        return repoUrl
          ? { commitUrl: `${repoUrl}/commit/${commit}`, shortSha: commit.slice(0, 7) }
          : { commitUrl: null, shortSha: null };
      }

      async function processAttestations(data) {
        if (!data?.attestations?.length) return { hasAttestation: false };
        const SLSA_TYPES = new Set(['https://slsa.dev/provenance/v1', 'https://slsa.dev/provenance/v0.2']);
        for (const att of data.attestations) {
          if (!SLSA_TYPES.has(att.predicateType)) continue;

          let commitUrl = null, shortSha = null;
          try {
            const payload = JSON.parse(Buffer.from(att.bundle.dsseEnvelope.payload, 'base64').toString());
            ({ commitUrl, shortSha } = extractCommitFromPayload(payload, att.predicateType));
          } catch {}

          let verified = false, identity = null, tlogIndex = null;
          try {
            const certBytes = att.bundle.verificationMaterial?.certificate?.rawBytes
              ?? att.bundle.verificationMaterial?.x509CertificateChain?.certificates?.[0]?.rawBytes;
            if (certBytes) {
              const certDer = Buffer.from(certBytes, 'base64');
              const pemCert = '-----BEGIN CERTIFICATE-----\n' + certDer.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n';
              const pubKey = createPublicKey({ key: pemCert, format: 'pem' });
              const x509 = new X509Certificate(certDer);
              const dsse = att.bundle.dsseEnvelope;
              const payloadBuf = Buffer.from(dsse.payload, 'base64');
              const pae = Buffer.concat([
                Buffer.from(`DSSEv1 ${dsse.payloadType.length} ${dsse.payloadType} ${payloadBuf.length} `),
                payloadBuf,
              ]);
              const sigBuf = Buffer.from(dsse.signatures[0].sig, 'base64');
              if (cryptoVerify('SHA256', pae, pubKey, sigBuf) && x509.issuer?.includes('sigstore')) {
                verified = true;
                const san = x509.subjectAltName || '';
                const uriMatch = san.match(/URI:([^\s,]+)/);
                identity = uriMatch ? uriMatch[1] : null;
                tlogIndex = att.bundle.verificationMaterial?.tlogEntries?.[0]?.logIndex ?? null;
              }
            }
          } catch {}

          return { hasAttestation: true, verified, commitUrl, shortSha, identity, tlogIndex };
        }
        // No SLSA attestation found — only show badge if non-npm-publish types exist
        const NPM_PUBLISH = 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1';
        return data.attestations.some(att => att.predicateType !== NPM_PUBLISH)
          ? { hasAttestation: true, verified: false, commitUrl: null, shortSha: null, identity: null }
          : { hasAttestation: false };
      }

      try {
        const [npmRes, cgrRes] = await Promise.allSettled([
          fetch(`https://registry.npmjs.org/-/npm/v1/attestations/${pkgVer}`).then(r => r.ok ? r.json() : null).catch(() => null),
          fetch(`https://libraries.cgr.dev/javascript/-/npm/v1/attestations/${pkgVer}`, { headers: cgrAuthHeaders }).then(r => r.ok ? r.json() : null).catch(() => null),
        ]);
        const [npmResult, cgrResult] = await Promise.all([
          processAttestations(npmRes.status === 'fulfilled' ? npmRes.value : null),
          processAttestations(cgrRes.status === 'fulfilled' ? cgrRes.value : null),
        ]);
        return new Response(JSON.stringify({ npm: npmResult, cgr: cgrResult }), { headers: { 'Content-Type': 'application/json' } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // Maven metadata
    if (url.pathname === '/api/maven-metadata') {
      const group = url.searchParams.get('group');
      const artifact = url.searchParams.get('artifact');
      if (!group || !artifact) return new Response('Missing group or artifact', { status: 400 });
      const groupPath = group.replace(/\./g, '/');
      const upstream = `https://repo1.maven.org/maven2/${groupPath}/${artifact}/maven-metadata.xml`;
      try {
        const res = await fetch(upstream, { headers: { 'User-Agent': 'maven-browser/1.0', 'Accept': 'application/xml, */*' } });
        const body = await res.text();
        return new Response(body, { status: res.status, headers: { 'Content-Type': 'application/xml' } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // Maven timestamps (search.maven.org Solr)
    if (url.pathname === '/api/maven-timestamps') {
      const group = url.searchParams.get('group');
      const artifact = url.searchParams.get('artifact');
      const start = parseInt(url.searchParams.get('start') || '0', 10);
      if (!group || !artifact) return new Response('Missing group or artifact', { status: 400 });
      const q = encodeURIComponent(`g:${group} AND a:${artifact}`);
      const upstream = `https://search.maven.org/solrsearch/select?q=${q}&core=gav&rows=200&start=${start}&sort=timestamp+desc&wt=json`;
      try {
        const res = await fetch(upstream);
        const body = await res.text();
        return new Response(body, { status: res.status, headers: { 'Content-Type': 'application/json' } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // Maven fallback dates via HEAD on POM files
    if (url.pathname === '/api/maven-dates' && req.method === 'POST') {
      const { group, artifact, versions } = await req.json();
      if (!group || !artifact || !Array.isArray(versions)) return new Response('Bad request', { status: 400 });
      const groupPath = group.replace(/\./g, '/');
      const results = await Promise.all(
        versions.map(async v => {
          const pomUrl = `https://repo1.maven.org/maven2/${groupPath}/${artifact}/${v}/${artifact}-${v}.pom`;
          try {
            const res = await fetch(pomUrl, { method: 'HEAD', headers: { 'User-Agent': 'maven-browser/1.0' } });
            const lastModified = res.headers.get('last-modified');
            return [v, lastModified ? new Date(lastModified).getTime() : null];
          } catch {
            return [v, null];
          }
        })
      );
      return new Response(JSON.stringify(Object.fromEntries(results)), { headers: { 'Content-Type': 'application/json' } });
    }

    // Maven / Java CGR proxy
    if (url.pathname === '/api/cgr-java') {
      const group = url.searchParams.get('group');
      const artifact = url.searchParams.get('artifact');
      const repo = url.searchParams.get('repo') || 'java';
      if (!group || !artifact) return new Response('Missing group or artifact', { status: 400 });
      const groupPath = group.replace(/\./g, '/');
      const upstream = `https://libraries.cgr.dev/${repo}/${groupPath}/${artifact}/maven-metadata.xml`;
      const headers = await cgrHeaders(req);
      try {
        const res = await fetch(upstream, { headers });
        const body = await res.text();
        return new Response(body, { status: res.status, headers: { 'Content-Type': 'application/xml' } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // Maven built-from-source versions via the Libraries catalog (console-api).
    // This is the authoritative source of what Chainguard actually builds from
    // source; the /java/ and /java-upstream/ maven-metadata.xml are a merged
    // serving view and cannot distinguish built vs proxied. Uses the platform
    // token (audience console-api.enforce.dev) — same one malware sync uses.
    if (url.pathname === '/api/cgr-java-catalog') {
      const group = url.searchParams.get('group');
      const artifact = url.searchParams.get('artifact');
      if (!group || !artifact) return new Response('Missing group or artifact', { status: 400 });
      if (!platformToken) {
        return new Response(JSON.stringify({ versions: [], authRequired: true }), { headers: { 'Content-Type': 'application/json' } });
      }
      const id = `maven:${group}:${artifact}`;
      const base = `https://console-api.enforce.dev/libraries/v1/artifacts/${encodeURIComponent(id)}/versions`;
      try {
        const versions = [];
        let pageToken = '';
        for (let i = 0; i < 50; i++) { // safety cap against a runaway paging loop
          const params = new URLSearchParams({ page_size: '1000' });
          if (pageToken) params.set('page_token', pageToken);
          const res = await fetch(`${base}?${params}`, { headers: { Authorization: `Bearer ${platformToken}` } });
          if (res.status === 404) break; // not in catalog → no built-from-source versions
          if (!res.ok) {
            const text = await res.text();
            return new Response(JSON.stringify({ versions: [], error: `console-api HTTP ${res.status}: ${text.slice(0, 200)}` }), { status: 502, headers: { 'Content-Type': 'application/json' } });
          }
          const data = await res.json();
          for (const it of (data.items || [])) if (it.version) versions.push(it.version);
          pageToken = data.nextPageToken || data.next_page_token || '';
          if (!pageToken) break;
        }
        return new Response(JSON.stringify({ versions }), { headers: { 'Content-Type': 'application/json' } });
      } catch (err) {
        return new Response(JSON.stringify({ versions: [], error: err.message }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // PyPI / Python CGR proxy — PEP 503 simple index
    if (url.pathname.startsWith('/api/cgr-python/')) {
      const path = url.pathname.slice('/api/cgr-python/'.length);
      const upstream = `https://libraries.cgr.dev/python/${path}`;
      const headers = await cgrHeaders(req);
      try {
        const res = await fetch(upstream, { headers });
        const body = await res.text();
        const ct = res.headers.get('content-type') || 'text/html';
        return new Response(body, { status: res.status, headers: { 'Content-Type': ct } });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // Malware cache status
    if (url.pathname === '/api/cgr-malware/status') {
      return new Response(JSON.stringify(malwareStatus()), { headers: { 'Content-Type': 'application/json' } });
    }

    // Per-ecosystem cooldown windows (from the org's Libraries policy bindings),
    // used by the UI to badge versions still within their cooldown period.
    if (url.pathname === '/api/libraries/policy') {
      return new Response(JSON.stringify(await librariesPolicyData()), { headers: { 'Content-Type': 'application/json' } });
    }

    // Platform token management
    if (url.pathname === '/api/platform-token' && req.method === 'POST') {
      const body = await req.json().catch(() => ({}));
      const token = (body.token || '').trim();
      if (token && !tokenAudienceOk(token)) {
        const auds = parsePlatformTokenAudiences(token);
        return new Response(JSON.stringify({
          error: `Token has wrong audience (${auds ? auds.join(', ') : 'none'}). ` +
                 `Mint one with: chainctl auth token --audience ${EXPECTED_TOKEN_AUDIENCE}`,
        }), { status: 400, headers: { 'Content-Type': 'application/json' } });
      }
      setPlatformToken(token || null);
      return new Response(JSON.stringify({ ok: true, status: malwareStatus().platformToken }), { headers: { 'Content-Type': 'application/json' } });
    }

    if (url.pathname === '/api/platform-token/refresh' && req.method === 'POST') {
      const token = await refreshPlatformTokenViaChainctl();
      if (!token) return new Response(JSON.stringify({ error: 'chainctl refresh failed — check server logs' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
      return new Response(JSON.stringify({ ok: true, status: malwareStatus().platformToken }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Malware cache sync (fire-and-forget). Server kicks off the sync in the
    // background; client polls /api/cgr-malware/status for progress.
    if (url.pathname === '/api/cgr-malware/sync' && req.method === 'POST') {
      if (syncState.running) {
        return new Response(JSON.stringify({ error: 'Sync already in progress', status: malwareStatus() }), { status: 409, headers: { 'Content-Type': 'application/json' } });
      }
      const body = await req.json().catch(() => ({}));
      const full = body.full === true;
      // Client can supply a token to override the server-stored one (e.g. fresh paste from settings)
      const token = (body.platformToken || '').trim() || platformToken;
      if (body.platformToken?.trim()) setPlatformToken(body.platformToken.trim());
      if (!token) return new Response(JSON.stringify({ error: 'No platform token set — paste one in Settings first' }), { status: 401, headers: { 'Content-Type': 'application/json' } });

      runMalwareSync({ token, full }).catch(() => { /* err captured in syncState.error */ });

      return new Response(JSON.stringify({ started: true, status: malwareStatus() }), { status: 202, headers: { 'Content-Type': 'application/json' } });
    }

    if (url.pathname === '/api/cgr-malware/sync/cancel' && req.method === 'POST') {
      if (!syncState.running) {
        return new Response(JSON.stringify({ error: 'No sync running' }), { status: 409, headers: { 'Content-Type': 'application/json' } });
      }
      syncState.cancelled = true;
      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Malware enrichment (fire-and-forget).
    if (url.pathname === '/api/cgr-malware/enrich' && req.method === 'POST') {
      if (enrichState.running) {
        return new Response(JSON.stringify({ error: 'Enrichment already in progress', state: enrichState }), { status: 409, headers: { 'Content-Type': 'application/json' } });
      }
      runMalwareEnrich().catch(() => {});
      return new Response(JSON.stringify({ started: true, state: enrichState }), { status: 202, headers: { 'Content-Type': 'application/json' } });
    }

    // Enrichment status.
    if (url.pathname === '/api/cgr-malware/enrich/status') {
      const counts = db.prepare(`
        SELECT
          COUNT(*) AS total,
          COUNT(CASE WHEN published_at IS NOT NULL AND published_at NOT IN ('NOT_FOUND','ERROR') THEN 1 END) AS enriched,
          COUNT(CASE WHEN published_at IS NULL THEN 1 END) AS pending,
          COUNT(CASE WHEN published_at IN ('NOT_FOUND','ERROR') THEN 1 END) AS unavailable
        FROM malware
      `).get();
      return new Response(JSON.stringify({ ...counts, enrichState: { ...enrichState } }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Detection lag statistics (TTL-cached for 30s per unique param string).
    if (url.pathname === '/api/cgr-malware/stats') {
      const cacheKey = url.search;
      const cached = statsCache.get(cacheKey);
      if (cached && cached.expiresAt > Date.now()) {
        return new Response(cached.result, { headers: { 'Content-Type': 'application/json', 'X-Cache': 'HIT' } });
      }

      const eco   = url.searchParams.get('eco')   || '';
      const since = url.searchParams.get('since') || '';
      const until = url.searchParams.get('until') || '';

      const pub_since = url.searchParams.get('pub_since') || '';
      const pub_until = url.searchParams.get('pub_until') || '';

      const source = url.searchParams.get('source') || '';

      const where = [`published_at IS NOT NULL`, `published_at NOT IN ('NOT_FOUND','ERROR')`, `blocked_at >= published_at`];
      const args = [];
      if (eco)       { where.push('ecosystem = ?');     args.push(eco); }
      if (source)    { where.push('source = ?');        args.push(source); }
      if (since)     { where.push('blocked_at >= ?');   args.push(since); }
      if (until)     { where.push('blocked_at <  ?');   args.push(until); }
      if (pub_since) { where.push('published_at >= ?'); args.push(pub_since); }
      if (pub_until) { where.push('published_at <  ?'); args.push(pub_until); }
      const whereSql = `WHERE ${where.join(' AND ')}`;
      const lagExpr = `(julianday(blocked_at) - julianday(published_at)) * 86400.0`;

      const overall = db.prepare(
        `SELECT COUNT(*) AS n, AVG(${lagExpr}) AS mean_s, MIN(${lagExpr}) AS min_s, MAX(${lagExpr}) AS max_s FROM malware ${whereSql}`
      ).get(...args);

      const percentileRows = overall.n > 0 ? db.prepare(`
        WITH ranked AS (
          SELECT ${lagExpr} AS lag_s, ROW_NUMBER() OVER (ORDER BY ${lagExpr}) AS rn, COUNT(*) OVER () AS total
          FROM malware ${whereSql}
        )
        SELECT
          AVG(CASE WHEN rn IN ((total+1)/2, (total+2)/2) THEN lag_s END) AS median_s,
          MAX(CASE WHEN rn = CAST(CEIL(total * 0.9) AS INTEGER) THEN lag_s END) AS p90_s,
          MAX(CASE WHEN rn = CAST(CEIL(total * 0.99) AS INTEGER) THEN lag_s END) AS p99_s
        FROM ranked
      `).get(...args) : null;

      // % detected within thresholds
      const thresholds = overall.n > 0 ? db.prepare(`
        SELECT
          ROUND(100.0 * SUM(CASE WHEN ${lagExpr} < 3600    THEN 1 ELSE 0 END) / COUNT(*), 1) AS pct_1h,
          ROUND(100.0 * SUM(CASE WHEN ${lagExpr} < 10800   THEN 1 ELSE 0 END) / COUNT(*), 1) AS pct_3h,
          ROUND(100.0 * SUM(CASE WHEN ${lagExpr} < 43200   THEN 1 ELSE 0 END) / COUNT(*), 1) AS pct_12h,
          ROUND(100.0 * SUM(CASE WHEN ${lagExpr} < 86400   THEN 1 ELSE 0 END) / COUNT(*), 1) AS pct_24h,
          ROUND(100.0 * SUM(CASE WHEN ${lagExpr} < 604800  THEN 1 ELSE 0 END) / COUNT(*), 1) AS pct_7d
        FROM malware ${whereSql}
      `).get(...args) : null;

      const byEco = db.prepare(
        `SELECT ecosystem, COUNT(*) AS n, AVG(${lagExpr}) AS mean_s FROM malware ${whereSql} GROUP BY ecosystem`
      ).all(...args);

      // Histogram grouped by (bucket, source) so the UI can render stacked bars
      const BUCKET_ORDER = ['<15m','<30m','<1h','1-6h','6-24h','1-7d','7-30d','>30d'];
      const bucketExpr = `CASE
        WHEN ${lagExpr} < 900     THEN '<15m'
        WHEN ${lagExpr} < 1800    THEN '<30m'
        WHEN ${lagExpr} < 3600    THEN '<1h'
        WHEN ${lagExpr} < 21600   THEN '1-6h'
        WHEN ${lagExpr} < 86400   THEN '6-24h'
        WHEN ${lagExpr} < 604800  THEN '1-7d'
        WHEN ${lagExpr} < 2592000 THEN '7-30d'
        ELSE '>30d'
      END`;
      const histRaw = db.prepare(`
        SELECT ${bucketExpr} AS bucket, COALESCE(source, 'unknown') AS src, COUNT(*) AS n
        FROM malware ${whereSql}
        GROUP BY bucket, src
      `).all(...args);

      const histMap = {};
      for (const r of histRaw) {
        if (!histMap[r.bucket]) histMap[r.bucket] = { bucket: r.bucket, n: 0, bySource: {} };
        histMap[r.bucket].n += r.n;
        histMap[r.bucket].bySource[r.src] = r.n;
      }
      const histogram = BUCKET_ORDER
        .map(b => histMap[b] || { bucket: b, n: 0, bySource: {} })
        .filter(b => b.n > 0);

      const body = JSON.stringify({
        overall: {
          ...overall,
          median_s: percentileRows?.median_s ?? null,
          p90_s:    percentileRows?.p90_s    ?? null,
          p99_s:    percentileRows?.p99_s    ?? null,
          ...thresholds,
        },
        byEco,
        histogram,
      });
      statsCache.set(cacheKey, { result: body, expiresAt: Date.now() + STATS_TTL });
      return new Response(body, { headers: { 'Content-Type': 'application/json' } });
    }

    // Malware search (filtered, server-side).
    if (url.pathname === '/api/cgr-malware/search') {
      const eco     = url.searchParams.get('eco')     || '';
      const q       = url.searchParams.get('q')       || '';
      const ver     = url.searchParams.get('version') || '';
      const reason  = url.searchParams.get('reason')  || '';
      const src     = url.searchParams.get('source')  || '';
      const since   = url.searchParams.get('since')   || '';
      const until   = url.searchParams.get('until')   || '';
      const exact     = url.searchParams.get('exact')     === '1';
      const lag_min_s = url.searchParams.get('lag_min_s') || '';
      const lag_max_s = url.searchParams.get('lag_max_s') || '';
      const pub_since = url.searchParams.get('pub_since') || '';
      const pub_until = url.searchParams.get('pub_until') || '';
      const limit   = Math.min(parseInt(url.searchParams.get('limit')  || '200', 10) || 200, 1000);
      const offset  = parseInt(url.searchParams.get('offset') || '0',  10) || 0;

      const where = eco ? ['ecosystem = ?'] : [];
      const args  = eco ? [eco] : [];
      if (q)     { where.push(exact ? 'package_name = ?' : 'package_name LIKE ?'); args.push(exact ? q : `%${q}%`); }
      if (ver)   { where.push(exact ? 'version = ?'      : 'version LIKE ?');      args.push(exact ? ver : `%${ver}%`); }
      if (reason){ where.push('reason_json LIKE ?');  args.push(`%${reason}%`); }
      if (src)   { where.push('source = ?');          args.push(src); }
      if (since) { where.push('blocked_at >= ?');     args.push(since); }
      if (until) { where.push('blocked_at <  ?');     args.push(until); }
      if (pub_since) { where.push(`published_at IS NOT NULL AND published_at NOT IN ('NOT_FOUND','ERROR') AND published_at >= ?`); args.push(pub_since); }
      if (pub_until) { where.push(`published_at IS NOT NULL AND published_at NOT IN ('NOT_FOUND','ERROR') AND published_at <  ?`); args.push(pub_until); }
      if (lag_min_s || lag_max_s) {
        where.push(`published_at IS NOT NULL AND published_at NOT IN ('NOT_FOUND','ERROR')`);
        const lagCol = `(julianday(blocked_at)-julianday(published_at))*86400.0`;
        if (lag_min_s) { where.push(`${lagCol} >= ?`); args.push(parseFloat(lag_min_s)); }
        if (lag_max_s) { where.push(`${lagCol} <  ?`); args.push(parseFloat(lag_max_s)); }
      }
      const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

      const total = db.prepare(`SELECT COUNT(*) AS n FROM malware ${whereSql}`).get(...args).n;
      const lagOrder = (lag_min_s || lag_max_s)
        ? `(julianday(blocked_at)-julianday(published_at))*86400.0 ASC`
        : `blocked_at DESC`;
      const rows  = db.prepare(`
        SELECT package_name, version, scope, malid, source, blocked_at, ecosystem, reason_json, description, published_at
        FROM malware ${whereSql}
        ORDER BY ${lagOrder}
        LIMIT ? OFFSET ?
      `).all(...args, limit, offset);
      const SENTINELS = new Set(['NOT_FOUND', 'ERROR']);
      const out = rows.map(r => ({
        ...r,
        reason: JSON.parse(r.reason_json || '[]'),
        reason_json: undefined,
        published_at: (r.published_at && !SENTINELS.has(r.published_at)) ? r.published_at : null,
      }));
      return new Response(JSON.stringify({ total, rows: out, limit, offset }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Per-day findings histogram (same filter shape as /search).
    if (url.pathname === '/api/cgr-malware/histogram') {
      const eco    = url.searchParams.get('eco')     || '';
      const q      = url.searchParams.get('q')       || '';
      const ver    = url.searchParams.get('version') || '';
      const reason = url.searchParams.get('reason')  || '';
      const src    = url.searchParams.get('source')  || '';
      const since  = url.searchParams.get('since')   || '';
      const until  = url.searchParams.get('until')   || '';
      const exact  = url.searchParams.get('exact')   === '1';
      const where = eco ? ['ecosystem = ?'] : [];
      const args  = eco ? [eco] : [];
      if (q)     { where.push(exact ? 'package_name = ?' : 'package_name LIKE ?'); args.push(exact ? q : `%${q}%`); }
      if (ver)   { where.push(exact ? 'version = ?'      : 'version LIKE ?');      args.push(exact ? ver : `%${ver}%`); }
      if (reason){ where.push('reason_json LIKE ?');  args.push(`%${reason}%`); }
      if (src)   { where.push('source = ?');          args.push(src); }
      if (since) { where.push('blocked_at >= ?');     args.push(since); }
      if (until) { where.push('blocked_at <  ?');     args.push(until); }
      const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
      const rows = db.prepare(`
        SELECT substr(blocked_at, 1, 10) AS day, COUNT(*) AS n
        FROM malware ${whereSql}
        GROUP BY day
        ORDER BY day
      `).all(...args);
      return new Response(JSON.stringify(rows), { headers: { 'Content-Type': 'application/json' } });
    }

    // All malware entries for one package (any version, any source).
    // Used by the npm tab to badge versions/packages flagged as malware.
    if (url.pathname === '/api/cgr-malware/check') {
      const rawPkg = url.searchParams.get('package') || '';
      const ecoParam = url.searchParams.get('eco') || 'npm';
      const ecoDbName = ecoParam === 'maven' ? 'Maven' : ecoParam === 'pypi' ? 'PyPI' : 'npm';
      // Maven coordinates are `group:artifact` upstream and in-DB, but the UI passes
      // `group/artifact` — normalise so both the lookup and reconcile match.
      const pkg = ecoDbName === 'Maven' ? rawPkg.replace('/', ':') : rawPkg;
      if (!pkg) return new Response(JSON.stringify({ rows: [], cooldown: {} }), { headers: { 'Content-Type': 'application/json' } });

      const readLocal = () => db.prepare(`
        SELECT package_name, version, scope, malid, source, blocked_at, reason_json, description
        FROM malware WHERE ecosystem = ? AND package_name = ?
      `).all(ecoDbName, pkg).map(r => ({ ...r, reason: JSON.parse(r.reason_json || '[]'), reason_json: undefined }));

      let out;
      if (!malwareWarm) {
        // Cold mirror (first fill in progress): serve live so results are correct
        // now instead of sparse. Read-only — doesn't touch the DB. Falls back to
        // whatever local data exists if the live call fails.
        const live = await liveMalwareLookup(ecoDbName, ecoDbName, pkg).catch(() => null);
        out = live || readLocal();
      } else {
        // Warm: self-heal against the live API (apiName === dbName for all three)
        // so cleared/added entries reconcile without a full sync. Best-effort.
        try { await reconcilePackage(ecoDbName, ecoDbName, pkg); }
        catch (err) { console.warn(`[pkg-check] reconcile failed for ${ecoDbName} ${pkg}: ${err.message}`); }
        out = readLocal();
      }
      // Authoritative per-version unblock times (org's own blocked pulls), best-effort.
      const cooldown = await authoritativeCooldown(ecoParam, pkg).catch(() => ({}));
      return new Response(JSON.stringify({ rows: out, cooldown }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Bulk malware check for a list of package names (used by the Lockfile Scan
    // tab). One request, chunked IN() queries — avoids hundreds of round-trips.
    // Returns { results: { <package_name>: [ {version, scope, ...} ] } } keyed
    // only for names that have at least one malware entry.
    if (url.pathname === '/api/cgr-malware/bulk-check' && req.method === 'POST') {
      const body = await req.json().catch(() => ({}));
      const ecoParam = body.ecosystem || 'npm';
      const ecoDbName = ecoParam === 'maven' ? 'Maven' : ecoParam === 'pypi' ? 'PyPI' : 'npm';
      // Maven coordinates are `group:artifact` (colon) upstream and in-DB; callers
      // may pass `group/artifact` (slash) — normalise so the IN() query matches.
      const normName = n => (ecoDbName === 'Maven' ? n.replace('/', ':') : n);
      const names = Array.isArray(body.packages)
        ? [...new Set(body.packages.filter(n => typeof n === 'string' && n).map(normName))]
        : [];
      const SENTINELS = new Set(['NOT_FOUND', 'ERROR']);
      const results = {};
      const CHUNK = 500;
      for (let i = 0; i < names.length; i += CHUNK) {
        const chunk = names.slice(i, i + CHUNK);
        const placeholders = chunk.map(() => '?').join(',');
        const rows = db.prepare(`
          SELECT package_name, version, scope, malid, source, blocked_at, reason_json, description, published_at
          FROM malware
          WHERE ecosystem = ? AND package_name IN (${placeholders})
        `).all(ecoDbName, ...chunk);
        for (const r of rows) {
          (results[r.package_name] ||= []).push({
            version: r.version,
            scope: r.scope,
            malid: r.malid,
            source: r.source,
            blocked_at: r.blocked_at,
            reason: JSON.parse(r.reason_json || '[]'),
            description: r.description,
            published_at: (r.published_at && !SENTINELS.has(r.published_at)) ? r.published_at : null,
          });
        }
      }
      return new Response(JSON.stringify({ ecosystem: ecoDbName, results }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Distinct reasons (for filter facets). Individual MAL-YYYY-N advisory IDs
    // are collapsed into a single "MAL-ID*" bucket; the row carries a
    // `searchAs` field so the client can submit a prefix to the search endpoint.
    if (url.pathname === '/api/cgr-malware/reasons') {
      const eco = url.searchParams.get('eco') || '';
      const ecoFilter = eco ? `AND m.ecosystem = ?` : '';
      const rows = db.prepare(`
        SELECT
          CASE WHEN je.value GLOB 'MAL-[0-9]*-[0-9]*' THEN 'MAL-ID*' ELSE je.value END AS reason,
          COUNT(DISTINCT m.rowid) AS n
        FROM malware m, json_each(m.reason_json) je
        WHERE 1=1 ${ecoFilter}
        GROUP BY reason
        ORDER BY reason COLLATE NOCASE
      `).all(...(eco ? [eco] : []));
      for (const r of rows) {
        if (r.reason === 'MAL-ID*') r.searchAs = 'MAL-';
      }
      return new Response(JSON.stringify(rows), { headers: { 'Content-Type': 'application/json' } });
    }

    return new Response('Not found', { status: 404 });
  },
});

console.log(`Listening on http://localhost:${Number(process.env.PORT) || 3000}`);
process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
