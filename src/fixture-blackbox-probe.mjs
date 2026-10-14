import http from 'node:http';
import { createHash, timingSafeEqual, randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';

// Independent upstream oracle. No APITrench source, customer writes, DB or OAuth secrets.
export function createObservableFixture({ controlKey, maximumNonces = 10000 } = {}) {
  if (typeof controlKey !== 'string' || controlKey.length < 24) throw new Error('BB_CONTROL_KEY must have at least 24 characters');
  const counts = new Map(), tokens = new Map();
  const equal = value => typeof value === 'string' && Buffer.byteLength(value) === Buffer.byteLength(controlKey)
    && timingSafeEqual(Buffer.from(value), Buffer.from(controlKey));
  const reply = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); };
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://fixture.local');
    if (req.method === 'GET' && ['/health', '/__bb/health'].includes(url.pathname)) return reply(res, 200, { ok: true, service: 'apitrench-observable-fixture', contractVersion: 1 });
    if (/^\/edge\/status\/[0-9]{3}$/.test(url.pathname)) {
      const status = Number(url.pathname.split('/').at(-1));
      if (status < 200 || status > 599) return reply(res, 400, { error: 'Invalid status' });
      return reply(res, status, { ok: status < 400, code: String(status) });
    }
    if (url.pathname.startsWith('/__bb/')) {
      if (!equal(req.headers['x-bb-control-key'])) return reply(res, 401, { error: 'Unauthorized' });
      const nonce = url.searchParams.get('nonce');
      if (!nonce || !/^[a-zA-Z0-9_-]{8,100}$/.test(nonce)) return reply(res, 400, { error: 'Valid nonce required' });
      if (url.pathname === '/__bb/inspect' && req.method === 'GET') return reply(res, 200, { nonce, count: counts.get(nonce) ?? 0 });
      if (url.pathname === '/__bb/reset' && req.method === 'DELETE') { counts.delete(nonce); return reply(res, 200, { ok: true }); }
      return reply(res, 404, { error: 'Not found' });
    }
    if (!['/bb/echo', '/bb/approval', '/bb/api-key', '/bb/uncertain', '/bb/failure', '/bb/large', '/bb/token', '/bb/runtime-resource'].includes(url.pathname)) return reply(res, 404, { error: 'Not found' });
    let body = {}; let bytes = 0; const chunks = [];
    try {
      for await (const chunk of req) { bytes += chunk.length; if (bytes > 1024 * 1024) return reply(res, 413, { error: 'Too large' }); chunks.push(chunk); }
      if (chunks.length) body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch { return reply(res, 400, { error: 'Invalid JSON' }); }
    if (!body || typeof body !== 'object' || Array.isArray(body)) return reply(res, 400, { error: 'JSON object required' });
    const nonce = body.bb_nonce ?? url.searchParams.get('bb_nonce') ?? undefined;
    if (nonce !== undefined && (typeof nonce !== 'string' || !/^[a-zA-Z0-9_-]{8,100}$/.test(nonce))) return reply(res, 400, { error: 'Invalid nonce' });
    if (nonce) {
      if (!counts.has(nonce) && counts.size >= maximumNonces) return reply(res, 429, { error: 'Fixture observation capacity reached' });
      counts.set(nonce, (counts.get(nonce) ?? 0) + 1);
    }
    if (url.pathname === '/bb/token') {
      const value = req.headers['x-api-key'];
      if (typeof value !== 'string' || !value.startsWith('bb-release-key-')) return reply(res, 401, { error: 'Synthetic seed required' });
      const token = 'bb-runtime-' + createHash('sha256').update(value + ':' + randomUUID()).digest('hex');
      tokens.set(token, { expiresAt: Date.now() + 120000, identityHash: createHash('sha256').update(value).digest('hex') });
      for (const [key, record] of tokens) if (record.expiresAt < Date.now()) tokens.delete(key);
      return reply(res, 200, { access_token: token, expires_in: 120, token_type: 'Bearer' });
    }
    if (url.pathname === '/bb/runtime-resource') {
      const token = req.headers.authorization?.replace(/^Bearer /, '');
      const record = tokens.get(token);
      if (!record || record.expiresAt <= Date.now()) return reply(res, 401, { error: 'Expired or invalid synthetic runtime' });
      return reply(res, 200, { ok: true, identityHash: record.identityHash });
    }
    if (url.pathname === '/bb/api-key') {
      const value = req.headers['x-api-key'];
      if (typeof value !== 'string' || !value.startsWith('bb-release-key-')) return reply(res, 401, { error: 'Synthetic key required' });
      return reply(res, 200, { ok: true, credentialAccepted: true, identityHash: createHash('sha256').update(value).digest('hex') });
    }
    if (url.pathname === '/bb/failure') return reply(res, 500, { error: 'Simulated upstream failure', accepted: true });
    if (url.pathname === '/bb/large') return reply(res, 200, { ok: true, items: Array.from({ length: 150 }, (_, id) => ({ id })), secret: 'bb-fixture-response-secret' });
    const send = () => { if (!res.destroyed) reply(res, 200, { ok: true, received: body, accepted: true }); };
    const delay = url.pathname === '/bb/uncertain' ? 3000 : Math.min(Math.max(Number(body.delayMs) || 0, 0), 3000);
    if (delay) { const timer = setTimeout(send, delay); timer.unref(); } else send();
  });
  return { server, counts };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { server } = createObservableFixture({ controlKey: process.env.BB_CONTROL_KEY });
  server.listen(Number(process.env.PORT ?? 8080), '0.0.0.0', () => console.log('Observable fixture listening; credentials are never printed'));
}
