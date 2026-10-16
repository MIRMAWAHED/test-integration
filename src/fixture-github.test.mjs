import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';

// Real local fixture routes; only the external Google/GitHub responses are mocked.
// No actual provider accounts, passwords or tokens are needed for these tests.
const nativeFetch = globalThis.fetch;
let server, origin, scenario, calls;
const defaultProfile = { id: 12345, login: 'fixture-user', name: 'Fixture User', email: null };
test.before(async () => {
  process.env.FIXTURE_BASE_URL = 'https://fixture.example.test';
  process.env.GITHUB_CLIENT_ID = 'fixture-test-github-client';
  process.env.GITHUB_CLIENT_SECRET = 'fixture-test-github-secret';
  process.env.GOOGLE_CLIENT_ID = 'fixture-test-google-client';
  process.env.GOOGLE_CLIENT_SECRET = 'fixture-test-google-secret';
  ({ server } = await import('../server.mjs'));
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  origin = 'http://127.0.0.1:' + server.address().port;
});
test.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
test.beforeEach(() => {
  scenario = {}; calls = [];
  mock.method(globalThis, 'fetch', async (url, init = {}) => {
    const address = String(url); calls.push({ url: address, init });
    if (address === 'https://api.github.com/user') {
      assert.equal(init.headers.authorization, 'Bearer fixture-synthetic-access-token');
      assert.equal(init.headers.accept, 'application/vnd.github+json');
      assert.equal(init.headers['x-github-api-version'], '2026-03-10');
      assert(init.headers['user-agent']);
      return new Response(scenario.profileRaw ?? JSON.stringify(scenario.profile ?? defaultProfile), { status: scenario.profileStatus ?? 200, headers: { 'Content-Type': 'application/json' } });
    }
    if (address === 'https://api.github.com/user/emails') return new Response(scenario.emailRaw ?? JSON.stringify(scenario.emails ?? [
      { email: 'unverified@example.test', primary: false, verified: false },
      { email: 'verified@example.test', primary: false, verified: true },
      { email: 'primary@example.test', primary: true, verified: true },
    ]), { status: scenario.emailStatus ?? 200, headers: { 'Content-Type': 'application/json' } });
    if (address === 'https://www.googleapis.com/oauth2/v3/userinfo') {
      assert.equal(init.headers.authorization, 'Bearer fixture-synthetic-access-token');
      return Response.json({ sub: 'google-user-123', email: 'google@example.test', name: 'Google User' });
    }
    if (['https://github.com/login/oauth/access_token', 'https://oauth2.googleapis.com/token'].includes(address)) {
      assert.equal(init.method, 'POST'); assert.equal(init.headers.accept, 'application/json');
      const body = new URLSearchParams(init.body); assert.equal(body.get('code'), 'fixture-code'); assert(body.get('client_secret'));
      return new Response(scenario.tokenRaw ?? JSON.stringify(scenario.token ?? { access_token: 'fixture-synthetic-access-token', token_type: 'bearer', scope: 'read:user,user:email' }),
        { status: scenario.tokenStatus ?? 200, headers: { 'Content-Type': scenario.tokenContentType ?? 'application/json' } });
    }
    assert.fail('Unexpected external request: ' + address);
  });
});
test.afterEach(() => mock.restoreAll());
async function get(route, { token = 'fixture-synthetic-access-token', method = 'GET' } = {}) {
  const response = await nativeFetch(origin + route, { method, redirect: 'manual', headers: token ? { Authorization: 'Bearer ' + token } : {} });
  const raw = await response.text(); let body; try { body = JSON.parse(raw); } catch { body = raw; }
  return { status: response.status, location: response.headers.get('location'), body };
}
test('public schema contains exactly one GitHub profile tool alongside the existing Google tool', async () => {
  const schema = (await get('/public/openapi.json')).body;
  assert.equal(Object.keys(schema.paths).length, 39);
  assert.equal(schema.paths['/real-oauth/google/profile'].get.operationId, 'googleOAuthProfile');
  const github = schema.paths['/real-oauth/github/profile'].get;
  assert.equal(github.operationId, 'githubOAuthProfile'); assert.equal(github['x-apitrench-role'], 'tool');
  assert.equal(github['x-apitrench-import-as-tool'], true); assert.equal(github['x-apitrench-safety-level'], 'read');
  assert.deepEqual(github.security, [{ githubOAuth: ['read:user', 'user:email'] }]);
  assert.equal(Object.values(schema.paths).filter(p => p.get?.operationId === 'githubOAuthProfile').length, 1);
  assert(schema.components.securitySchemes.githubOAuth.flows.authorizationCode.scopes.offline_access);
});
test('GitHub tool refuses missing bearer before making any provider request', async () => {
  assert.equal((await get('/real-oauth/github/profile', { token: null })).status, 401); assert.equal(calls.length, 0);
});
test('private email array is preserved and verified primary email is selected', async () => {
  const response = await get('/real-oauth/github/profile'); assert.equal(response.status, 200);
  assert.equal(response.body.endpoint, 'githubOAuthProfile'); assert.equal(response.body.profile.provider, 'github');
  assert.equal(response.body.profile.providerUserId, '12345'); assert.equal(response.body.profile.username, 'fixture-user');
  assert.equal(response.body.profile.email, 'primary@example.test'); assert.equal(calls.length, 2);
  assert(!JSON.stringify(response.body).includes('fixture-synthetic-access-token'));
});
test('public profile email does not require an unnecessary email API request', async () => {
  scenario.profile = { ...defaultProfile, email: 'public@example.test' };
  const r = await get('/real-oauth/github/profile'); assert.equal(r.status, 200); assert.equal(r.body.profile.email, 'public@example.test'); assert.equal(calls.length, 1);
});
test('a verified alternative is used when the primary email is unverified', async () => {
  scenario.emails = [{ email: 'unverified@example.test', primary: true, verified: false }, { email: 'verified@example.test', primary: false, verified: true }];
  const r = await get('/real-oauth/github/profile'); assert.equal(r.status, 200); assert.equal(r.body.profile.email, 'verified@example.test');
});
for (const emails of [[], [{ email: 'unverified@example.test', primary: true, verified: false }]]) test('absence of a verified email leaves the authenticated profile usable: ' + emails.length, async () => {
  scenario.emails = emails; const r = await get('/real-oauth/github/profile'); assert.equal(r.status, 200); assert.equal(r.body.profile.email, null);
});
for (const status of [403, 404]) test('optional email permission denial does not destroy a valid identity: ' + status, async () => {
  scenario.emailStatus = status; const r = await get('/real-oauth/github/profile'); assert.equal(r.status, 200); assert.equal(r.body.profile.email, null); assert.equal(r.body.profile.providerUserId, '12345');
});
for (const [emailStatus, expected] of [[401, 401], [500, 502]]) test('email provider failure is not silently reported as a successful profile: ' + emailStatus, async () => {
  scenario.emailStatus = emailStatus; const r = await get('/real-oauth/github/profile'); assert.equal(r.status, expected);
});
test('a malformed email response fails without echoing the upstream body', async () => {
  scenario.emailRaw = '{fixture-private-body'; const r = await get('/real-oauth/github/profile'); assert.equal(r.status, 502); assert(!JSON.stringify(r.body).includes('fixture-private-body'));
});
for (const profile of [{ login: 'missing-id' }, { id: 12345 }, [], { id: -1, login: 'invalid-id' }]) test('malformed GitHub identity cannot produce a success or fixture JWT: ' + JSON.stringify(profile), async () => {
  scenario.profile = profile; assert.equal((await get('/real-oauth/github/profile')).status, 502);
  assert.equal((await get('/exchange/github-oauth-to-jwt', { method: 'POST' })).status, 502);
});
for (const status of [401, 403, 500]) test('GitHub rejects the supplied token or provider fails: ' + status, async () => {
  scenario.profileStatus = status; const r = await get('/real-oauth/github/profile'); assert.equal(r.status, status === 500 ? 502 : 401); assert.equal(calls.length, 1);
});
test('Google profile and Google-to-JWT keep their original identity contract', async () => {
  const r = await get('/real-oauth/google/profile'); assert.equal(r.status, 200); assert.equal(r.body.profile.providerUserId, 'google-user-123');
  const jwt = await get('/exchange/google-oauth-to-jwt', { method: 'POST' }); assert.equal(jwt.status, 200);
  const payload = JSON.parse(Buffer.from(jwt.body.jwt.split('.')[1], 'base64url').toString()); assert.equal(payload.provider, 'google'); assert.equal(payload.sub, 'google-user-123');
});
test('GitHub-to-JWT produces a credential accepted by the existing protected resource', async () => {
  const r = await get('/exchange/github-oauth-to-jwt', { method: 'POST' }); assert.equal(r.status, 200);
  const payload = JSON.parse(Buffer.from(r.body.jwt.split('.')[1], 'base64url').toString());
  assert.equal(payload.provider, 'github'); assert.equal(payload.sub, '12345'); assert.equal(payload.username, 'fixture-user');
  assert.equal((await get('/protected/jwt/resource', { token: r.body.jwt })).status, 200);
});
test('GitHub login requests profile, email and expiring-token support; Google still requests offline consent', async () => {
  const github = await get('/real-oauth/github/login'); assert.equal(github.status, 302);
  const url = new URL(github.location); assert.equal(url.origin + url.pathname, 'https://github.com/login/oauth/authorize');
  assert.deepEqual(url.searchParams.get('scope').split(' '), ['read:user', 'user:email', 'offline_access']); assert(url.searchParams.get('state'));
  const google = new URL((await get('/real-oauth/google/login')).location);
  assert.equal(google.searchParams.get('access_type'), 'offline'); assert.equal(google.searchParams.get('prompt'), 'consent');
});
test('provider metadata advertises APITrench connection settings without client secrets', async () => {
  const r = await get('/public/demo-credentials'); const github = r.body.externalOAuthProviders?.github;
  assert(github, 'GitHub provider metadata missing'); assert.equal(github.tokenAuthMethod, 'client_secret_post'); assert.equal(github.pkceEnabled, true);
  assert.deepEqual(github.defaultScopes, ['read:user', 'user:email', 'offline_access']);
  assert(!JSON.stringify(r.body).includes('fixture-test-github-secret'));
});
test('GitHub direct callback exchanges a real code-shaped request and then verifies the returned token identity', async () => {
  const login = new URL((await get('/real-oauth/github/login')).location);
  const r = await get('/real-oauth/github/callback?code=fixture-code&state=' + encodeURIComponent(login.searchParams.get('state')));
  assert.equal(r.status, 200); assert.equal(r.body.profile.providerUserId, '12345');
  assert.equal(calls[0].url, 'https://github.com/login/oauth/access_token');
  assert.equal(new URLSearchParams(calls[0].init.body).get('redirect_uri'), 'https://fixture.example.test/real-oauth/github/callback');
});
test('GitHub OAuth errors returned with HTTP 200 are rejected without echoing provider payload', async () => {
  scenario.token = { error: 'bad_verification_code', error_description: 'fixture-provider-private-error' };
  const login = new URL((await get('/real-oauth/github/login')).location);
  const r = await get('/real-oauth/github/callback?code=fixture-code&state=' + encodeURIComponent(login.searchParams.get('state')));
  assert.equal(r.status, 401); assert.equal(calls.length, 1); assert(!JSON.stringify(r.body).includes('fixture-provider-private-error'));
});
test('GitHub form-encoded token response is accepted when the provider returns that format', async () => {
  scenario.tokenRaw = 'access_token=fixture-synthetic-access-token&token_type=bearer&scope=read%3Auser'; scenario.tokenContentType = 'application/x-www-form-urlencoded';
  const login = new URL((await get('/real-oauth/github/login')).location);
  assert.equal((await get('/real-oauth/github/callback?code=fixture-code&state=' + encodeURIComponent(login.searchParams.get('state')))).status, 200);
});
test('invalid state cannot reach GitHub token exchange', async () => {
  assert.equal((await get('/real-oauth/github/callback?code=fixture-code&state=invalid')).status, 400); assert.equal(calls.length, 0);
});
for (const token of [{}, { access_token: {} }, { access_token: '' }]) test('malformed token payload cannot reach the profile API: ' + JSON.stringify(token), async () => {
  scenario.token = token;
  const login = new URL((await get('/real-oauth/github/login')).location);
  const r = await get('/real-oauth/github/callback?code=fixture-code&state=' + encodeURIComponent(login.searchParams.get('state')));
  assert.equal(r.status, 502); assert.equal(calls.length, 1);
});
test('provider server error stays a provider failure even when its body has an OAuth error field', async () => {
  scenario.token = { error: 'server_error' }; scenario.tokenStatus = 500;
  const login = new URL((await get('/real-oauth/github/login')).location);
  assert.equal((await get('/real-oauth/github/callback?code=fixture-code&state=' + encodeURIComponent(login.searchParams.get('state')))).status, 502);
});
