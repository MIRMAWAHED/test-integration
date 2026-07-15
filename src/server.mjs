import http from 'node:http';
import crypto from 'node:crypto';

const PORT = Number(process.env.PORT || 8080);
const BASE_URL = (process.env.FIXTURE_BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const ALLOWED_REDIRECT_ORIGINS = (process.env.ALLOWED_REDIRECT_ORIGINS || 'http://localhost:3000,http://localhost:4000')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean);

const FIXTURE = {
  apiKey: process.env.FIXTURE_API_KEY || 'atk_live_demo',
  bearerToken: process.env.FIXTURE_BEARER_TOKEN || 'bearer_demo',
  basicUser: process.env.FIXTURE_BASIC_USER || 'demo',
  basicPassword: process.env.FIXTURE_BASIC_PASSWORD || 'secret',
  clientToken: process.env.FIXTURE_CLIENT_TOKEN || 'client_token_demo',
  customClientId: process.env.FIXTURE_CUSTOM_CLIENT_ID || 'demo-client',
  customClientSecret: process.env.FIXTURE_CUSTOM_CLIENT_SECRET || 'demo-client-secret',
  oauthClientId: process.env.FIXTURE_OAUTH_CLIENT_ID || 'apitrench-client',
  oauthClientSecret: process.env.FIXTURE_OAUTH_CLIENT_SECRET || 'apitrench-secret',
  googleClientId: process.env.GOOGLE_CLIENT_ID || '',
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
  githubClientId: process.env.GITHUB_CLIENT_ID || '',
  githubClientSecret: process.env.GITHUB_CLIENT_SECRET || '',
  googleRedirectUri: process.env.GOOGLE_OAUTH_REDIRECT_URI || `${BASE_URL}/real-oauth/google/callback`,
  githubRedirectUri: process.env.GITHUB_OAUTH_REDIRECT_URI || `${BASE_URL}/real-oauth/github/callback`,
  jwtSecret: process.env.FIXTURE_JWT_SECRET || 'fixture-jwt-secret',
  hmacSecret: process.env.FIXTURE_HMAC_SECRET || 'fixture-hmac-secret',
};

const codeStore = new Map();
const accessTokenStore = new Map();
const refreshTokenStore = new Map();
const sessionStore = new Map();
const revokedTokens = new Set();
const externalOAuthStateStore = new Map();
const invocationCounters = new Map();

function nowIso() {
  return new Date().toISOString();
}

function randomToken(prefix) {
  return `${prefix}_${crypto.randomBytes(18).toString('base64url')}`;
}

function sha256Base64Url(value) {
  return crypto.createHash('sha256').update(value).digest('base64url');
}

function hmacHex(secret, value) {
  return crypto.createHmac('sha256', secret).update(value).digest('hex');
}

function json(res, statusCode, payload, headers = {}) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    ...headers,
  });
  res.end(body);
}

function text(res, statusCode, body, headers = {}) {
  res.writeHead(statusCode, {
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': 'no-store',
    ...headers,
  });
  res.end(body);
}

function redirect(res, location) {
  res.writeHead(302, {
    location,
    'cache-control': 'no-store',
  });
  res.end();
}

function notFound(res, req) {
  json(res, 404, {
    error: 'not_found',
    message: `No fixture route for ${req.method} ${new URL(req.url, BASE_URL).pathname}`,
  });
}

function unauthorized(res, message, extra = {}) {
  json(res, 401, {
    error: 'unauthorized',
    message,
    ...extra,
  });
}

function forbidden(res, message, extra = {}) {
  json(res, 403, {
    error: 'forbidden',
    message,
    ...extra,
  });
}

function badRequest(res, message, extra = {}) {
  json(res, 400, {
    error: 'bad_request',
    message,
    ...extra,
  });
}

function methodNotAllowed(res, allowed) {
  json(res, 405, { error: 'method_not_allowed', allowed }, { allow: allowed.join(', ') });
}

function getHeader(req, name) {
  const value = req.headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

async function readBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.byteLength;
    if (total > 1024 * 1024) {
      const err = new Error('Request body too large');
      err.statusCode = 413;
      throw err;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

async function parseBody(req) {
  const raw = await readBody(req);
  if (!raw) return {};
  const contentType = String(getHeader(req, 'content-type') || '').toLowerCase();
  if (contentType.includes('application/json')) {
    try {
      return JSON.parse(raw);
    } catch {
      const err = new Error('Invalid JSON body');
      err.statusCode = 400;
      throw err;
    }
  }
  if (contentType.includes('application/x-www-form-urlencoded')) {
    return Object.fromEntries(new URLSearchParams(raw).entries());
  }
  return { raw };
}

function requireApiKeyHeader(req, res) {
  const value = getHeader(req, 'x-api-key');
  if (value !== FIXTURE.apiKey) {
    unauthorized(res, 'Expected x-api-key header', {
      expectedShape: { headers: { 'x-api-key': '<api key>' } },
      demoValue: FIXTURE.apiKey,
    });
    return false;
  }
  return true;
}

function requireApiKeyQuery(url, res) {
  const value = url.searchParams.get('api_key');
  if (value !== FIXTURE.apiKey) {
    unauthorized(res, 'Expected api_key query parameter', {
      expectedShape: { query: { api_key: '<api key>' } },
      demoValue: FIXTURE.apiKey,
    });
    return false;
  }
  return true;
}

function requireBearer(req, res, expected = FIXTURE.bearerToken, label = 'bearer token') {
  const auth = getHeader(req, 'authorization') || '';
  const prefix = 'Bearer ';
  if (!auth.startsWith(prefix) || auth.slice(prefix.length) !== expected) {
    unauthorized(res, `Expected Authorization: Bearer <${label}>`, {
      expectedShape: { headers: { authorization: `Bearer <${label}>` } },
      demoValue: expected,
    });
    return false;
  }
  return true;
}

function requireBasic(req, res) {
  const auth = getHeader(req, 'authorization') || '';
  const expected = `Basic ${Buffer.from(`${FIXTURE.basicUser}:${FIXTURE.basicPassword}`).toString('base64')}`;
  if (auth !== expected) {
    unauthorized(res, 'Expected HTTP Basic credentials', {
      expectedShape: { username: FIXTURE.basicUser, password: FIXTURE.basicPassword },
    });
    return false;
  }
  return true;
}

function requireCustomHeader(req, res) {
  const value = getHeader(req, 'x-client-token');
  if (value !== FIXTURE.clientToken) {
    unauthorized(res, 'Expected x-client-token header', {
      expectedShape: { headers: { 'x-client-token': '<client token>' } },
      demoValue: FIXTURE.clientToken,
    });
    return false;
  }
  return true;
}

function requireCustomTemplate(req, url, res) {
  const clientId = getHeader(req, 'x-client-id');
  const signature = getHeader(req, 'x-client-signature');
  const nonce = url.searchParams.get('nonce') || '';
  const expected = hmacHex(FIXTURE.customClientSecret, `${clientId}:${nonce}`);
  if (clientId !== FIXTURE.customClientId || signature !== expected) {
    unauthorized(res, 'Expected x-client-id plus HMAC signature over clientId:nonce', {
      expectedShape: {
        headers: {
          'x-client-id': FIXTURE.customClientId,
          'x-client-signature': 'sha256_hmac(clientSecret, "clientId:nonce")',
        },
        query: { nonce: 'anything' },
      },
      demoNonce: nonce || 'demo-nonce',
      demoSignatureForDemoNonce: hmacHex(FIXTURE.customClientSecret, `${FIXTURE.customClientId}:${nonce || 'demo-nonce'}`),
    });
    return false;
  }
  return true;
}

function requireHmac(req, res, bodyText = '') {
  const timestamp = getHeader(req, 'x-timestamp');
  const signature = getHeader(req, 'x-signature');
  const path = new URL(req.url, BASE_URL).pathname;
  if (!timestamp || !signature) {
    unauthorized(res, 'Expected x-timestamp and x-signature headers', {
      expectedShape: {
        headers: {
          'x-timestamp': '<unix seconds>',
          'x-signature': 'hex(hmac_sha256(secret, "METHOD\nPATH\nTIMESTAMP\nBODY"))',
        },
      },
    });
    return false;
  }
  const expected = hmacHex(FIXTURE.hmacSecret, `${req.method}\n${path}\n${timestamp}\n${bodyText}`);
  if (signature !== expected) {
    unauthorized(res, 'Invalid HMAC signature', {
      demoSigningString: `${req.method}\n${path}\n${timestamp}\n${bodyText}`,
      expectedSignatureForThisRequest: expected,
    });
    return false;
  }
  return true;
}

function getOAuthAccessToken(req) {
  const auth = getHeader(req, 'authorization') || '';
  if (!auth.startsWith('Bearer ')) return null;
  const token = auth.slice('Bearer '.length).trim();
  const record = accessTokenStore.get(token);
  if (!record || revokedTokens.has(token)) return null;
  if (record.expiresAt <= Date.now()) return null;
  return { token, record };
}

function requireOAuthAccessToken(req, res, requiredScope = null) {
  const resolved = getOAuthAccessToken(req);
  if (!resolved) {
    unauthorized(res, 'Expected valid fixture OAuth access token', {
      howToGetOne: 'GET /oauth/authorize then POST /oauth/token, or use APITrench OAuth provider flow.',
    });
    return null;
  }
  if (requiredScope && !resolved.record.scopes.includes(requiredScope)) {
    forbidden(res, `OAuth token missing required scope: ${requiredScope}`, {
      tokenScopes: resolved.record.scopes,
    });
    return null;
  }
  return resolved;
}


function getBearerTokenFromRequest(req) {
  const auth = getHeader(req, 'authorization') || '';
  const prefix = 'Bearer ';
  if (!auth.startsWith(prefix)) return null;
  const token = auth.slice(prefix.length).trim();
  return token || null;
}


function getExternalOAuthConfig(provider) {
  if (provider === 'google') {
    return {
      provider: 'google',
      clientId: FIXTURE.googleClientId,
      clientSecret: FIXTURE.googleClientSecret,
      redirectUri: FIXTURE.googleRedirectUri,
      authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenUrl: 'https://oauth2.googleapis.com/token',
      defaultScopes: ['openid', 'email', 'profile'],
    };
  }

  if (provider === 'github') {
    return {
      provider: 'github',
      clientId: FIXTURE.githubClientId,
      clientSecret: FIXTURE.githubClientSecret,
      redirectUri: FIXTURE.githubRedirectUri,
      authorizationUrl: 'https://github.com/login/oauth/authorize',
      tokenUrl: 'https://github.com/login/oauth/access_token',
      defaultScopes: ['read:user', 'user:email'],
    };
  }

  return null;
}

function assertExternalOAuthConfigured(provider) {
  const config = getExternalOAuthConfig(provider);

  if (!config) {
    const err = new Error(`Unsupported external OAuth provider: ${provider}`);
    err.statusCode = 404;
    throw err;
  }

  if (!config.clientId || !config.clientSecret) {
    const upper = provider.toUpperCase();
    const err = new Error(`${provider} OAuth is not configured. Set ${upper}_CLIENT_ID and ${upper}_CLIENT_SECRET in this app's .env.`);
    err.statusCode = 500;
    err.missingEnv = [`${upper}_CLIENT_ID`, `${upper}_CLIENT_SECRET`];
    throw err;
  }

  return config;
}

function buildExternalOAuthAuthorizationUrl(provider) {
  const config = assertExternalOAuthConfigured(provider);
  const state = randomToken(`${provider}_state`);
  externalOAuthStateStore.set(state, {
    provider,
    createdAt: Date.now(),
    expiresAt: Date.now() + 10 * 60 * 1000,
  });

  const url = new URL(config.authorizationUrl);
  url.searchParams.set('client_id', config.clientId);
  url.searchParams.set('redirect_uri', config.redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', config.defaultScopes.join(' '));
  url.searchParams.set('state', state);

  if (provider === 'google') {
    url.searchParams.set('access_type', 'offline');
    url.searchParams.set('prompt', 'consent');
  }

  return { authorizationUrl: url.toString(), state, config };
}

function consumeExternalOAuthState(provider, state) {
  const record = state ? externalOAuthStateStore.get(state) : null;

  if (!record || record.provider !== provider || record.expiresAt <= Date.now()) {
    const err = new Error(`Invalid or expired ${provider} OAuth state`);
    err.statusCode = 400;
    throw err;
  }

  externalOAuthStateStore.delete(state);
}

async function exchangeExternalOAuthCode(provider, code, state) {
  const config = assertExternalOAuthConfigured(provider);
  consumeExternalOAuthState(provider, state);

  const body = new URLSearchParams();
  body.set('grant_type', 'authorization_code');
  body.set('code', code);
  body.set('redirect_uri', config.redirectUri);
  body.set('client_id', config.clientId);
  body.set('client_secret', config.clientSecret);

  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/x-www-form-urlencoded',
    },
    body,
  });

  const textBody = await response.text();
  let tokenPayload = null;

  if (textBody) {
    try {
      tokenPayload = JSON.parse(textBody);
    } catch {
      tokenPayload = Object.fromEntries(new URLSearchParams(textBody));
    }
  }

  if (!response.ok) {
    const err = new Error(`${provider} OAuth code exchange failed (${response.status})`);
    err.statusCode = response.status === 400 || response.status === 401 ? 401 : 502;
    err.providerPayload = tokenPayload;
    throw err;
  }

  if (!tokenPayload || typeof tokenPayload !== 'object' || !tokenPayload.access_token) {
    const err = new Error(`${provider} OAuth token response did not include access_token`);
    err.statusCode = 502;
    err.providerPayload = tokenPayload;
    throw err;
  }

  return tokenPayload;
}

async function completeExternalOAuthCallback(provider, url) {
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const providerError = url.searchParams.get('error');
  const providerErrorDescription = url.searchParams.get('error_description');

  if (providerError) {
    const err = new Error(providerErrorDescription || providerError);
    err.statusCode = 400;
    throw err;
  }

  if (!code) {
    const err = new Error(`Missing ${provider} OAuth code`);
    err.statusCode = 400;
    throw err;
  }

  const tokenPayload = await exchangeExternalOAuthCode(provider, code, state);
  const accessToken = tokenPayload.access_token;
  const profile = await resolveExternalOAuthProfileFromToken(provider, accessToken);

  return { tokenPayload, profile };
}

async function resolveExternalOAuthProfileFromToken(provider, token) {
  const fakeReq = { headers: { authorization: `Bearer ${token}` } };
  return resolveExternalOAuthProfile(fakeReq, provider);
}

async function fetchJsonWithBearer(url, token, extraHeaders = {}) {
  const response = await fetch(url, {
    headers: {
      accept: 'application/json',
      authorization: `Bearer ${token}`,
      ...extraHeaders,
    },
  });

  const textBody = await response.text();
  let data = null;

  if (textBody) {
    try {
      data = JSON.parse(textBody);
    } catch {
      data = { raw: textBody };
    }
  }

  if (!response.ok) {
    const err = new Error(`External OAuth provider rejected token (${response.status})`);
    err.statusCode = response.status === 401 || response.status === 403 ? 401 : 502;
    err.providerStatus = response.status;
    err.providerPayload = data;
    throw err;
  }

  return data && typeof data === 'object' && !Array.isArray(data) ? data : {};
}

async function resolveExternalOAuthProfile(req, provider) {
  const token = getBearerTokenFromRequest(req);

  if (!token) {
    const err = new Error(`Expected Authorization: Bearer <${provider} OAuth access token>`);
    err.statusCode = 401;
    throw err;
  }

  if (provider === 'google') {
    const profile = await fetchJsonWithBearer(
      'https://www.googleapis.com/oauth2/v3/userinfo',
      token,
    );

    return {
      provider: 'google',
      providerUserId: profile.sub ?? null,
      email: profile.email ?? null,
      displayName: profile.name ?? profile.email ?? null,
      username: profile.email ?? null,
      rawProfile: profile,
    };
  }

  if (provider === 'github') {
    const headers = {
      'user-agent': 'apitrench-fixture-api',
      'x-github-api-version': '2022-11-28',
    };

    const profile = await fetchJsonWithBearer(
      'https://api.github.com/user',
      token,
      headers,
    );

    let primaryEmail = typeof profile.email === 'string' && profile.email ? profile.email : null;

    if (!primaryEmail) {
      try {
        const emails = await fetchJsonWithBearer(
          'https://api.github.com/user/emails',
          token,
          headers,
        );

        if (Array.isArray(emails)) {
          const primary = emails.find((item) => item?.primary && item?.verified && item?.email) ?? emails.find((item) => item?.email);
          primaryEmail = typeof primary?.email === 'string' ? primary.email : null;
        }
      } catch {
        // The user may not have granted user:email. Keep the profile usable without it.
      }
    }

    return {
      provider: 'github',
      providerUserId: profile.id != null ? String(profile.id) : null,
      email: primaryEmail,
      displayName: profile.name ?? profile.login ?? primaryEmail ?? null,
      username: profile.login ?? null,
      rawProfile: profile,
    };
  }

  const err = new Error(`Unsupported external OAuth provider: ${provider}`);
  err.statusCode = 400;
  throw err;
}


function signJwt(payload, expiresInSeconds = 900) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = {
    iss: BASE_URL,
    aud: 'apitrench-fixture-api',
    iat: now,
    exp: now + expiresInSeconds,
    ...payload,
  };
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(fullPayload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', FIXTURE.jwtSecret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64url');
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function verifyJwt(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedPayload, signature] = parts;
  const expected = crypto
    .createHmac('sha256', FIXTURE.jwtSecret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  try {
    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
    if (payload.exp && payload.exp <= Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

function requireJwt(req, res) {
  const auth = getHeader(req, 'authorization') || '';
  if (!auth.startsWith('Bearer ')) {
    unauthorized(res, 'Expected Authorization: Bearer <jwt>');
    return null;
  }
  const payload = verifyJwt(auth.slice('Bearer '.length).trim());
  if (!payload) {
    unauthorized(res, 'Invalid or expired JWT');
    return null;
  }
  return payload;
}

function issueOAuthTokens(input) {
  const accessToken = randomToken('oauth_at');
  const refreshToken = randomToken('oauth_rt');
  const expiresIn = Number(input.expiresIn || 3600);
  const record = {
    clientId: input.clientId || FIXTURE.oauthClientId,
    userId: input.userId || 'user_fixture_123',
    displayName: input.displayName || 'Fixture User',
    email: input.email || 'fixture@example.com',
    scopes: input.scopes || ['profile', 'email', 'read:data'],
    createdAt: Date.now(),
    expiresAt: Date.now() + expiresIn * 1000,
    metadata: input.metadata || {},
  };
  accessTokenStore.set(accessToken, record);
  refreshTokenStore.set(refreshToken, record);
  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    token_type: 'Bearer',
    expires_in: expiresIn,
    scope: record.scopes.join(' '),
  };
}

function getOpenApi() {
  const securitySchemes = {
    apiKeyHeader: { type: 'apiKey', in: 'header', name: 'x-api-key' },
    apiKeyQuery: { type: 'apiKey', in: 'query', name: 'api_key' },
    bearerAuth: { type: 'http', scheme: 'bearer' },
    basicAuth: { type: 'http', scheme: 'basic' },
    customClientToken: { type: 'apiKey', in: 'header', name: 'x-client-token' },
    customClientId: { type: 'apiKey', in: 'header', name: 'x-client-id' },
    hmacSignature: { type: 'apiKey', in: 'header', name: 'x-signature' },
    fixtureOAuth: {
      type: 'oauth2',
      flows: {
        authorizationCode: {
          authorizationUrl: `${BASE_URL}/oauth/authorize`,
          tokenUrl: `${BASE_URL}/oauth/token`,
          scopes: {
            profile: 'Read profile',
            email: 'Read email',
            'read:data': 'Read fixture data',
            'write:data': 'Write fixture data',
            'mint:jwt': 'Exchange OAuth access token for JWT',
            'admin:danger': 'Dangerous test scope',
          },
        },
      },
    },
    googleOAuth: {
      type: 'oauth2',
      description: 'Real Google OAuth access token. Configure Google as an APITrench OAuth provider, then use the stored token against these fixture endpoints.',
      flows: {
        authorizationCode: {
          authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
          tokenUrl: 'https://oauth2.googleapis.com/token',
          scopes: {
            openid: 'OpenID identity',
            email: 'Read email address',
            profile: 'Read basic profile',
          },
        },
      },
    },
    githubOAuth: {
      type: 'oauth2',
      description: 'Real GitHub OAuth access token. Configure GitHub as an APITrench OAuth provider, then use the stored token against these fixture endpoints.',
      flows: {
        authorizationCode: {
          authorizationUrl: 'https://github.com/login/oauth/authorize',
          tokenUrl: 'https://github.com/login/oauth/access_token',
          scopes: {
            'read:user': 'Read GitHub profile',
            'user:email': 'Read GitHub email addresses',
          },
        },
      },
    },
  };

  const jsonResponse = {
    '200': {
      description: 'JSON response',
      content: {
        'application/json': {
          schema: { type: 'object', additionalProperties: true },
        },
      },
    },
  };

  return {
    openapi: '3.1.0',
    info: {
      title: 'APITrench Fixture API',
      version: '1.0.0',
      description: 'A live fixture API for testing APITrench auth providers, credential application modes, chained auth workflows, response slimming, logs, and safety gates.',
    },
    servers: [{ url: BASE_URL }],
    tags: [
      { name: 'public' },
      { name: 'auth-basic-modes' },
      { name: 'oauth-provider' },
      { name: 'external-oauth-providers' },
      { name: 'chained-workflows' },
      { name: 'policies-and-logs' },
      { name: 'edge-cases' },
    ],
    components: { securitySchemes },
    paths: {
      '/health': { get: { tags: ['public'], operationId: 'health', responses: jsonResponse } },
      '/public/ping': { get: { tags: ['public'], operationId: 'publicPing', responses: jsonResponse } },
      '/auth/api-key-header': { get: { tags: ['auth-basic-modes'], operationId: 'apiKeyHeaderEcho', security: [{ apiKeyHeader: [] }], responses: jsonResponse } },
      '/auth/api-key-query': { get: { tags: ['auth-basic-modes'], operationId: 'apiKeyQueryEcho', security: [{ apiKeyQuery: [] }], responses: jsonResponse } },
      '/auth/bearer': { get: { tags: ['auth-basic-modes'], operationId: 'bearerEcho', security: [{ bearerAuth: [] }], responses: jsonResponse } },
      '/auth/basic': { get: { tags: ['auth-basic-modes'], operationId: 'basicEcho', security: [{ basicAuth: [] }], responses: jsonResponse } },
      '/auth/custom-header': { get: { tags: ['auth-basic-modes'], operationId: 'customHeaderEcho', security: [{ customClientToken: [] }], responses: jsonResponse } },
      '/auth/custom-template': { get: { tags: ['auth-basic-modes'], operationId: 'customTemplateEcho', security: [{ customClientId: [] }], parameters: [{ name: 'nonce', in: 'query', schema: { type: 'string' } }], responses: jsonResponse } },
      '/auth/hmac': { post: { tags: ['auth-basic-modes'], operationId: 'hmacEcho', security: [{ hmacSignature: [] }], requestBody: { content: { 'application/json': { schema: { type: 'object' } } } }, responses: jsonResponse } },
      '/oauth/authorize': { get: { tags: ['oauth-provider'], operationId: 'fixtureOauthAuthorize', responses: { '302': { description: 'Redirect with code and state' } } } },
      '/oauth/token': { post: { tags: ['oauth-provider'], operationId: 'fixtureOauthToken', responses: jsonResponse } },
      '/oauth/userinfo': { get: { tags: ['oauth-provider'], operationId: 'fixtureOauthUserinfo', security: [{ fixtureOAuth: ['profile', 'email'] }], responses: jsonResponse } },
      '/oauth/revoke': { post: { tags: ['oauth-provider'], operationId: 'fixtureOauthRevoke', responses: jsonResponse } },
      '/real-oauth/google/login': { get: { tags: ['external-oauth-providers'], operationId: 'googleOAuthLogin', responses: { '302': { description: 'Redirect to Google OAuth consent screen' } } } },
      '/real-oauth/google/callback': { get: { tags: ['external-oauth-providers'], operationId: 'googleOAuthCallback', responses: jsonResponse } },
      '/real-oauth/github/login': { get: { tags: ['external-oauth-providers'], operationId: 'githubOAuthLogin', responses: { '302': { description: 'Redirect to GitHub OAuth consent screen' } } } },
      '/real-oauth/github/callback': { get: { tags: ['external-oauth-providers'], operationId: 'githubOAuthCallback', responses: jsonResponse } },
      '/real-oauth/google/profile': { get: { tags: ['external-oauth-providers'], operationId: 'googleOAuthProfile', security: [{ googleOAuth: ['openid', 'email', 'profile'] }], responses: jsonResponse } },
      '/real-oauth/github/profile': { get: { tags: ['external-oauth-providers'], operationId: 'githubOAuthProfile', security: [{ githubOAuth: ['read:user', 'user:email'] }], responses: jsonResponse } },
      '/exchange/google-oauth-to-jwt': { post: { tags: ['external-oauth-providers', 'chained-workflows'], operationId: 'exchangeGoogleOAuthToJwt', security: [{ googleOAuth: ['openid', 'email', 'profile'] }], responses: jsonResponse } },
      '/exchange/github-oauth-to-jwt': { post: { tags: ['external-oauth-providers', 'chained-workflows'], operationId: 'exchangeGithubOAuthToJwt', security: [{ githubOAuth: ['read:user', 'user:email'] }], responses: jsonResponse } },
      '/exchange/oauth-to-jwt': { post: { tags: ['chained-workflows'], operationId: 'exchangeOauthToJwt', security: [{ fixtureOAuth: ['mint:jwt'] }], responses: jsonResponse } },
      '/exchange/api-key-to-session': { post: { tags: ['chained-workflows'], operationId: 'exchangeApiKeyToSession', security: [{ apiKeyHeader: [] }], responses: jsonResponse } },
      '/exchange/basic-to-bearer': { post: { tags: ['chained-workflows'], operationId: 'exchangeBasicToBearer', security: [{ basicAuth: [] }], responses: jsonResponse } },
      '/exchange/jwt-to-downstream-token': { post: { tags: ['chained-workflows'], operationId: 'exchangeJwtToDownstreamToken', security: [{ bearerAuth: [] }], responses: jsonResponse } },
      '/protected/jwt/resource': { get: { tags: ['chained-workflows'], operationId: 'jwtProtectedResource', security: [{ bearerAuth: [] }], responses: jsonResponse } },
      '/protected/session/resource': { get: { tags: ['chained-workflows'], operationId: 'sessionProtectedResource', security: [{ customClientToken: [] }], responses: jsonResponse } },
      '/protected/downstream/resource': { get: { tags: ['chained-workflows'], operationId: 'downstreamProtectedResource', security: [{ bearerAuth: [] }], responses: jsonResponse } },
      '/policy/read-safe': { get: { tags: ['policies-and-logs'], operationId: 'readSafeEndpoint', responses: jsonResponse } },
      '/policy/write-safe': { post: { tags: ['policies-and-logs'], operationId: 'writeSafeEndpoint', requestBody: { content: { 'application/json': { schema: { type: 'object' } } } }, responses: jsonResponse } },
      '/policy/destructive': { delete: { tags: ['policies-and-logs'], operationId: 'destructiveEndpoint', responses: jsonResponse } },
      '/responses/large': { get: { tags: ['policies-and-logs'], operationId: 'largeResponse', responses: jsonResponse } },
      '/responses/nested': { get: { tags: ['policies-and-logs'], operationId: 'nestedResponse', responses: jsonResponse } },
      '/responses/html': { get: { tags: ['policies-and-logs'], operationId: 'htmlResponse', responses: { '200': { description: 'HTML response' } } } },
      '/responses/binary': { get: { tags: ['edge-cases'], operationId: 'binaryResponse', responses: { '200': { description: 'Binary response' } } } },
      '/edge/slow': { get: { tags: ['edge-cases'], operationId: 'slowEndpoint', parameters: [{ name: 'ms', in: 'query', schema: { type: 'integer', default: 2000 } }], responses: jsonResponse } },
      '/edge/status/{code}': { get: { tags: ['edge-cases'], operationId: 'statusEndpoint', parameters: [{ name: 'code', in: 'path', required: true, schema: { type: 'integer' } }], responses: jsonResponse } },
      '/edge/redirect': { get: { tags: ['edge-cases'], operationId: 'redirectEndpoint', responses: { '302': { description: 'Redirect' } } } },
      '/edge/rate-limit-demo': { get: { tags: ['edge-cases'], operationId: 'upstreamRateLimitDemo', responses: jsonResponse } },
    },
    'x-apitrench-fixture': {
      demoCredentials: getDemoCredentials(),
      recommendedTabs: ['Overview', 'Tools', 'Credentials', 'Gateway', 'Test', 'Logs', 'Advanced'],
    },
  };
}

function getDemoCredentials() {
  return {
    apiKeyHeader: { payload: { api_key: FIXTURE.apiKey }, applicationType: 'api_key_header', applicationConfig: { headerName: 'x-api-key', keyField: 'api_key' } },
    apiKeyQuery: { payload: { api_key: FIXTURE.apiKey }, applicationType: 'api_key_query', applicationConfig: { queryName: 'api_key', keyField: 'api_key' } },
    bearerHeader: { payload: { access_token: FIXTURE.bearerToken }, applicationType: 'bearer_header', applicationConfig: { tokenField: 'access_token', prefix: 'Bearer ' } },
    basicHeader: { payload: { username: FIXTURE.basicUser, password: FIXTURE.basicPassword }, applicationType: 'basic_header', applicationConfig: { usernameField: 'username', passwordField: 'password' } },
    customHeader: { payload: { token: FIXTURE.clientToken }, applicationType: 'custom_header', applicationConfig: { headerName: 'x-client-token', valueField: 'token' } },
    customTemplate: {
      payload: { client_id: FIXTURE.customClientId, client_secret: FIXTURE.customClientSecret },
      applicationType: 'custom_template',
      applicationConfig: {
        headers: { 'x-client-id': '{{credential.client_id}}' },
        note: 'x-client-signature must be HMAC(client_secret, client_id:nonce); this intentionally requires workflow support beyond simple static template substitution.',
      },
    },
    oauthProvider: {
      providerKey: 'apitrench-fixture',
      displayName: 'APITrench Fixture OAuth',
      authorizationUrl: `${BASE_URL}/oauth/authorize`,
      tokenUrl: `${BASE_URL}/oauth/token`,
      userinfoUrl: `${BASE_URL}/oauth/userinfo`,
      revokeUrl: `${BASE_URL}/oauth/revoke`,
      clientId: FIXTURE.oauthClientId,
      clientSecret: FIXTURE.oauthClientSecret,
      defaultScopes: ['profile', 'email', 'read:data', 'mint:jwt'],
      tokenAuthMethod: 'client_secret_post',
      pkceEnabled: true,
      userinfoMapping: { providerUserId: ['sub', 'email'], displayName: ['name', 'email'] },
    },
    externalOAuthProviders: {
      google: {
        providerKey: 'google',
        displayName: 'Google',
        authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenUrl: 'https://oauth2.googleapis.com/token',
        userinfoUrl: 'https://www.googleapis.com/oauth2/v3/userinfo',
        revokeUrl: 'https://oauth2.googleapis.com/revoke',
        clientId: FIXTURE.googleClientId ? '<configured from GOOGLE_CLIENT_ID>' : '<missing GOOGLE_CLIENT_ID>',
        clientSecret: FIXTURE.googleClientSecret ? '<configured from GOOGLE_CLIENT_SECRET>' : '<missing GOOGLE_CLIENT_SECRET>',
        fixtureLoginUrl: `${BASE_URL}/real-oauth/google/login`,
        fixtureCallbackUrl: FIXTURE.googleRedirectUri,
        defaultScopes: ['openid', 'email', 'profile'],
        tokenAuthMethod: 'client_secret_post',
        pkceEnabled: true,
        userinfoMapping: { providerUserId: ['sub', 'email'], displayName: ['name', 'email'] },
      },
      github: {
        providerKey: 'github',
        displayName: 'GitHub',
        authorizationUrl: 'https://github.com/login/oauth/authorize',
        tokenUrl: 'https://github.com/login/oauth/access_token',
        userinfoUrl: 'https://api.github.com/user',
        revokeUrl: null,
        clientId: FIXTURE.githubClientId ? '<configured from GITHUB_CLIENT_ID>' : '<missing GITHUB_CLIENT_ID>',
        clientSecret: FIXTURE.githubClientSecret ? '<configured from GITHUB_CLIENT_SECRET>' : '<missing GITHUB_CLIENT_SECRET>',
        fixtureLoginUrl: `${BASE_URL}/real-oauth/github/login`,
        fixtureCallbackUrl: FIXTURE.githubRedirectUri,
        defaultScopes: ['read:user', 'user:email'],
        tokenAuthMethod: 'client_secret_post',
        pkceEnabled: false,
        userinfoMapping: { providerUserId: ['id', 'login'], displayName: ['name', 'login', 'email'] },
      },
    },
  };
}

function successPayload(name, extra = {}) {
  return {
    ok: true,
    fixture: 'apitrench-fixture-api',
    endpoint: name,
    at: nowIso(),
    ...extra,
  };
}

function isRedirectAllowed(rawRedirectUri) {
  if (!rawRedirectUri) return false;
  if (ALLOWED_REDIRECT_ORIGINS.includes('*')) return true;
  try {
    const origin = new URL(rawRedirectUri).origin;
    return ALLOWED_REDIRECT_ORIGINS.includes(origin);
  } catch {
    return false;
  }
}

async function route(req, res) {
  const url = new URL(req.url, BASE_URL);
  const pathname = url.pathname;

  if (req.method === 'GET' && pathname === '/health') {
    return json(res, 200, successPayload('health', { service: 'fixture-api' }));
  }

  if (req.method === 'GET' && pathname === '/') {
    return json(res, 200, successPayload('root', {
      docs: `${BASE_URL}/public/openapi.json`,
      demoCredentials: `${BASE_URL}/public/demo-credentials`,
      importHint: 'Import /public/openapi.json into APITrench, then configure credential seeds and gateway keys.',
    }));
  }

  if (req.method === 'GET' && pathname === '/public/openapi.json') {
    return json(res, 200, getOpenApi());
  }

  if (req.method === 'GET' && pathname === '/public/demo-credentials') {
    return json(res, 200, getDemoCredentials());
  }

  if (req.method === 'GET' && pathname === '/public/ping') {
    return json(res, 200, successPayload('publicPing', { authRequired: false }));
  }

  if (req.method === 'GET' && pathname === '/auth/api-key-header') {
    if (!requireApiKeyHeader(req, res)) return;
    return json(res, 200, successPayload('apiKeyHeaderEcho', { auth: 'api_key_header' }));
  }

  if (req.method === 'GET' && pathname === '/auth/api-key-query') {
    if (!requireApiKeyQuery(url, res)) return;
    return json(res, 200, successPayload('apiKeyQueryEcho', { auth: 'api_key_query' }));
  }

  if (req.method === 'GET' && pathname === '/auth/bearer') {
    if (!requireBearer(req, res)) return;
    return json(res, 200, successPayload('bearerEcho', { auth: 'bearer_header' }));
  }

  if (req.method === 'GET' && pathname === '/auth/basic') {
    if (!requireBasic(req, res)) return;
    return json(res, 200, successPayload('basicEcho', { auth: 'basic_header' }));
  }

  if (req.method === 'GET' && pathname === '/auth/custom-header') {
    if (!requireCustomHeader(req, res)) return;
    return json(res, 200, successPayload('customHeaderEcho', { auth: 'custom_header' }));
  }

  if (req.method === 'GET' && pathname === '/auth/custom-template') {
    if (!requireCustomTemplate(req, url, res)) return;
    return json(res, 200, successPayload('customTemplateEcho', { auth: 'custom_template_plus_hmac' }));
  }

  if (req.method === 'POST' && pathname === '/auth/hmac') {
    const raw = await readBody(req);
    if (!requireHmac(req, res, raw)) return;
    let parsed = null;
    try { parsed = raw ? JSON.parse(raw) : null; } catch { parsed = raw; }
    return json(res, 200, successPayload('hmacEcho', { auth: 'hmac_signature', received: parsed }));
  }

  if (req.method === 'GET' && pathname === '/oauth/authorize') {
    const responseType = url.searchParams.get('response_type');
    const clientId = url.searchParams.get('client_id');
    const redirectUri = url.searchParams.get('redirect_uri');
    const state = url.searchParams.get('state') || '';
    const scope = url.searchParams.get('scope') || 'profile email read:data mint:jwt';
    const codeChallenge = url.searchParams.get('code_challenge');
    const codeChallengeMethod = url.searchParams.get('code_challenge_method');

    if (responseType !== 'code') return badRequest(res, 'response_type must be code');
    if (clientId !== FIXTURE.oauthClientId) return badRequest(res, 'Unknown OAuth client_id', { demoClientId: FIXTURE.oauthClientId });
    if (!isRedirectAllowed(redirectUri)) return badRequest(res, 'redirect_uri origin is not allowed', { allowedOrigins: ALLOWED_REDIRECT_ORIGINS });

    const code = randomToken('code');
    codeStore.set(code, {
      clientId,
      redirectUri,
      state,
      scopes: scope.split(/\s+/).filter(Boolean),
      codeChallenge,
      codeChallengeMethod,
      createdAt: Date.now(),
      expiresAt: Date.now() + 10 * 60 * 1000,
      used: false,
    });

    const out = new URL(redirectUri);
    out.searchParams.set('code', code);
    if (state) out.searchParams.set('state', state);
    return redirect(res, out.toString());
  }

  if (req.method === 'POST' && pathname === '/oauth/token') {
    const body = await parseBody(req);
    const grantType = body.grant_type || body.grantType;
    const clientId = body.client_id || body.clientId;
    const clientSecret = body.client_secret || body.clientSecret;

    if (clientId !== FIXTURE.oauthClientId) return unauthorized(res, 'Invalid OAuth client_id', { demoClientId: FIXTURE.oauthClientId });
    if (clientSecret && clientSecret !== FIXTURE.oauthClientSecret) return unauthorized(res, 'Invalid OAuth client_secret');

    if (grantType === 'authorization_code') {
      const code = body.code;
      const record = codeStore.get(code);
      if (!record || record.used || record.expiresAt <= Date.now()) return badRequest(res, 'Invalid or expired authorization code');
      if (body.redirect_uri && body.redirect_uri !== record.redirectUri) return badRequest(res, 'redirect_uri mismatch');
      if (record.codeChallenge) {
        const verifier = body.code_verifier || body.codeVerifier;
        if (!verifier) return badRequest(res, 'Missing PKCE code_verifier');
        const expected = record.codeChallengeMethod === 'plain' ? verifier : sha256Base64Url(verifier);
        if (expected !== record.codeChallenge) return badRequest(res, 'Invalid PKCE code_verifier');
      }
      record.used = true;
      return json(res, 200, issueOAuthTokens({ clientId, scopes: record.scopes, metadata: { grant: 'authorization_code' } }));
    }

    if (grantType === 'refresh_token') {
      const refreshToken = body.refresh_token || body.refreshToken;
      const existing = refreshTokenStore.get(refreshToken);
      if (!existing || revokedTokens.has(refreshToken)) return badRequest(res, 'Invalid refresh token');
      return json(res, 200, issueOAuthTokens({
        clientId: existing.clientId,
        userId: existing.userId,
        displayName: existing.displayName,
        email: existing.email,
        scopes: existing.scopes,
        metadata: { grant: 'refresh_token' },
      }));
    }

    if (grantType === 'client_credentials') {
      if (clientSecret !== FIXTURE.oauthClientSecret) return unauthorized(res, 'client_credentials requires client_secret');
      const scope = String(body.scope || 'read:data').split(/\s+/).filter(Boolean);
      return json(res, 200, issueOAuthTokens({
        clientId,
        userId: 'service_fixture_123',
        displayName: 'Fixture Service Client',
        email: 'service-client@example.com',
        scopes: scope,
        metadata: { grant: 'client_credentials' },
      }));
    }

    return badRequest(res, 'Unsupported grant_type', { supported: ['authorization_code', 'refresh_token', 'client_credentials'] });
  }

  if (req.method === 'GET' && pathname === '/oauth/userinfo') {
    const resolved = requireOAuthAccessToken(req, res);
    if (!resolved) return;
    return json(res, 200, {
      sub: resolved.record.userId,
      id: resolved.record.userId,
      email: resolved.record.email,
      name: resolved.record.displayName,
      preferred_username: 'fixture-user',
      scopes: resolved.record.scopes,
      provider: 'apitrench-fixture',
    });
  }

  if (req.method === 'POST' && pathname === '/oauth/revoke') {
    const body = await parseBody(req);
    const token = body.token || body.access_token || body.refresh_token;
    if (token) revokedTokens.add(token);
    return json(res, 200, successPayload('oauthRevoke', { revoked: Boolean(token) }));
  }


  if (req.method === 'GET' && pathname === '/real-oauth/google/login') {
    const out = buildExternalOAuthAuthorizationUrl('google');
    return redirect(res, out.authorizationUrl);
  }

  if (req.method === 'GET' && pathname === '/real-oauth/google/callback') {
    const out = await completeExternalOAuthCallback('google', url);
    return json(res, 200, successPayload('googleOAuthCallback', {
      provider: 'google',
      tokenPayload: out.tokenPayload,
      profile: out.profile,
      nextManualTests: {
        profile: `curl -H "Authorization: Bearer ${out.tokenPayload.access_token}" ${BASE_URL}/real-oauth/google/profile`,
        exchangeToJwt: `curl -X POST -H "Authorization: Bearer ${out.tokenPayload.access_token}" ${BASE_URL}/exchange/google-oauth-to-jwt`,
      },
    }));
  }

  if (req.method === 'GET' && pathname === '/real-oauth/github/login') {
    const out = buildExternalOAuthAuthorizationUrl('github');
    return redirect(res, out.authorizationUrl);
  }

  if (req.method === 'GET' && pathname === '/real-oauth/github/callback') {
    const out = await completeExternalOAuthCallback('github', url);
    return json(res, 200, successPayload('githubOAuthCallback', {
      provider: 'github',
      tokenPayload: out.tokenPayload,
      profile: out.profile,
      nextManualTests: {
        profile: `curl -H "Authorization: Bearer ${out.tokenPayload.access_token}" ${BASE_URL}/real-oauth/github/profile`,
        exchangeToJwt: `curl -X POST -H "Authorization: Bearer ${out.tokenPayload.access_token}" ${BASE_URL}/exchange/github-oauth-to-jwt`,
      },
    }));
  }

  if (req.method === 'GET' && pathname === '/real-oauth/google/profile') {
    const profile = await resolveExternalOAuthProfile(req, 'google');
    return json(res, 200, successPayload('googleOAuthProfile', {
      auth: 'real_google_oauth_access_token',
      profile,
    }));
  }

  if (req.method === 'GET' && pathname === '/real-oauth/github/profile') {
    const profile = await resolveExternalOAuthProfile(req, 'github');
    return json(res, 200, successPayload('githubOAuthProfile', {
      auth: 'real_github_oauth_access_token',
      profile,
    }));
  }

  if (req.method === 'POST' && pathname === '/exchange/google-oauth-to-jwt') {
    const profile = await resolveExternalOAuthProfile(req, 'google');
    const jwt = signJwt({
      sub: profile.providerUserId,
      email: profile.email,
      name: profile.displayName,
      provider: 'google',
      source: 'google_oauth_access_token',
      scopes: ['openid', 'email', 'profile'],
    });
    return json(res, 200, successPayload('exchangeGoogleOAuthToJwt', {
      jwt,
      token_type: 'Bearer',
      expires_in: 900,
      providerProfile: profile,
      next: `${BASE_URL}/protected/jwt/resource`,
      workflow: ['Google OAuth authorization_code', 'Google access_token', 'exchange Google token to fixture JWT', 'call JWT protected resource'],
    }));
  }

  if (req.method === 'POST' && pathname === '/exchange/github-oauth-to-jwt') {
    const profile = await resolveExternalOAuthProfile(req, 'github');
    const jwt = signJwt({
      sub: profile.providerUserId,
      email: profile.email,
      name: profile.displayName,
      username: profile.username,
      provider: 'github',
      source: 'github_oauth_access_token',
      scopes: ['read:user', 'user:email'],
    });
    return json(res, 200, successPayload('exchangeGithubOAuthToJwt', {
      jwt,
      token_type: 'Bearer',
      expires_in: 900,
      providerProfile: profile,
      next: `${BASE_URL}/protected/jwt/resource`,
      workflow: ['GitHub OAuth authorization_code', 'GitHub access_token', 'exchange GitHub token to fixture JWT', 'call JWT protected resource'],
    }));
  }

  if (req.method === 'POST' && pathname === '/exchange/oauth-to-jwt') {
    const resolved = requireOAuthAccessToken(req, res, 'mint:jwt');
    if (!resolved) return;
    const jwt = signJwt({
      sub: resolved.record.userId,
      email: resolved.record.email,
      scopes: resolved.record.scopes,
      source: 'oauth_access_token',
    });
    return json(res, 200, successPayload('exchangeOauthToJwt', {
      jwt,
      token_type: 'Bearer',
      expires_in: 900,
      next: `${BASE_URL}/protected/jwt/resource`,
      workflow: ['OAuth authorization_code', 'OAuth access_token', 'exchange OAuth token to JWT', 'call JWT protected resource'],
    }));
  }

  if (req.method === 'POST' && pathname === '/exchange/api-key-to-session') {
    if (!requireApiKeyHeader(req, res)) return;
    const sessionToken = randomToken('session');
    sessionStore.set(sessionToken, { createdAt: Date.now(), expiresAt: Date.now() + 30 * 60 * 1000, source: 'api_key_header' });
    return json(res, 200, successPayload('exchangeApiKeyToSession', {
      session_token: sessionToken,
      token_type: 'CustomHeader',
      header_name: 'x-client-token',
      next: `${BASE_URL}/protected/session/resource`,
    }));
  }

  if (req.method === 'POST' && pathname === '/exchange/basic-to-bearer') {
    if (!requireBasic(req, res)) return;
    const token = randomToken('bearer_exchanged');
    accessTokenStore.set(token, {
      clientId: 'basic-exchange',
      userId: 'basic_user_fixture',
      displayName: 'Basic Exchanged User',
      email: 'basic-user@example.com',
      scopes: ['read:data'],
      createdAt: Date.now(),
      expiresAt: Date.now() + 1800 * 1000,
      metadata: { source: 'basic_to_bearer' },
    });
    return json(res, 200, successPayload('exchangeBasicToBearer', {
      access_token: token,
      token_type: 'Bearer',
      expires_in: 1800,
      next: `${BASE_URL}/oauth/userinfo`,
    }));
  }

  if (req.method === 'POST' && pathname === '/exchange/jwt-to-downstream-token') {
    const payload = requireJwt(req, res);
    if (!payload) return;
    const downstreamToken = randomToken('downstream');
    sessionStore.set(downstreamToken, { createdAt: Date.now(), expiresAt: Date.now() + 600 * 1000, source: 'jwt', sub: payload.sub });
    return json(res, 200, successPayload('exchangeJwtToDownstreamToken', {
      access_token: downstreamToken,
      token_type: 'Bearer',
      expires_in: 600,
      next: `${BASE_URL}/protected/downstream/resource`,
    }));
  }

  if (req.method === 'GET' && pathname === '/protected/jwt/resource') {
    const payload = requireJwt(req, res);
    if (!payload) return;
    return json(res, 200, successPayload('jwtProtectedResource', {
      auth: 'jwt',
      subject: payload.sub,
      scopes: payload.scopes || [],
      secretProof: 'jwt signature verified',
    }));
  }

  if (req.method === 'GET' && pathname === '/protected/session/resource') {
    const token = getHeader(req, 'x-client-token');
    const session = token ? sessionStore.get(token) : null;
    if (!session || session.expiresAt <= Date.now()) {
      return unauthorized(res, 'Expected x-client-token containing exchanged session token');
    }
    return json(res, 200, successPayload('sessionProtectedResource', {
      auth: 'exchanged_session_token',
      sessionSource: session.source,
    }));
  }

  if (req.method === 'GET' && pathname === '/protected/downstream/resource') {
    const auth = getHeader(req, 'authorization') || '';
    const token = auth.startsWith('Bearer ') ? auth.slice('Bearer '.length).trim() : null;
    const session = token ? sessionStore.get(token) : null;
    if (!session || session.expiresAt <= Date.now()) {
      return unauthorized(res, 'Expected downstream Bearer token from /exchange/jwt-to-downstream-token');
    }
    return json(res, 200, successPayload('downstreamProtectedResource', {
      auth: 'jwt_exchanged_downstream_bearer',
      subject: session.sub,
    }));
  }

  if (req.method === 'GET' && pathname === '/policy/read-safe') {
    return json(res, 200, successPayload('readSafeEndpoint', { safetyLevel: 'read', requiresHumanApproval: false }));
  }

  if (req.method === 'POST' && pathname === '/policy/write-safe') {
    const body = await parseBody(req);
    return json(res, 200, successPayload('writeSafeEndpoint', { safetyLevel: 'write', received: body }));
  }

  if (req.method === 'DELETE' && pathname === '/policy/destructive') {
    return json(res, 200, successPayload('destructiveEndpoint', {
      safetyLevel: 'destructive',
      requiresHumanApproval: true,
      warning: 'This endpoint does not delete anything; it exists to test APITrench approval gates.',
    }));
  }

  if (req.method === 'GET' && pathname === '/responses/large') {
    const count = Math.min(Number(url.searchParams.get('count') || 250), 2000);
    const items = Array.from({ length: count }, (_, index) => ({
      id: `item_${index + 1}`,
      name: `Fixture Item ${index + 1}`,
      description: 'This repeated field exists to test response slimming, truncation metadata, and max array item policies.',
      metadata: {
        debug_trace_id: randomToken('trace'),
        internal_notes: 'Should be removable by response policy strip/debug behavior.',
        links: { self: `${BASE_URL}/items/${index + 1}` },
      },
    }));
    return json(res, 200, successPayload('largeResponse', { count, items }));
  }

  if (req.method === 'GET' && pathname === '/responses/nested') {
    return json(res, 200, successPayload('nestedResponse', {
      organization: {
        id: 'org_fixture',
        teams: [
          {
            id: 'team_red',
            members: [
              { id: 'u1', name: 'Ava', secrets: { api_key: 'should_be_redacted' } },
              { id: 'u2', name: 'Noah', tokens: { access_token: 'should_be_redacted' } },
            ],
          },
        ],
      },
      debug: { rawHeaders: req.headers, internalTiming: { db: 12, upstream: 34 } },
      html: '<div><strong>Hello</strong> fixture</div>',
      nullable: null,
      emptyObject: {},
      emptyArray: [],
    }));
  }

  if (req.method === 'GET' && pathname === '/responses/html') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end('<!doctype html><html><body><h1>Fixture HTML</h1><script>window.secret="do-not-return"</script><p>Use this to test strip_html.</p></body></html>');
  }

  if (req.method === 'GET' && pathname === '/responses/binary') {
    const buffer = crypto.randomBytes(128);
    res.writeHead(200, { 'content-type': 'application/octet-stream' });
    return res.end(buffer);
  }

  if (req.method === 'GET' && pathname === '/edge/slow') {
    const ms = Math.min(Math.max(Number(url.searchParams.get('ms') || 2000), 0), 65000);
    await new Promise((resolve) => setTimeout(resolve, ms));
    return json(res, 200, successPayload('slowEndpoint', { sleptMs: ms }));
  }

  const statusMatch = pathname.match(/^\/edge\/status\/(\d{3})$/);
  if (req.method === 'GET' && statusMatch) {
    const code = Math.min(Math.max(Number(statusMatch[1]), 100), 599);
    return json(res, code, successPayload('statusEndpoint', { requestedStatus: code }));
  }

  if (req.method === 'GET' && pathname === '/edge/redirect') {
    return redirect(res, `${BASE_URL}/public/ping`);
  }

  if (req.method === 'GET' && pathname === '/edge/rate-limit-demo') {
    const key = getHeader(req, 'x-api-key') || getHeader(req, 'authorization') || req.socket.remoteAddress || 'anonymous';
    const bucket = invocationCounters.get(key) || { count: 0, resetAt: Date.now() + 60_000 };
    if (bucket.resetAt <= Date.now()) {
      bucket.count = 0;
      bucket.resetAt = Date.now() + 60_000;
    }
    bucket.count += 1;
    invocationCounters.set(key, bucket);
    if (bucket.count > 5) {
      return json(res, 429, {
        error: 'fixture_upstream_rate_limited',
        message: 'This simulates an upstream provider rate limit after 5 calls per minute per presented key.',
        resetAt: new Date(bucket.resetAt).toISOString(),
      }, {
        'x-upstream-ratelimit-limit': '5',
        'x-upstream-ratelimit-remaining': '0',
        'x-upstream-ratelimit-reset': String(Math.ceil(bucket.resetAt / 1000)),
      });
    }
    return json(res, 200, successPayload('upstreamRateLimitDemo', {
      count: bucket.count,
      remaining: Math.max(5 - bucket.count, 0),
      resetAt: new Date(bucket.resetAt).toISOString(),
    }), {
      'x-upstream-ratelimit-limit': '5',
      'x-upstream-ratelimit-remaining': String(Math.max(5 - bucket.count, 0)),
      'x-upstream-ratelimit-reset': String(Math.ceil(bucket.resetAt / 1000)),
    });
  }

  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && pathname.startsWith('/auth/')) {
    return methodNotAllowed(res, ['GET']);
  }

  return notFound(res, req);
}

const server = http.createServer(async (req, res) => {
  try {
    await route(req, res);
  } catch (error) {
    const status = error.statusCode || 500;
    json(res, status, {
      error: status >= 500 ? 'internal_error' : 'request_error',
      message: error.message || 'Unexpected fixture API error',
      at: nowIso(),
    });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`APITrench fixture API listening on ${PORT}`);
  console.log(`OpenAPI: ${BASE_URL}/public/openapi.json`);
});
