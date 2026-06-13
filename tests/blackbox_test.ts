import { assertEquals, assertNotEquals } from '@std/assert';

const BASE = Deno.env.get('MCP_SERVER_URL') || 'http://localhost:8000';
const ISSUER = Deno.env.get('ISSUER') || BASE;

Deno.test('blackbox: discovery metadata', async () => {
  const res = await fetch(`${BASE}/.well-known/oauth-authorization-server`);
  assertEquals(res.status, 200);
  const body = await res.json();
  assertEquals(body.issuer, ISSUER);
  assertEquals(body.authorization_endpoint, `${ISSUER}/authorize`);
  assertEquals(body.token_endpoint, `${ISSUER}/token`);
  assertEquals(body.registration_endpoint, `${ISSUER}/register`);
  assertEquals(body.response_types_supported, ['code']);
  assertEquals(body.grant_types_supported, [
    'authorization_code',
    'refresh_token',
  ]);
  assertEquals(body.code_challenge_methods_supported, ['S256']);
});

Deno.test('blackbox: DCR register', async () => {
  const res = await fetch(`${BASE}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'blackbox-test',
      redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
    }),
  });
  assertEquals(res.status, 201);
  const body = await res.json();
  assertEquals(typeof body.client_id, 'string');
  assertEquals(typeof body.client_secret, 'string');
  assertEquals(body.client_secret_expires_at, 0);
});

Deno.test('blackbox: authorize form', async () => {
  const res = await fetch(
    `${BASE}/authorize?response_type=code&client_id=test&redirect_uri=https://claude.ai/api/mcp/auth_callback&code_challenge=abc123&code_challenge_method=S256&state=xyz`,
  );
  assertEquals(res.status, 200);
  const text = await res.text();
  assertEquals(text.includes('<form'), true);
  assertEquals(text.includes('abc123'), true);
  assertEquals(text.includes('xyz'), true);
});

Deno.test('blackbox: full OAuth flow + MCP tool call', async () => {
  // 1. Generate PKCE challenge
  const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const encoder = new TextEncoder();
  const hash = await crypto.subtle.digest(
    'SHA-256',
    encoder.encode(codeVerifier),
  );
  const challenge = btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  // 2. Authorize: post storage config
  const formData = new FormData();
  formData.append('endpoint', 'https://s3.us-east-1.amazonaws.com');
  formData.append('region', 'us-east-1');
  formData.append('bucket', 'test-bucket');
  formData.append('accessKeyId', 'AKIAIOSFODNN7EXAMPLE');
  formData.append(
    'secretAccessKey',
    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  );
  formData.append(
    'publicUrlBase',
    'https://test-bucket.s3.us-east-1.amazonaws.com',
  );
  formData.append('redirect_uri', 'https://claude.ai/api/mcp/auth_callback');
  formData.append('state', 'test-state');
  formData.append('code_challenge', challenge);

  const authRes = await fetch(`${BASE}/authorize`, {
    method: 'POST',
    body: formData,
    redirect: 'manual',
  });
  assertEquals(authRes.status, 302);
  const location = authRes.headers.get('location') || '';
  assertEquals(
    location.startsWith('https://claude.ai/api/mcp/auth_callback?code='),
    true,
  );
  const code = new URL(location).searchParams.get('code') || '';
  await authRes.body?.cancel();
  const state = new URL(location).searchParams.get('state');
  assertEquals(state, 'test-state');
  assertNotEquals(code, '');

  // 3. Exchange code for tokens
  const tokenBody = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: 'https://claude.ai/api/mcp/auth_callback',
    code_verifier: codeVerifier,
  });

  const tokenRes = await fetch(`${BASE}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: tokenBody.toString(),
  });
  assertEquals(tokenRes.status, 200);
  const tokens = await tokenRes.json();
  assertEquals(tokens.token_type, 'Bearer');
  assertEquals(typeof tokens.access_token, 'string');
  assertEquals(typeof tokens.refresh_token, 'string');
  const accessToken = tokens.access_token;

  // 4. Call MCP tools/list
  const listRes = await fetch(`${BASE}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'authorization': `Bearer ${accessToken}`,
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
    }),
  });
  assertEquals(listRes.status, 200);
  const listBody = await listRes.json();
  assertEquals(listBody.result.tools.length, 1);
  assertEquals(listBody.result.tools[0].name, 'get_upload_url');

  // 5. Call MCP tools/call
  const callRes = await fetch(`${BASE}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'authorization': `Bearer ${accessToken}`,
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: {
        name: 'get_upload_url',
        arguments: { filename: 'acceptance-test.png' },
      },
    }),
  });
  assertEquals(callRes.status, 200);
  const callBody = await callRes.json();
  const parsed = JSON.parse(callBody.result.content[0].text);
  assertEquals(typeof parsed.url, 'string');
  assertEquals(parsed.url.includes('X-Amz-Signature'), true);
  assertEquals(parsed.publicUrl.endsWith('/acceptance-test.png'), true);

  // 6. Refresh token
  const refreshBody = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: tokens.refresh_token,
  });
  const refreshRes = await fetch(`${BASE}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: refreshBody.toString(),
  });
  assertEquals(refreshRes.status, 200);
  const refreshed = await refreshRes.json();
  assertEquals(typeof refreshed.access_token, 'string');
  assertNotEquals(refreshed.access_token, accessToken);
});

Deno.test('blackbox: /mcp rejects unauthenticated request', async () => {
  const res = await fetch(`${BASE}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
    }),
  });
  assertEquals(res.status, 401);
  await res.body?.cancel();
});
