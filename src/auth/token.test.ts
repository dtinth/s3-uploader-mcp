import { assertEquals, assertRejects } from '@std/assert';
import { createTokenHandler, computePkceChallenge } from './token.ts';
import { encrypt } from '../crypto/jwe.ts';
import { Hono } from 'hono';

function makeKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}

Deno.test('verifyPkceChallenge validates S256 code verifier', async () => {
  const codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const challenge = await computePkceChallenge(codeVerifier);
  const expected = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
  assertEquals(challenge, expected);
});

Deno.test('POST /token exchanges auth code for tokens', async () => {
  const encKey = makeKey();
  const hmacSecret = makeKey();
  const app = new Hono();
  app.post('/token', createTokenHandler(encKey, hmacSecret));

  const code = await encrypt(
    {
      endpoint: 'https://s3.us-east-1.amazonaws.com',
      region: 'us-east-1',
      bucket: 'my-bucket',
      accessKeyId: 'AKIA123',
      secretAccessKey: 'secret123',
      publicUrlBase: 'https://my-bucket.public.url/',
      codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      typ: 'auth_code',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
    },
    encKey,
  );

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: 'https://claude.ai/api/mcp/auth_callback',
    code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
  });

  const res = await app.request('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  assertEquals(res.status, 200);
  const json = await res.json();
  assertEquals(json.token_type, 'Bearer');
  assertEquals(typeof json.access_token, 'string');
  assertEquals(typeof json.refresh_token, 'string');
  assertEquals(typeof json.expires_in, 'number');
});

Deno.test('POST /token rejects wrong code_verifier', async () => {
  const encKey = makeKey();
  const hmacSecret = makeKey();
  const app = new Hono();
  app.post('/token', createTokenHandler(encKey, hmacSecret));

  const code = await encrypt(
    {
      endpoint: 'https://s3.us-east-1.amazonaws.com',
      region: 'us-east-1',
      bucket: 'my-bucket',
      accessKeyId: 'AKIA123',
      secretAccessKey: 'secret123',
      publicUrlBase: 'https://my-bucket.public.url/',
      codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      typ: 'auth_code',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
    },
    encKey,
  );

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: 'https://claude.ai/api/mcp/auth_callback',
    code_verifier: 'wrong-verifier',
  });

  const res = await app.request('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  assertEquals(res.status, 400);
  const json = await res.json();
  assertEquals(json.error, 'invalid_grant');
});

Deno.test('POST /token rejects non-auth_code tokens', async () => {
  const encKey = makeKey();
  const app = new Hono();
  app.post('/token', createTokenHandler(encKey, makeKey()));

  const token = await encrypt(
    {
      endpoint: 'https://s3.us-east-1.amazonaws.com',
      region: 'us-east-1',
      bucket: 'my-bucket',
      accessKeyId: 'AKIA123',
      secretAccessKey: 'secret123',
      publicUrlBase: 'https://my-bucket.public.url/',
      typ: 'access_token',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    },
    encKey,
  );

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: token,
    redirect_uri: 'https://claude.ai/api/mcp/auth_callback',
    code_verifier: 'test',
  });

  const res = await app.request('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  assertEquals(res.status, 400);
});

Deno.test('POST /token supports refresh_token grant type', async () => {
  const encKey = makeKey();
  const app = new Hono();
  app.post('/token', createTokenHandler(encKey, makeKey()));

  const refreshToken = await encrypt(
    {
      endpoint: 'https://s3.us-east-1.amazonaws.com',
      region: 'us-east-1',
      bucket: 'my-bucket',
      accessKeyId: 'AKIA123',
      secretAccessKey: 'secret123',
      publicUrlBase: 'https://my-bucket.public.url/',
      typ: 'refresh_token',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 86400 * 365,
    },
    encKey,
  );

  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
  });

  const res = await app.request('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  assertEquals(res.status, 200);
  const json = await res.json();
  assertEquals(json.token_type, 'Bearer');
  assertEquals(typeof json.access_token, 'string');
  assertEquals(typeof json.refresh_token, 'string');
});
