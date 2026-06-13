import { assertEquals } from '@std/assert';
import { createRegistrationHandler } from './register.ts';
import { Hono } from 'hono';

Deno.test('POST /register returns client credentials', async () => {
  const app = new Hono();
  const hmacSecret = new TextEncoder().encode('test-hmac-secret');
  app.post('/register', createRegistrationHandler(hmacSecret));

  const res = await app.request('/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'test-client',
      redirect_uris: ['http://localhost/callback'],
    }),
  });

  assertEquals(res.status, 201);
  const body = await res.json();
  assertEquals(typeof body.client_id, 'string');
  assertEquals(typeof body.client_secret, 'string');
  assertEquals(body.client_secret_expires_at, 0);
  assertEquals(body.token_endpoint_auth_method, 'none');
  assertEquals(typeof body.client_id_issued_at, 'number');
});

Deno.test('POST /register client_secret is HMAC of client_id', async () => {
  const hmacSecret = new TextEncoder().encode('test-hmac-secret');
  const handler = createRegistrationHandler(hmacSecret);

  const app = new Hono();
  app.post('/register', handler);

  const res = await app.request('/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ redirect_uris: ['http://localhost/callback'] }),
  });

  const body = await res.json();
  assertEquals(body.client_secret.length, 64);
});

Deno.test('POST /register with invalid content-type is rejected', async () => {
  const app = new Hono();
  app.post('/register', createRegistrationHandler(new Uint8Array(32)));

  const res = await app.request('/register', {
    method: 'POST',
    headers: { 'content-type': 'text/plain' },
    body: 'not json',
  });

  assertEquals(res.status, 400);
});

Deno.test('POST /register with missing redirect_uris is rejected', async () => {
  const app = new Hono();
  app.post('/register', createRegistrationHandler(new Uint8Array(32)));

  const res = await app.request('/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'test' }),
  });

  assertEquals(res.status, 400);
});
