import { assertEquals } from '@std/assert';
import { createAuthorizeHandler } from './authorize.ts';
import { Hono } from 'hono';

function makeApp() {
  const app = new Hono();
  const encKey = new Uint8Array(32);
  app.get(
    '/authorize',
    createAuthorizeHandler(encKey, 'http://localhost:8000'),
  );
  app.post(
    '/authorize',
    createAuthorizeHandler(encKey, 'http://localhost:8000'),
  );
  return app;
}

Deno.test('GET /authorize includes bulk config modal with template', async () => {
  const app = makeApp();
  const res = await app.request('/authorize');
  const text = await res.text();

  assertEquals(text.includes('Paste config'), true);
  assertEquals(text.includes('S3_ENDPOINT'), true);
  assertEquals(text.includes('S3_REGION'), true);
  assertEquals(text.includes('S3_BUCKET'), true);
  assertEquals(text.includes('S3_ACCESS_KEY_ID'), true);
  assertEquals(text.includes('S3_SECRET_ACCESS_KEY'), true);
  assertEquals(text.includes('S3_PUBLIC_URL_BASE'), true);
  assertEquals(text.includes('S3_KEY_PREFIX'), true);
});

Deno.test('GET /authorize returns HTML form with OAuth params preserved', async () => {
  const app = makeApp();
  const res = await app.request(
    '/authorize?response_type=code&client_id=test&redirect_uri=https://claude.ai/api/mcp/auth_callback&code_challenge=abc123&code_challenge_method=S256&state=xyz',
  );
  assertEquals(res.status, 200);
  const text = await res.text();
  assertEquals(text.includes('input'), true);
  assertEquals(text.includes('abc123'), true);
  assertEquals(text.includes('xyz'), true);
});

Deno.test('POST /authorize with valid config redirects with code', async () => {
  const app = makeApp();
  const formData = new FormData();
  formData.append('endpoint', 'https://s3.us-east-1.amazonaws.com');
  formData.append('region', 'us-east-1');
  formData.append('bucket', 'my-bucket');
  formData.append('accessKeyId', 'AKIA123');
  formData.append('secretAccessKey', 'secret123');
  formData.append('publicUrlBase', 'https://my-bucket.public.url/');
  formData.append('keyPrefix', 'uploads/');
  formData.append('redirect_uri', 'https://claude.ai/api/mcp/auth_callback');
  formData.append('state', 'xyz');
  formData.append('code_challenge', 'challenge123');

  const res = await app.request('/authorize', {
    method: 'POST',
    body: formData,
  });

  assertEquals(res.status, 302);
  const location = res.headers.get('location') || '';
  assertEquals(
    location.startsWith('https://claude.ai/api/mcp/auth_callback?code='),
    true,
  );
  assertEquals(location.includes('&state=xyz'), true);
});

Deno.test('POST /authorize without redirect_uri defaults to claude callback', async () => {
  const app = makeApp();
  const formData = new FormData();
  formData.append('endpoint', 'https://s3.us-east-1.amazonaws.com');
  formData.append('region', 'us-east-1');
  formData.append('bucket', 'my-bucket');
  formData.append('accessKeyId', 'AKIA123');
  formData.append('secretAccessKey', 'secret123');
  formData.append('publicUrlBase', 'https://my-bucket.public.url/');

  const res = await app.request('/authorize', {
    method: 'POST',
    body: formData,
  });

  assertEquals(res.status, 302);
  const location = res.headers.get('location') || '';
  assertEquals(
    location.startsWith('https://claude.ai/api/mcp/auth_callback?code='),
    true,
  );
});

Deno.test('POST /authorize with missing required fields returns form with error', async () => {
  const app = makeApp();
  const formData = new FormData();
  formData.append('endpoint', 'https://s3.us-east-1.amazonaws.com');

  const res = await app.request('/authorize', {
    method: 'POST',
    body: formData,
  });

  assertEquals(res.status, 200);
  const text = await res.text();
  assertEquals(text.includes('Missing required field'), true);
});
