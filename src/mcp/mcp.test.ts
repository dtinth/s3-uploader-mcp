import { assertEquals } from '@std/assert';
import { createMcpHandler } from './mcp.ts';
import { encrypt } from '../crypto/jwe.ts';
import { Hono } from 'hono';

function makeKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}

async function createToken(key: Uint8Array) {
  return await encrypt(
    {
      endpoint: 'https://s3.us-east-1.amazonaws.com',
      region: 'us-east-1',
      bucket: 'test-bucket',
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      publicUrlBase: 'https://test-bucket.s3.us-east-1.amazonaws.com',
      typ: 'access_token',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    },
    key,
  );
}

Deno.test('POST /mcp initialize returns capabilities', async () => {
  const encKey = makeKey();
  const app = new Hono();
  app.post('/mcp', createMcpHandler(encKey, 'http://localhost:8000/mcp'));

  const token = await createToken(encKey);
  const res = await app.request('/mcp', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'test', version: '1.0' },
      },
    }),
  });

  assertEquals(res.status, 200);
  const body = await res.json();
  assertEquals(body.jsonrpc, '2.0');
  assertEquals(body.id, 1);
  assertEquals(body.result.protocolVersion, '2024-11-05');
  assertEquals(body.result.serverInfo.name, 's3-uploader-mcp');
});

Deno.test('POST /mcp tools/list returns tools', async () => {
  const encKey = makeKey();
  const app = new Hono();
  app.post('/mcp', createMcpHandler(encKey, 'http://localhost:8000/mcp'));

  const token = await createToken(encKey);
  const res = await app.request('/mcp', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/list',
    }),
  });

  assertEquals(res.status, 200);
  const body = await res.json();
  assertEquals(body.jsonrpc, '2.0');
  assertEquals(body.id, 2);
  assertEquals(body.result.tools.length, 1);
  assertEquals(body.result.tools[0].name, 'get_upload_url');
  assertEquals(body.result.tools[0].inputSchema.required, ['filename']);
});

Deno.test('POST /mcp tools/call get_upload_url returns presigned URL', async () => {
  const encKey = makeKey();
  const app = new Hono();
  app.post('/mcp', createMcpHandler(encKey, 'http://localhost:8000/mcp'));

  const token = await createToken(encKey);
  const res = await app.request('/mcp', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'authorization': `Bearer ${token}`,
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'get_upload_url',
        arguments: { filename: 'test.png' },
      },
    }),
  });

  assertEquals(res.status, 200);
  const body = await res.json();
  assertEquals(body.jsonrpc, '2.0');
  assertEquals(body.id, 3);
  const text = body.result.content[0].text;
  const parsed = JSON.parse(text);
  assertEquals(typeof parsed.url, 'string');
  assertEquals(typeof parsed.publicUrl, 'string');
  assertEquals(parsed.url.includes('X-Amz-Signature'), true);
  assertEquals(parsed.publicUrl.endsWith('-test.png'), true);
  assertEquals(typeof parsed.usage, 'string');
  assertEquals(parsed.usage.includes('curl'), true);
  assertEquals(parsed.usage.includes('<file>'), true);
  assertEquals(parsed.usage.includes('<url>'), true);
});

Deno.test('POST /mcp rejects request without auth', async () => {
  const encKey = makeKey();
  const app = new Hono();
  app.post('/mcp', createMcpHandler(encKey, 'http://localhost:8000/mcp'));

  const res = await app.request('/mcp', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {},
    }),
  });

  assertEquals(res.status, 401);
});

Deno.test('POST /mcp rejects expired token', async () => {
  const encKey = makeKey();
  const app = new Hono();
  app.post('/mcp', createMcpHandler(encKey, 'http://localhost:8000/mcp'));

  const expiredToken = await encrypt(
    {
      endpoint: 'https://s3.us-east-1.amazonaws.com',
      region: 'us-east-1',
      bucket: 'test-bucket',
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      publicUrlBase: 'https://test-bucket.s3.us-east-1.amazonaws.com',
      typ: 'access_token',
      iat: Math.floor(Date.now() / 1000) - 7200,
      exp: Math.floor(Date.now() / 1000) - 3600,
    },
    encKey,
  );

  const res = await app.request('/mcp', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'authorization': `Bearer ${expiredToken}`,
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
    }),
  });

  assertEquals(res.status, 401);
});

Deno.test('POST /mcp rejects non-access_token type', async () => {
  const encKey = makeKey();
  const app = new Hono();
  app.post('/mcp', createMcpHandler(encKey, 'http://localhost:8000/mcp'));

  const refreshToken = await encrypt(
    {
      endpoint: 'https://s3.us-east-1.amazonaws.com',
      region: 'us-east-1',
      bucket: 'test-bucket',
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      publicUrlBase: 'https://test-bucket.s3.us-east-1.amazonaws.com',
      typ: 'refresh_token',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 86400 * 365,
    },
    encKey,
  );

  const res = await app.request('/mcp', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'authorization': `Bearer ${refreshToken}`,
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
    }),
  });

  assertEquals(res.status, 401);
});
