import { assertEquals } from '@std/assert';
import { createDiscoveryHandler } from './discovery.ts';
import { Hono } from 'hono';

Deno.test('GET /.well-known/oauth-authorization-server returns metadata', async () => {
  const app = new Hono();
  app.get(
    '/.well-known/oauth-authorization-server',
    createDiscoveryHandler('https://mcp.example.com'),
  );

  const res = await app.request('/.well-known/oauth-authorization-server');
  assertEquals(res.status, 200);

  const body = await res.json();
  assertEquals(body.issuer, 'https://mcp.example.com');
  assertEquals(body.authorization_endpoint, 'https://mcp.example.com/authorize');
  assertEquals(body.token_endpoint, 'https://mcp.example.com/token');
  assertEquals(body.registration_endpoint, 'https://mcp.example.com/register');
  assertEquals(body.response_types_supported, ['code']);
  assertEquals(body.grant_types_supported, ['authorization_code', 'refresh_token']);
  assertEquals(body.code_challenge_methods_supported, ['S256']);
  assertEquals(body.scopes_supported, ['upload', 'offline_access']);
  assertEquals(body.token_endpoint_auth_methods_supported, ['none']);
});
