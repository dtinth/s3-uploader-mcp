import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { createDiscoveryHandler } from './auth/discovery.ts';
import { createRegistrationHandler } from './auth/register.ts';
import { createAuthorizeHandler } from './auth/authorize.ts';
import { createTokenHandler } from './auth/token.ts';
import { createMcpHandler } from './mcp/mcp.ts';

export function createApp(
  encryptionKey: Uint8Array,
  hmacSecret: Uint8Array,
  issuer: string,
) {
  const app = new Hono();

  app.use('/*', cors());

  app.get(
    '/.well-known/oauth-authorization-server',
    createDiscoveryHandler(issuer),
  );

  app.post('/register', createRegistrationHandler(hmacSecret));
  app.get('/authorize', createAuthorizeHandler(encryptionKey));
  app.post('/authorize', createAuthorizeHandler(encryptionKey));
  app.post('/token', createTokenHandler(encryptionKey, hmacSecret));
  app.post('/mcp', createMcpHandler(encryptionKey));

  return app;
}
