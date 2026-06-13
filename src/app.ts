import { Hono } from 'hono';
import { cors } from 'hono/cors';
import {
  createDiscoveryHandler,
  createProtectedResourceHandler,
} from './auth/discovery.ts';
import { createRegistrationHandler } from './auth/register.ts';
import { createAuthorizeHandler } from './auth/authorize.ts';
import { createTokenHandler } from './auth/token.ts';
import { createMcpHandler } from './mcp/mcp.ts';

export function createApp(
  encryptionKey: Uint8Array,
  hmacSecret: Uint8Array,
  issuer: string,
  mcpUrl: string,
) {
  const app = new Hono();

  app.use('/*', cors());

  app.get(
    '/.well-known/oauth-authorization-server',
    createDiscoveryHandler(issuer),
  );

  app.get(
    '/.well-known/oauth-protected-resource',
    createProtectedResourceHandler(mcpUrl),
  );

  app.post('/register', createRegistrationHandler(hmacSecret));
  app.get('/authorize', createAuthorizeHandler(encryptionKey, issuer));
  app.post('/authorize', createAuthorizeHandler(encryptionKey, issuer));
  app.post('/token', createTokenHandler(encryptionKey, hmacSecret));
  app.post('/mcp', createMcpHandler(encryptionKey, mcpUrl));

  return app;
}
