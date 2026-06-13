import { Context } from 'hono';

export function createDiscoveryHandler(issuer: string) {
  return (c: Context) => {
    return c.json({
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      registration_endpoint: `${issuer}/register`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      scopes_supported: ['upload', 'offline_access'],
      token_endpoint_auth_methods_supported: ['none'],
    });
  };
}
