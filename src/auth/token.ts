import { Context } from 'hono';
import { decrypt, encrypt } from '../crypto/jwe.ts';
import type { TokenPayload } from '../crypto/jwe.ts';
import { verifyClientSecret } from './register.ts';

export async function computePkceChallenge(
  codeVerifier: string,
): Promise<string> {
  const hash = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(codeVerifier),
  );
  const bytes = new Uint8Array(hash);
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function createTokenPayload(
  base: TokenPayload,
  typ: 'access_token' | 'refresh_token',
  ttlSeconds: number | null,
): TokenPayload {
  const now = Math.floor(Date.now() / 1000);
  return {
    endpoint: base.endpoint,
    region: base.region,
    bucket: base.bucket,
    accessKeyId: base.accessKeyId,
    secretAccessKey: base.secretAccessKey,
    publicUrlBase: base.publicUrlBase,
    keyPrefix: base.keyPrefix,
    typ,
    iat: now,
    exp: ttlSeconds ? now + ttlSeconds : now + 86400 * 365,
  };
}

export function createTokenHandler(
  encryptionKey: Uint8Array,
  hmacSecret: Uint8Array,
) {
  return async (c: Context) => {
    const contentType = c.req.header('content-type') || '';
    if (!contentType.includes('application/x-www-form-urlencoded')) {
      return c.json({ error: 'invalid_request' }, 400);
    }

    let body: URLSearchParams;
    try {
      const text = await c.req.text();
      body = new URLSearchParams(text);
    } catch {
      return c.json({ error: 'invalid_request' }, 400);
    }

    const grantType = body.get('grant_type');

    if (grantType === 'authorization_code') {
      const code = body.get('code');
      const codeVerifier = body.get('code_verifier') || '';
      if (!code) {
        return c.json({ error: 'invalid_request' }, 400);
      }

      let payload: TokenPayload;
      try {
        payload = await decrypt(code, encryptionKey);
      } catch {
        return c.json({ error: 'invalid_grant' }, 400);
      }

      if (payload.typ !== 'auth_code') {
        return c.json({ error: 'invalid_grant' }, 400);
      }

      const clientId = body.get('client_id');
      const clientSecret = body.get('client_secret');
      if (clientId && clientSecret) {
        const valid = await verifyClientSecret(
          hmacSecret,
          clientId,
          clientSecret,
        );
        if (!valid) {
          return c.json({ error: 'invalid_client' }, 400);
        }
      }

      if (payload.codeChallenge) {
        const challenge = await computePkceChallenge(codeVerifier);
        if (challenge !== payload.codeChallenge) {
          return c.json({ error: 'invalid_grant' }, 400);
        }
      }

      const accessToken = await encrypt(
        createTokenPayload(payload, 'access_token', 3600),
        encryptionKey,
      );
      const refreshToken = await encrypt(
        createTokenPayload(payload, 'refresh_token', null),
        encryptionKey,
      );

      return c.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: refreshToken,
        scope: 'upload',
      });
    }

    if (grantType === 'refresh_token') {
      const refreshTokenValue = body.get('refresh_token');
      if (!refreshTokenValue) {
        return c.json({ error: 'invalid_request' }, 400);
      }

      let payload: TokenPayload;
      try {
        payload = await decrypt(refreshTokenValue, encryptionKey);
      } catch {
        return c.json({ error: 'invalid_grant' }, 400);
      }

      if (payload.typ !== 'refresh_token') {
        return c.json({ error: 'invalid_grant' }, 400);
      }

      const accessToken = await encrypt(
        createTokenPayload(payload, 'access_token', 3600),
        encryptionKey,
      );
      const newRefreshToken = await encrypt(
        createTokenPayload(payload, 'refresh_token', null),
        encryptionKey,
      );

      return c.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: newRefreshToken,
        scope: 'upload',
      });
    }

    return c.json({ error: 'unsupported_grant_type' }, 400);
  };
}
