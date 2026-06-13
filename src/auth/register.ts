import { Context } from 'hono';

export function createRegistrationHandler(hmacSecret: Uint8Array) {
  return async (c: Context) => {
    const contentType = c.req.header('content-type') || '';
    if (!contentType.includes('application/json')) {
      return c.json({ error: 'invalid_client_metadata' }, 400);
    }

    let body: Record<string, unknown>;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: 'invalid_client_metadata' }, 400);
    }

    if (!body.redirect_uris || !Array.isArray(body.redirect_uris)) {
      return c.json({ error: 'invalid_client_metadata' }, 400);
    }

    const clientId = crypto.randomUUID();
    const clientSecret = await computeClientSecret(hmacSecret, clientId);

    return c.json(
      {
        client_id: clientId,
        client_secret: clientSecret,
        client_secret_expires_at: 0,
        client_id_issued_at: Math.floor(Date.now() / 1000),
        token_endpoint_auth_method: 'none',
        redirect_uris: body.redirect_uris,
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
      },
      201,
    );
  };
}

export async function computeClientSecret(
  hmacSecret: Uint8Array,
  clientId: string,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    hmacSecret.slice().buffer as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const sig = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(clientId),
  );

  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function verifyClientSecret(
  hmacSecret: Uint8Array,
  clientId: string,
  clientSecret: string,
): Promise<boolean> {
  const expected = await computeClientSecret(hmacSecret, clientId);
  if (expected.length !== clientSecret.length) return false;
  let result = 0;
  for (let i = 0; i < expected.length; i++) {
    result |= expected.charCodeAt(i) ^ clientSecret.charCodeAt(i);
  }
  return result === 0;
}
