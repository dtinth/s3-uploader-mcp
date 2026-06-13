import { Context } from 'hono';
import { encrypt } from '../crypto/jwe.ts';

const REQUIRED_FIELDS = [
  'endpoint',
  'region',
  'bucket',
  'accessKeyId',
  'secretAccessKey',
  'publicUrlBase',
] as const;

const DEFAULT_REDIRECT = 'https://claude.ai/api/mcp/auth_callback';

function renderForm(
  oauthParams: Record<string, string>,
  error?: string,
  values?: Record<string, string>,
): string {
  const hiddenFields = Object.entries(oauthParams)
    .map(([k, v]) => `<input type="hidden" name="${k}" value="${v}">`)
    .join('\n      ');

  const errorHtml = error
    ? `<p style="color:red;font-weight:bold">${error}</p>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize S3 Uploader MCP</title>
  <style>
    body { font-family: sans-serif; max-width: 480px; margin: 2rem auto; padding: 1rem; }
    label { display: block; margin: 0.75rem 0 0.25rem; font-weight: 600; }
    input { width: 100%; padding: 0.5rem; box-sizing: border-box; font-family: monospace; }
    button { margin-top: 1rem; padding: 0.6rem 1.5rem; background: #0a7; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
    .optional { color: #888; font-weight: normal; }
  </style>
</head>
<body>
  <h1>Authorize S3 Uploader MCP</h1>
  <p>Paste your S3-compatible storage credentials below. They will be encrypted into a token so the agent can generate upload URLs without seeing your keys.</p>
  ${errorHtml}
  <form method="POST">
      ${hiddenFields}
    <label for="endpoint">Endpoint</label>
    <input type="text" id="endpoint" name="endpoint" placeholder="https://s3.us-east-1.amazonaws.com" value="${
    values?.endpoint || ''
  }" required>
    <label for="region">Region</label>
    <input type="text" id="region" name="region" placeholder="us-east-1" value="${
    values?.region || ''
  }" required>
    <label for="bucket">Bucket</label>
    <input type="text" id="bucket" name="bucket" placeholder="my-bucket" value="${
    values?.bucket || ''
  }" required>
    <label for="accessKeyId">Access Key ID</label>
    <input type="text" id="accessKeyId" name="accessKeyId" placeholder="AKIA..." value="${
    values?.accessKeyId || ''
  }" required>
    <label for="secretAccessKey">Secret Access Key</label>
    <input type="password" id="secretAccessKey" name="secretAccessKey" placeholder="●●●●●●●●" value="${
    values?.secretAccessKey || ''
  }" required>
    <label for="publicUrlBase">Public URL Base</label>
    <input type="text" id="publicUrlBase" name="publicUrlBase" placeholder="https://my-bucket.public.url/" value="${
    values?.publicUrlBase || ''
  }" required>
    <label for="keyPrefix">Key Prefix <span class="optional">(optional)</span></label>
    <input type="text" id="keyPrefix" name="keyPrefix" placeholder="uploads/" value="${
    values?.keyPrefix || ''
  }">
    <button type="submit">Authorize</button>
  </form>
</body>
</html>`;
}

const OAUTH_PARAM_KEYS = [
  'response_type',
  'client_id',
  'redirect_uri',
  'code_challenge',
  'code_challenge_method',
  'state',
  'scope',
];

export function createAuthorizeHandler(encryptionKey: Uint8Array) {
  return async (c: Context) => {
    if (c.req.method === 'GET') {
      const query = c.req.query();
      const oauthParams: Record<string, string> = {};
      for (const key of OAUTH_PARAM_KEYS) {
        const v = query[key];
        if (v) oauthParams[key] = v;
      }
      return c.html(renderForm(oauthParams));
    }

    const formData = await c.req.parseBody();
    const oauthParams: Record<string, string> = {};
    for (const key of OAUTH_PARAM_KEYS) {
      const v = formData[key];
      if (typeof v === 'string') oauthParams[key] = v;
    }

    const values: Record<string, string> = {};
    for (const field of REQUIRED_FIELDS) {
      const val = formData[field];
      if (typeof val !== 'string' || !val.trim()) {
        for (const f of REQUIRED_FIELDS) {
          const v = formData[f];
          if (typeof v === 'string') values[f] = v;
        }
        if (formData.keyPrefix && typeof formData.keyPrefix === 'string') {
          values.keyPrefix = formData.keyPrefix;
        }
        return c.html(
          renderForm(oauthParams, `Missing required field: ${field}`, values),
        );
      }
      values[field] = val.trim();
    }

    if (formData.keyPrefix && typeof formData.keyPrefix === 'string') {
      values.keyPrefix = formData.keyPrefix;
    }

    const redirectUri =
      typeof formData.redirect_uri === 'string' && formData.redirect_uri.trim()
        ? formData.redirect_uri.trim()
        : DEFAULT_REDIRECT;
    const state = typeof formData.state === 'string' ? formData.state : '';
    const codeChallenge = typeof formData.code_challenge === 'string'
      ? formData.code_challenge
      : '';

    const now = Math.floor(Date.now() / 1000);
    const code = await encrypt(
      {
        endpoint: values.endpoint,
        region: values.region,
        bucket: values.bucket,
        accessKeyId: values.accessKeyId,
        secretAccessKey: values.secretAccessKey,
        publicUrlBase: values.publicUrlBase,
        keyPrefix: values.keyPrefix,
        codeChallenge,
        typ: 'auth_code',
        iat: now,
        exp: now + 300,
      },
      encryptionKey,
    );

    const location = `${redirectUri}?code=${encodeURIComponent(code)}${
      state ? `&state=${encodeURIComponent(state)}` : ''
    }`;
    return c.redirect(location, 302);
  };
}
