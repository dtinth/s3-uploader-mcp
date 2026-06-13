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

const TEMPLATE = [
  '# S3 Storage Configuration',
  '# Fill in your S3-compatible storage credentials',
  '# Lines starting with # are ignored',
  '',
  'S3_ENDPOINT=https://s3.us-east-1.amazonaws.com',
  'S3_REGION=us-east-1',
  'S3_BUCKET=my-bucket',
  'S3_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
  'S3_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  'S3_PUBLIC_URL_BASE=https://my-bucket.s3.us-east-1.amazonaws.com',
  'S3_KEY_PREFIX=uploads/',
].join('\n');

const TEMPLATE_KEY_MAP: Record<string, string> = {
  S3_ENDPOINT: 'endpoint',
  S3_REGION: 'region',
  S3_BUCKET: 'bucket',
  S3_ACCESS_KEY_ID: 'accessKeyId',
  S3_SECRET_ACCESS_KEY: 'secretAccessKey',
  S3_PUBLIC_URL_BASE: 'publicUrlBase',
  S3_KEY_PREFIX: 'keyPrefix',
};

const ALLOWED_KEYS = new Set(Object.keys(TEMPLATE_KEY_MAP));

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
    button { padding: 0.6rem 1.5rem; border: none; border-radius: 4px; cursor: pointer; font-size: 0.9rem; }
    .btn-primary { background: #0a7; color: #fff; }
    .btn-secondary { background: #e5e7eb; color: #333; }
    .btn-row { display: flex; gap: 0.5rem; margin-top: 1rem; }
    .optional { color: #888; font-weight: normal; }
    .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.4); align-items: center; justify-content: center; z-index: 100; }
    .modal-overlay.open { display: flex; }
    .modal { background: #fff; border-radius: 8px; padding: 1.5rem; max-width: 560px; width: 90%; max-height: 80vh; display: flex; flex-direction: column; }
    .modal h2 { margin: 0 0 0.5rem; }
    .modal p { margin: 0 0 1rem; color: #555; font-size: 0.9rem; }
    .modal textarea { width: 100%; min-height: 240px; font-family: monospace; font-size: 0.8rem; padding: 0.5rem; box-sizing: border-box; resize: vertical; }
    .modal .btn-row { justify-content: flex-end; }
  </style>
</head>
<body>
  <h1>Authorize S3 Uploader MCP</h1>
  <p>Paste your S3-compatible storage credentials below. They will be encrypted into a token so the agent can generate upload URLs without seeing your keys.</p>
  ${errorHtml}
  <form method="POST" id="auth-form">
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
    <input type="password" id="secretAccessKey" name="secretAccessKey" placeholder="" value="${
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
    <div class="btn-row">
      <button type="button" class="btn-secondary" onclick="document.getElementById('modal').classList.add('open')">Paste config</button>
      <button type="submit" class="btn-primary">Authorize</button>
    </div>
  </form>

  <div class="modal-overlay" id="modal" onclick="if(event.target===this)this.classList.remove('open')">
    <div class="modal">
      <h2>Paste Storage Configuration</h2>
      <p>Copy the template below, fill in your credentials, then paste everything back and click Apply.</p>
      <textarea id="config-textarea">${TEMPLATE}</textarea>
      <div class="btn-row">
        <button type="button" class="btn-secondary" onclick="document.getElementById('modal').classList.remove('open')">Cancel</button>
        <button type="button" class="btn-primary" onclick="applyConfig()">Apply</button>
      </div>
    </div>
  </div>

  <script>
  function applyConfig() {
    const text = document.getElementById('config-textarea').value;
    const lines = text.split('\\n');
    const parsed = {};
    const errors = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eq = trimmed.indexOf('=');
      if (eq === -1) { errors.push('Invalid line: ' + trimmed); continue; }
      const key = trimmed.slice(0, eq).trim();
      const value = trimmed.slice(eq + 1).trim();
      parsed[key] = value;
    }

    if (errors.length) {
      alert(errors.join('\\n'));
      return;
    }

    const allowed = new Set(${JSON.stringify(Array.from(ALLOWED_KEYS))});
    const fieldMap = ${JSON.stringify(TEMPLATE_KEY_MAP)};

    const unknownKeys = Object.keys(parsed).filter(k => !allowed.has(k));
    if (unknownKeys.length) {
      alert('Unknown key(s): ' + unknownKeys.join(', '));
      return;
    }

    const missingRequired = [];
    for (const requiredKey of ['S3_ENDPOINT','S3_REGION','S3_BUCKET','S3_ACCESS_KEY_ID','S3_SECRET_ACCESS_KEY','S3_PUBLIC_URL_BASE']) {
      if (!parsed[requiredKey]) missingRequired.push(requiredKey);
    }
    if (missingRequired.length) {
      alert('Missing required key(s):\\n' + missingRequired.join('\\n'));
      return;
    }

    for (const [envKey, fieldName] of Object.entries(fieldMap)) {
      if (parsed[envKey] !== undefined) {
        document.getElementById(fieldName).value = parsed[envKey];
      }
    }

    document.getElementById('modal').classList.remove('open');
  }
  </script>
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

export function createAuthorizeHandler(
  encryptionKey: Uint8Array,
  issuer: string,
) {
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

    const location = `${redirectUri}?code=${encodeURIComponent(code)}&iss=${
      encodeURIComponent(issuer)
    }${state ? `&state=${encodeURIComponent(state)}` : ''}`;
    return c.redirect(location, 302);
  };
}
