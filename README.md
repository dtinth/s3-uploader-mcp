# S3 Uploader MCP

An MCP server that lets Claude upload files to _your_ S3-compatible storage and
return a public URL — without ever seeing your storage credentials.

## Why

When Claude Code or Claude.ai works on a project and wants to create a PR with
screenshots, it needs somewhere to upload those images. GitHub doesn't provide a
file upload API, so you need object storage. But teaching every agent how to
configure S3 credentials is tedious and risky — the credentials end up visible
to the agent, the LLM provider, and anyone who reads the conversation logs.

This server solves that by acting as a stateless proxy: you paste your S3
credentials into an authorization form once, they get encrypted into a bearer
token, and the agent only ever receives a presigned upload URL. Your keys never
leave your encrypted token.

## Quick start — try the public instance

There's a public instance at `https://s3-uploader-mcp.spacet.me/mcp` — you're
welcome to try it out with any S3-compatible provider. Just keep in mind:

- Use credentials scoped to a **single bucket with object-write only**
- There is **no uptime guarantee**
- You're trusting the operator with your cloud credentials → for production,
  **self-host**

### 1. Add the connector in Claude

**Claude.ai (web):** Settings → Connectors → Add custom connector → enter the
MCP URL.

**Claude Code:** In your project's `.claude/settings.json`:

```json
{
  "mcpServers": {
    "s3-uploader": {
      "type": "remote",
      "url": "https://s3-uploader-mcp.spacet.me/mcp"
    }
  }
}
```

**Claude Code on the Web:** In Cloud environment settings → Network access →
Allowed domains, add your S3 endpoint domain.

### 2. Authorize

Claude will open the authorization page. Click **Paste config** and fill in your
S3-compatible storage details:

| Field             | Description                        |
| ----------------- | ---------------------------------- |
| Endpoint          | S3-compatible endpoint URL         |
| Region            | e.g. `us-east-1`                   |
| Bucket            | Your bucket name                   |
| Access Key ID     | Your access key                    |
| Secret Access Key | Your secret key                    |
| Public URL Base   | Base URL for generated public URLs |
| Key Prefix        | (optional) e.g. `uploads/`         |

Or use the **Paste config** button to copy a template, fill it in your editor,
and paste it back in one go.

### 3. Upload

Once connected, just ask Claude to upload a file. The agent calls
`get_upload_url(filename)` and gets back:

```json
{
  "url": "https://...?X-Amz-Signature=...",
  "publicUrl": "https://.../2026/06/13/<uuid>-screenshot.png",
  "usage": "Example upload command: `curl -s -o /dev/null -w '%{http_code}' -X PUT -T '<file>' '<url>'`"
}
```

The agent uploads the file using the presigned URL, then includes the
`publicUrl` in the PR description or wherever it's needed.

**Note for Claude.ai (web):** You must allowlist your S3 endpoint domain in
Settings → Capabilities → Additional allowed domains. Otherwise Claude can't
reach your storage to upload.

## How it works

```
┌──────────┐      ┌──────────────┐      ┌─────────────────┐
│  Claude  │ ───→ │  Your MCP    │ ───→ │  Your S3 bucket │
│  client  │ ←─── │  server      │      └─────────────────┘
└──────────┘      └──────┬───────┘
                         │ reads credentials from
                         │ encrypted bearer token
                         ▼
                  ┌──────────────────┐
                  │  Your storage    │
                  │  credentials     │
                  │  (self-issued)   │
                  └──────────────────┘
```

The server is **fully stateless**. The full OAuth 2.0 DCR flow runs on every
connection:

1. **Discovery** — Claude fetches `/.well-known/oauth-authorization-server` to
   find endpoints
2. **Register** — Claude registers via DCR (`POST /register`), gets HMAC-signed
   client credentials
3. **Authorize** — You paste your S3 config into `/authorize`, the server
   encrypts it into a 5-minute **auth code JWE**
4. **Token** — Claude exchanges the code at `/token` (PKCE-verified) for a
   1-hour **access token JWE** and a perpetual **refresh token JWE**
5. **Call** — Claude sends the access token to `/mcp` where the server decrypts
   it, signs a presigned PUT URL, and returns it — all without the agent ever
   seeing your raw keys

All three token types carry the same payload encrypted with `A256GCM`:

- Endpoint, region, bucket, access key ID, secret access key, public URL base,
  optional key prefix

## Security model

| Layer               | Mechanism                                                                                                                          |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Credential storage  | **None**. Credentials are encrypted into self-contained JWEs, never stored on disk or in memory beyond the request                 |
| Token theft         | PKCE (`S256`) protects the auth code. Access tokens expire in 1 hour. Refresh tokens are perpetual — rotate your S3 keys to revoke |
| Client registration | Stateless HMAC-signed `client_id`/`client_secret`. No database                                                                     |
| Attack surface      | The server makes **no outbound connections**. It only listens for incoming HTTP requests                                           |
| Key derivation      | Single `SERVER_SECRET` → HKDF → encryption key + HMAC secret                                                                       |

## Self-host

### Requirements

- [Docker](https://docker.com)
- A `SERVER_SECRET` — generate one with `openssl rand -hex 32`

### docker-compose.yml

```yaml
services:
  s3-uploader-mcp:
    image: ghcr.io/dtinth/s3-uploader-mcp:latest
    ports:
      - '8000:8000'
    environment:
      - SERVER_SECRET=${SERVER_SECRET}
      - ISSUER=https://your-domain.com
```

### Environment variables

| Variable        | Required | Default                 | Description                                                 |
| --------------- | -------- | ----------------------- | ----------------------------------------------------------- |
| `SERVER_SECRET` | ✅       | —                       | Master secret for encryption + HMAC. `openssl rand -hex 32` |
| `ISSUER`        | —        | `http://localhost:8000` | Public URL of your server (used in OAuth metadata)          |

### Deploy

```bash
export SERVER_SECRET=$(openssl rand -hex 32)
export ISSUER=https://your-domain.com
docker compose up -d
```

Then add `https://your-domain.com/mcp` as a custom connector in Claude.

## Development

```bash
deno task test    # run tests
deno task check   # type check all files
deno lint         # lint
deno fmt          # format
```
