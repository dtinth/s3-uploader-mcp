# ADR 0001: Architectural decisions for S3 Uploader MCP

## Context

We are building a stateless, multi-tenant MCP server that issues presigned S3
upload URLs. End-users paste their own S3-compatible storage credentials into an
authorization form; those credentials are encrypted into a bearer token so the
MCP server can sign URLs without the agent ever seeing the raw keys.

## Decisions

### Encryption: single symmetric key

One `ENCRYPTION_KEY` env var, reused for all JWE types (auth_code, access_token,
refresh_token). `jose` with `alg: "dir"`, `enc: "A256GCM"`. If the key leaks,
all tokens are compromised — the mitigation is that S3 keys can be rotated
independently.

### PKCE verification

The server verifies `code_challenge` (S256) against `code_verifier` at `/token`
per OAuth spec. The `code_challenge` is embedded in the auth code JWE payload so
verification is stateless.

### No jti / replay tracking

PKCE + 5-min auth code expiry is sufficient. The `code_verifier` goes directly
to `/token` (never through the redirect URL), so an intercepted auth code alone
is worthless.

### Client secret verification

`/register` returns `client_secret = HMAC(HMAC_SECRET, client_id)`. `/token`
verifies the secret via the same HMAC computation — stateless, zero storage.

### MCP tools

Single tool: `get_upload_url(filename: string)` → returns
`{ url: string (presigned PUT URL), publicUrl: string }`. No delete, list, or
other operations — the agent only gets upload capability.

### Web framework: Hono

Hono is used as the HTTP framework for Deno. Lightweight, TypeScript-native, low
memory footprint, and the most popular choice for Deno API servers.

### Runtime: Deno 2.x

The server runs on Deno 2.x. Chosen for low RAM footprint (Dokploy target),
native TypeScript support, and a single-binary deployment model.

### Auth mechanism: OAuth 2.0 DCR (Dynamic Client Registration)

Instead of a real identity provider, the server exposes a fake, stateless
`/register` endpoint (RFC 7591) that returns an HMAC-signed
`client_id`/`client_secret`. This is what Claude's MCP connector expects by
default and follows the MCP auth spec most closely.

### Token system: 3 JWE types, stateless

All tokens are JWEs (encrypted JWTs) using `jose` library with `alg: "dir"`,
`enc: "A256GCM"`. No database.

| JWE type           | `typ` claim     | `exp` | Purpose                                     |
| ------------------ | --------------- | ----- | ------------------------------------------- |
| Authorization code | `auth_code`     | 5 min | One-time exchange at `/token`               |
| Access token       | `access_token`  | 1 hr  | Sent to `/mcp`                              |
| Refresh token      | `refresh_token` | none  | Stored by Claude for access token refreshes |

All three carry the same payload: the end-user's S3-compatible storage
configuration.

### JWE payload schema

```
{
  endpoint: string,
  region: string,
  bucket: string,
  accessKeyId: string,
  secretAccessKey: string,
  publicUrlBase: string,
  keyPrefix: string,       // optional, scopes upload paths
  iat: number,
  exp: number,
  typ: "auth_code" | "access_token" | "refresh_token",
  jti?: string             // for auth code replay prevention
}
```

### Relationship: Operator and End-user

- **Operator** deploys and maintains the server instance
- **End-user** connects their MCP client (Claude) to the server and pastes their
  storage credentials into the authorization form
