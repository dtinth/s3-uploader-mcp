import { createApp } from './src/app.ts';
import { deriveKey } from './src/crypto/key.ts';

const SERVER_SECRET = Deno.env.get('SERVER_SECRET');
if (!SERVER_SECRET) {
  console.error('SERVER_SECRET environment variable is required');
  Deno.exit(1);
}

const ISSUER = Deno.env.get('ISSUER') || 'http://localhost:8000';
const MCP_URL = Deno.env.get('MCP_URL') || `${ISSUER}/mcp`;

const { encryptionKey, hmacSecret } = await deriveKey(SERVER_SECRET);

const app = createApp(encryptionKey, hmacSecret, ISSUER, MCP_URL);

console.log(
  `S3 Uploader MCP server starting on :8000 (issuer: ${ISSUER}, mcp: ${MCP_URL})`,
);
Deno.serve({ port: 8000 }, app.fetch);
