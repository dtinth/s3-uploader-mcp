import { Context } from 'hono';
import { decrypt } from '../crypto/jwe.ts';
import type { TokenPayload } from '../crypto/jwe.ts';
import { createPresignedPutUrl } from '../s3/s3.ts';

const MCP_VERSION = '2024-11-05';

function jsonRpcError(id: number | string | null, code: number, message: string) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

function jsonRpcResult(id: number | string | null, result: unknown) {
  return { jsonrpc: '2.0', id, result };
}

export function createMcpHandler(encryptionKey: Uint8Array) {
  return async (c: Context) => {
    const auth = c.req.header('authorization') || '';
    if (!auth.startsWith('Bearer ')) {
      return c.json(
        { error: 'unauthorized' },
        401,
        { 'WWW-Authenticate': 'Bearer' },
      );
    }

    const token = auth.slice(7);
    let payload: TokenPayload;
    try {
      payload = await decrypt(token, encryptionKey);
    } catch {
      return c.json(
        { error: 'invalid_token' },
        401,
        { 'WWW-Authenticate': 'Bearer' },
      );
    }

    if (payload.typ !== 'access_token') {
      return c.json(
        { error: 'invalid_token' },
        401,
        { 'WWW-Authenticate': 'Bearer' },
      );
    }

    let reqBody: { jsonrpc?: string; id?: number | string | null; method?: string; params?: Record<string, unknown> };
    try {
      reqBody = await c.req.json();
    } catch {
      return c.json({ error: 'invalid_request' }, 400);
    }

    if (reqBody.jsonrpc !== '2.0') {
      return c.json(jsonRpcError(reqBody.id ?? null, -32600, 'Invalid Request'), 400);
    }

    const method = reqBody.method || '';

    if (method === 'initialize') {
      return c.json(
        jsonRpcResult(reqBody.id ?? null, {
          protocolVersion: MCP_VERSION,
          capabilities: { tools: {} },
          serverInfo: { name: 's3-uploader-mcp', version: '0.1.0' },
        }),
      );
    }

    if (method === 'ping') {
      return c.json(jsonRpcResult(reqBody.id ?? null, {}));
    }

    if (method === 'tools/list') {
      return c.json(
        jsonRpcResult(reqBody.id ?? null, {
          tools: [
            {
              name: 'get_upload_url',
              description: 'Get a presigned upload URL for a file',
              inputSchema: {
                type: 'object',
                properties: {
                  filename: {
                    type: 'string',
                    description: 'The filename (path) to upload to the storage bucket',
                  },
                },
                required: ['filename'],
              },
            },
          ],
        }),
      );
    }

    if (method === 'tools/call') {
      const params = reqBody.params || {};
      const toolName = params.name as string;
      const args = (params.arguments || {}) as Record<string, string>;

      if (toolName !== 'get_upload_url') {
        return c.json(jsonRpcError(reqBody.id ?? null, -32602, `Unknown tool: ${toolName}`), 400);
      }

      const filename = args.filename;
      if (!filename || typeof filename !== 'string') {
        return c.json(jsonRpcError(reqBody.id ?? null, -32602, 'Missing required argument: filename'), 400);
      }

      try {
        const result = await createPresignedPutUrl(
          {
            endpoint: payload.endpoint,
            region: payload.region,
            bucket: payload.bucket,
            accessKeyId: payload.accessKeyId,
            secretAccessKey: payload.secretAccessKey,
            publicUrlBase: payload.publicUrlBase,
            keyPrefix: payload.keyPrefix,
          },
          filename,
        );

        return c.json(
          jsonRpcResult(reqBody.id ?? null, {
            content: [{ type: 'text', text: JSON.stringify(result) }],
          }),
        );
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Internal error';
        return c.json(jsonRpcError(reqBody.id ?? null, -32603, message), 500);
      }
    }

    if (method.startsWith('notifications/')) {
      return c.json(jsonRpcResult(reqBody.id ?? null, {}));
    }

    return c.json(jsonRpcError(reqBody.id ?? null, -32601, `Method not found: ${method}`), 400);
  };
}
