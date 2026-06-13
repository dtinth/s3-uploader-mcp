import { AwsClient } from 'aws4fetch';
import { v7 } from '@std/uuid';

export interface StorageConfig {
  endpoint: string;
  region: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  publicUrlBase: string;
  keyPrefix?: string;
}

export interface PresignedPutUrlResult {
  url: string;
  publicUrl: string;
  usage: string;
}

function buildKey(prefix: string | undefined, filename: string): string {
  const now = new Date();
  const yyyy = now.getFullYear();
  const mm = String(now.getMonth() + 1).padStart(2, '0');
  const dd = String(now.getDate()).padStart(2, '0');
  const id = v7.generate();
  const base = prefix ? `${prefix.replace(/\/$/, '')}` : '';
  return `${base}${base ? '/' : ''}${yyyy}/${mm}/${dd}/${id}-${filename}`;
}

const USAGE_TEXT =
  "Example upload command: `curl -s -o /dev/null -w '%{http_code}' -X PUT -T '<file>' '<url>'`";

export async function createPresignedPutUrl(
  config: StorageConfig,
  filename: string,
): Promise<PresignedPutUrlResult> {
  if (!filename) {
    throw new Error('Filename is required');
  }

  const key = buildKey(config.keyPrefix, filename);

  const client = new AwsClient({
    accessKeyId: config.accessKeyId,
    secretAccessKey: config.secretAccessKey,
    region: config.region,
    service: 's3',
  });

  const endpoint = config.endpoint.replace(/\/$/, '');
  const objectUrl = `${endpoint}/${config.bucket}/${key}`;

  const request = new Request(objectUrl, { method: 'PUT' });
  const signed = await client.sign(request, {
    aws: { signQuery: true, allHeaders: true },
  });

  const publicUrl = `${config.publicUrlBase.replace(/\/$/, '')}/${key}`;

  return { url: signed.url, publicUrl, usage: USAGE_TEXT };
}
