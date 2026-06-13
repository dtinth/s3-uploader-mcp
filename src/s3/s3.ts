import { AwsClient } from 'aws4fetch';

export interface StorageConfig {
  endpoint: string;
  region: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  publicUrlBase: string;
  keyPrefix?: string;
}

export async function createPresignedPutUrl(
  config: StorageConfig,
  filename: string,
): Promise<{ url: string; publicUrl: string }> {
  if (!filename) {
    throw new Error('Filename is required');
  }

  const key = config.keyPrefix
    ? `${config.keyPrefix.replace(/\/$/, '')}/${filename}`
    : filename;

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

  return { url: signed.url, publicUrl };
}
