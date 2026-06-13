export async function deriveKey(
  secret: string,
): Promise<{ encryptionKey: Uint8Array; hmacSecret: Uint8Array }> {
  const encoder = new TextEncoder();
  const keyBytes = encoder.encode(secret);

  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );

  const encryptionKey = new Uint8Array(
    await crypto.subtle.sign(
      'HMAC',
      key,
      encoder.encode('s3-uploader-encryption-key'),
    ),
  );

  const hmacSecret = new Uint8Array(
    await crypto.subtle.sign(
      'HMAC',
      key,
      encoder.encode('s3-uploader-hmac-secret'),
    ),
  );

  return { encryptionKey, hmacSecret };
}
