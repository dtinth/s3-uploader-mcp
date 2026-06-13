import { assertEquals, assertRejects } from '@std/assert';
import { createPresignedPutUrl } from './s3.ts';

Deno.test('createPresignedPutUrl returns presigned URL, public URL, and usage', async () => {
  const result = await createPresignedPutUrl(
    {
      endpoint: 'https://s3.us-east-1.amazonaws.com',
      region: 'us-east-1',
      bucket: 'test-bucket',
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      publicUrlBase: 'https://test-bucket.s3.us-east-1.amazonaws.com',
      keyPrefix: 'uploads/',
    },
    'hello.txt',
  );

  assertEquals(typeof result.url, 'string');
  assertEquals(result.url.startsWith('http'), true);
  assertEquals(result.url.includes('X-Amz-Signature'), true);

  assertEquals(typeof result.publicUrl, 'string');
  assertEquals(result.publicUrl.includes('uploads/'), true);
  assertEquals(result.publicUrl.endsWith('-hello.txt'), true);

  assertEquals(typeof result.usage, 'string');
  assertEquals(result.usage.includes('curl'), true);
  assertEquals(result.usage.includes('<file>'), true);
  assertEquals(result.usage.includes('<url>'), true);
});

Deno.test('createPresignedPutUrl includes date/uuid prefix in key path', async () => {
  const result = await createPresignedPutUrl(
    {
      endpoint: 'https://s3.us-east-1.amazonaws.com',
      region: 'us-east-1',
      bucket: 'test-bucket',
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      publicUrlBase: 'https://test-bucket.s3.us-east-1.amazonaws.com',
      keyPrefix: 'uploads/',
    },
    'images/photo.png',
  );

  const now = new Date();
  const yyyy = String(now.getFullYear());
  const mm = String(now.getMonth() + 1).padStart(2, '0');
  const dd = String(now.getDate()).padStart(2, '0');
  const datePath = `${yyyy}/${mm}/${dd}`;

  assertEquals(result.publicUrl.includes(`uploads/${datePath}/`), true);
  assertEquals(result.publicUrl.endsWith('-images/photo.png'), true);
  assertEquals(result.url.includes(`uploads/${datePath}/`), true);
});

Deno.test('createPresignedPutUrl works without keyPrefix', async () => {
  const result = await createPresignedPutUrl(
    {
      endpoint: 'https://s3.us-east-1.amazonaws.com',
      region: 'us-east-1',
      bucket: 'test-bucket',
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      publicUrlBase: 'https://test-bucket.s3.us-east-1.amazonaws.com',
    },
    'test.txt',
  );

  assertEquals(result.publicUrl.endsWith('-test.txt'), true);
});

Deno.test('createPresignedPutUrl throws on empty filename', async () => {
  await assertRejects(
    () =>
      createPresignedPutUrl(
        {
          endpoint: 'https://s3.us-east-1.amazonaws.com',
          region: 'us-east-1',
          bucket: 'test-bucket',
          accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
          secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
          publicUrlBase: 'https://test-bucket.s3.us-east-1.amazonaws.com',
        },
        '',
      ),
    Error,
    'Filename is required',
  );
});
