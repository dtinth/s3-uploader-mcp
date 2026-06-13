import { assertEquals, assertRejects } from '@std/assert';
import { createPresignedPutUrl } from './s3.ts';

Deno.test('createPresignedPutUrl returns presigned URL and public URL', async () => {
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
  assertEquals(result.url.includes('hello.txt'), true);

  assertEquals(typeof result.publicUrl, 'string');
  assertEquals(result.publicUrl.includes('uploads/hello.txt'), true);
});

Deno.test('createPresignedPutUrl includes keyPrefix when configured', async () => {
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

  assertEquals(result.url.includes('uploads/images/photo.png'), true);
  assertEquals(result.publicUrl.includes('uploads/images/photo.png'), true);
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

  assertEquals(result.url.includes('/test.txt'), true);
  assertEquals(result.publicUrl.endsWith('/test.txt'), true);
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
