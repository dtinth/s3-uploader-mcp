import { assertEquals, assertRejects } from '@std/assert';
import { decrypt, encrypt, type TokenPayload } from './jwe.ts';

Deno.test('encrypt and decrypt roundtrip', async () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const payload: TokenPayload = {
    endpoint: 'https://s3.us-east-1.amazonaws.com',
    region: 'us-east-1',
    bucket: 'my-bucket',
    accessKeyId: 'AKIA123',
    secretAccessKey: 'secret123',
    publicUrlBase: 'https://my-bucket.public.url/',
    keyPrefix: 'uploads/',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    typ: 'access_token',
  };

  const jwe = await encrypt(payload, key);
  const decrypted = await decrypt(jwe, key);

  assertEquals(decrypted, payload);
});

Deno.test('decrypt with wrong key fails', async () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const wrongKey = crypto.getRandomValues(new Uint8Array(32));
  const payload: TokenPayload = {
    endpoint: 'https://s3.us-east-1.amazonaws.com',
    region: 'us-east-1',
    bucket: 'my-bucket',
    accessKeyId: 'AKIA123',
    secretAccessKey: 'secret123',
    publicUrlBase: 'https://my-bucket.public.url/',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    typ: 'access_token',
  };

  const jwe = await encrypt(payload, key);
  await assertRejects(() => decrypt(jwe, wrongKey));
});

Deno.test('expired token is rejected', async () => {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const payload: TokenPayload = {
    endpoint: 'https://s3.us-east-1.amazonaws.com',
    region: 'us-east-1',
    bucket: 'my-bucket',
    accessKeyId: 'AKIA123',
    secretAccessKey: 'secret123',
    publicUrlBase: 'https://my-bucket.public.url/',
    iat: Math.floor(Date.now() / 1000) - 7200,
    exp: Math.floor(Date.now() / 1000) - 3600,
    typ: 'access_token',
  };

  const jwe = await encrypt(payload, key);
  await assertRejects(() => decrypt(jwe, key));
});
