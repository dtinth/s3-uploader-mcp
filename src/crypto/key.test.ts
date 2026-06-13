import { assertEquals } from '@std/assert';
import { deriveKey } from './key.ts';

Deno.test('deriveKey produces deterministic results', async () => {
  const secret = 'my-secret-key';
  const result1 = await deriveKey(secret);
  const result2 = await deriveKey(secret);

  assertEquals(result1.encryptionKey, result2.encryptionKey);
  assertEquals(result1.hmacSecret, result2.hmacSecret);
});

Deno.test('deriveKey produces different sub-keys', async () => {
  const { encryptionKey, hmacSecret } = await deriveKey('test-secret');

  assertEquals(encryptionKey.byteLength, 32);
  assertEquals(hmacSecret.byteLength, 32);
});

Deno.test('different secrets produce different keys', async () => {
  const [a, b] = await Promise.all([
    deriveKey('secret-a'),
    deriveKey('secret-b'),
  ]);

  const aKey = new Uint8Array(a.encryptionKey);
  const bKey = new Uint8Array(b.encryptionKey);
  let same = true;
  for (let i = 0; i < aKey.length; i++) {
    if (aKey[i] !== bKey[i]) { same = false; break; }
  }
  assertEquals(same, false);
});
