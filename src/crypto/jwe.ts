import { EncryptJWT, jwtDecrypt } from 'jose';

export type TokenType = 'auth_code' | 'access_token' | 'refresh_token';

export interface TokenPayload {
  endpoint: string;
  region: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  publicUrlBase: string;
  keyPrefix?: string;
  codeChallenge?: string;
  clientId?: string;
  typ: TokenType;
  iat: number;
  exp: number;
}

export async function encrypt(
  payload: TokenPayload,
  key: Uint8Array,
): Promise<string> {
  const jwe = await new EncryptJWT({ ...payload })
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .setIssuedAt(payload.iat)
    .setExpirationTime(payload.exp)
    .encrypt(key);
  return jwe;
}

export async function decrypt(
  jwe: string,
  key: Uint8Array,
): Promise<TokenPayload> {
  const { payload } = await jwtDecrypt(jwe, key);
  return payload as unknown as TokenPayload;
}
