import { compactDecrypt } from 'jose/jwe/compact/decrypt';
import { CompactEncrypt } from 'jose/jwe/compact/encrypt';
import { decodeProtectedHeader } from 'jose/util/decode_protected_header';
import { throwError } from './helper';
import { JWK } from './jwk';
import { JWKS } from './jwks';
import {
  EmbeddedKey,
  JWEDecryptOptions,
  JWEEncryptOptions,
  JWEKeyOptions,
} from './types';

export class JWE {
  static async decrypt(
    cypher: string,
    key?: JWK | JWKS,
    options?: JWEDecryptOptions,
  ): Promise<string> {
    const jwk = await this.getKeyFrom(cypher, key, options);
    const { plaintext } = await compactDecrypt(cypher, jwk.key, {
      contentEncryptionAlgorithms: options?.enc ? [...options.enc] : undefined,
      keyManagementAlgorithms: options?.alg ? [...options.alg] : undefined,
    });

    return plaintext.toString();
  }

  static encrypt(data: string, key: JWK | JWKS, options: JWEEncryptOptions) {
    const jwk = key.getKey({
      use: 'enc',
      kid: options.kid,
      alg: options.alg === 'dir' ? undefined : options.alg,
    });

    const encoder = new TextEncoder();
    const jwe = new CompactEncrypt(encoder.encode(data));

    jwe.setProtectedHeader({
      alg: options.alg,
      enc: options.enc,
      kid: options.kid ?? jwk.kid,
    });

    return jwe.encrypt(jwk.key);
  }

  static async getKeyFrom(
    cypher: string,
    jwk?: JWK | JWKS,
    options?: JWEKeyOptions,
  ): Promise<JWK> {
    const header = decodeProtectedHeader(cypher);

    if (jwk === undefined) {
      if (header.jwk === undefined) {
        return throwError('JWE', 'key', 'it is empty in header');
      }

      const embedded = await JWK.fromObject(header.jwk as EmbeddedKey);
      return embedded;
    }

    return jwk.getKey({
      use: 'enc',
      kid: options?.kid ? options.kid : header.kid,
    });
  }
}
