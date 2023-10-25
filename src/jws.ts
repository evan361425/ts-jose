import {
  CompactSign,
  compactVerify,
  CompactVerifyGetKey,
  CompactVerifyResult,
  decodeProtectedHeader,
  EmbeddedJWK,
} from 'jose';
import { JWSCompleteResult } from './';
import { JoseError } from './error';
import { JWK } from './jwk';
import { JWKS } from './jwks';
import {
  EmbeddedKey,
  JWKey,
  JWSHeaderParameters,
  JWSSignOptions,
  JWSVerifyOptions,
  KidOptions,
} from './types';

export class JWS {
  static async verify(
    token: string,
    key?: JWK | JWKS,
    options?: JWSVerifyOptions<false>,
  ): Promise<string>;
  static async verify(
    token: string,
    key?: JWK | JWKS,
    options?: JWSVerifyOptions<true>,
  ): Promise<JWSCompleteResult>;
  static async verify<
    T extends JWSVerifyOptions<false> | JWSVerifyOptions<true>,
  >(
    signature: string,
    jwk?: JWK | JWKS,
    options?: T,
  ): Promise<string | JWSCompleteResult> {
    const key = await this.getKeyFrom(signature, jwk, options);

    const result = (await (typeof key === 'function'
      ? compactVerify(signature, key, options)
      : compactVerify(signature, key, options))) as CompactVerifyResult & {
      key?: JWKey;
    };

    if (
      options?.typ !== undefined &&
      result.protectedHeader.typ !== options.typ
    ) {
      throw new JoseError('JWS', 'typ', options.typ);
    }

    return options?.complete
      ? {
          payload: Buffer.from(result.payload).toString(),
          header: result.protectedHeader,
          key: result.key,
        }
      : Buffer.from(result.payload).toString();
  }

  static async sign(
    data: string,
    key: JWK | JWKS,
    options?: JWSSignOptions,
  ): Promise<string> {
    const jwk = key.getKey({
      kid: options?.kid,
      use: 'sig',
      alg: options?.alg,
    });

    const encoder = new TextEncoder();
    const jws = new CompactSign(encoder.encode(data));

    jws.setProtectedHeader({
      typ: options?.typ,
      kid: options?.kid ?? jwk.kid,
      alg: options?.alg ?? jwk.alg ?? '',
      jwk: options?.jwk ? (jwk.toObject() as EmbeddedKey) : undefined,
    });

    return jws.sign(jwk.key);
  }

  // HELPER

  static async getKeyFrom(
    signature: string,
    key?: JWK | JWKS,
    options?: KidOptions,
  ): Promise<JWKey | CompactVerifyGetKey> {
    if (key === undefined) return EmbeddedJWK;

    const header = decodeProtectedHeader(signature) as JWSHeaderParameters;

    const publicKey = await key
      .getKey({
        use: 'sig',
        kid: options?.kid ? options.kid : header.kid,
        alg: header.alg,
      })
      .toPublic();

    return publicKey.key;
  }
}
