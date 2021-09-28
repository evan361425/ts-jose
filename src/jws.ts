import EmbeddedJWK from 'jose/jwk/embedded';
import { CompactSign } from 'jose/jws/compact/sign';
import { compactVerify, CompactVerifyGetKey } from 'jose/jws/compact/verify';
import decodeProtectedHeader from 'jose/util/decode_protected_header';
import { JoseError } from './error';
import { JWK } from './jwk';
import { JWKS } from './jwks';
import {
  EmbeddedKey,
  JWKey,
  JWSHeaderParameters,
  JWSSignOptions,
  JWSVerifyOptions,
} from './types';

export class JWS {
  static async verify(
    signature: string,
    jwk?: JWK | JWKS,
    options?: JWSVerifyOptions,
  ): Promise<string> {
    const key = await this.getKeyFrom(signature, jwk);

    const result = await (typeof key === 'function'
      ? compactVerify(signature, key, options)
      : compactVerify(signature, key, options));

    if (
      options?.typ !== undefined &&
      result.protectedHeader.typ !== options.typ
    ) {
      throw new JoseError('JWS', 'typ', options.typ);
    }

    return result.payload.toString();
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
      alg: options?.alg ?? jwk.alg,
      jwk: options?.jwk ? (jwk.toObject() as EmbeddedKey) : undefined,
    });

    return jws.sign(jwk.key);
  }

  // HELPER

  static async getKeyFrom(
    signature: string,
    key?: JWK | JWKS,
  ): Promise<JWKey | CompactVerifyGetKey> {
    if (key === undefined) return EmbeddedJWK;

    const header = decodeProtectedHeader(signature) as JWSHeaderParameters;

    const publicKey = await key
      .getKey({
        use: 'sig',
        kid: header.kid,
        alg: header.alg,
      })
      .toPublic();

    return publicKey.key;
  }
}
