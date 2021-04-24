import EmbeddedJWK from 'jose/jwk/embedded';
import { CompactSign } from 'jose/jws/compact/sign';
import { compactVerify, CompactVerifyGetKey } from 'jose/jws/compact/verify';
import decodeProtectedHeader from 'jose/util/decode_protected_header';
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
    const key = this.getKeyFrom(signature, jwk);
    const result = await compactVerify(signature, key, options);

    return result.payload.toString();
  }
  static async sign(data: string, key: JWK | JWKS, options?: JWSSignOptions) {
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

  static getKeyFrom(
    signature: string,
    key?: JWK | JWKS,
  ): JWKey | CompactVerifyGetKey {
    if (key === undefined) return EmbeddedJWK;

    const header = decodeProtectedHeader(signature) as JWSHeaderParameters;

    return key.getKey({
      use: 'sig',
      kid: header.kid,
      alg: header.alg,
    }).key;
  }
}
