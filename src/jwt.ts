import { compactDecrypt } from 'jose/jwe/compact/decrypt';
import { CompactEncrypt } from 'jose/jwe/compact/encrypt';
import { EmbeddedJWK } from 'jose/jwk/embedded';
import jwtDecrypt from 'jose/jwt/decrypt';
import { EncryptJWT } from 'jose/jwt/encrypt';
import SignJWT from 'jose/jwt/sign';
import jwtVerify, { JWTVerifyGetKey } from 'jose/jwt/verify';
import ProduceJWT from 'jose/lib/jwt_producer';
import { JoseHeaderParameters, JWTClaimVerificationOptions } from 'jose/types';
import { decodeProtectedHeader } from 'jose/util/decode_protected_header';
import { throwError } from './helper';
import { JWK } from './jwk';
import { JWKS } from './jwks';
import {
  EmbeddedKey,
  FromJWTOptions,
  JWKey,
  JWSHeaderParameters,
  JWTCompleteResult,
  JWTDecryptOptions,
  JWTEncryptOptions,
  JWTPayload,
  JWTSignOptions,
  JWTVerifyOptions,
  ToJWTOptions,
} from './types';

export class JWT {
  // ========== JWS ===============

  static async verify(
    token: string,
    key?: JWK | JWKS,
    options?: JWTVerifyOptions<false>,
  ): Promise<JWTPayload>;
  static async verify(
    token: string,
    key?: JWK | JWKS,
    options?: JWTVerifyOptions<true>,
  ): Promise<JWTCompleteResult>;
  static async verify<
    T extends JWTVerifyOptions<false> | JWTVerifyOptions<true>
  >(
    token: string,
    key?: JWK | JWKS,
    options?: T,
  ): Promise<JWTPayload | JWTCompleteResult> {
    const result = await jwtVerify(token, getKey(), options);

    this.verifyJWTClaims(result.payload, result.protectedHeader, options);

    return options?.complete
      ? {
          payload: result.payload,
          header: result.protectedHeader,
        }
      : result.payload;

    function getKey(): JWKey | JWTVerifyGetKey {
      if (key === undefined) return EmbeddedJWK;

      const header = decodeProtectedHeader(token) as JWSHeaderParameters;

      return key.getKey({
        use: 'sig',
        kid: header.kid,
        alg: header.alg,
      }).key;
    }
  }

  static sign(
    payload: JWTPayload,
    key: JWK | JWKS,
    options?: JWTSignOptions,
  ): Promise<string> {
    const jwk = key.getKey({
      kid: options?.kid,
      use: 'sig',
      alg: options?.alg,
    });
    const jwt = new SignJWT(payload);

    jwt.setProtectedHeader({
      typ: options?.typ ?? 'jwt',
      kid: options?.kid ?? jwk.kid,
      alg: options?.alg ?? jwk.alg,
      jwk: options?.jwk,
    });

    this.setupJwt(jwt, options ?? {});

    return jwt.sign(jwk.key);
  }

  // ========== JWE ===============

  static async decrypt(
    token: string,
    jwk?: JWK | JWKS,
    options?: JWTDecryptOptions<false>,
  ): Promise<JWTPayload>;
  static async decrypt(
    token: string,
    jwk?: JWK | JWKS,
    options?: JWTDecryptOptions<true>,
  ): Promise<JWTCompleteResult>;
  static async decrypt<
    T extends JWTDecryptOptions<false> | JWTDecryptOptions<true>
  >(
    token: string,
    jwk?: JWK | JWKS,
    options?: T,
  ): Promise<JWTPayload | string> {
    const key = await getKey();
    const usePlainText =
      Object.keys(options ?? {}).find((option) => option !== 'typ') ===
      undefined;

    if (options?.useText) {
      const { plaintext } = await compactDecrypt(token, key);
      return plaintext.toString();
    }

    const result = await jwtDecrypt(token, key, options);
    this.verifyJWTClaims(result.payload, result.protectedHeader, options);

    return result.payload;

    async function getKey(): Promise<JWKey> {
      const header = decodeProtectedHeader(token);

      if (jwk === undefined) {
        if (header.jwk === undefined) {
          return throwError('JWT decrypt', 'jwk', 'empty in header');
        }

        const embedded = await JWK.fromObject(header.jwk as EmbeddedKey);
        return embedded.key;
      }

      return jwk.getKey({
        use: 'enc',
        kid: header.kid,
      }).key;
    }
  }

  static encrypt(
    data: string | JWTPayload,
    key: JWK | JWKS,
    options: JWTEncryptOptions,
  ) {
    const jwk = key.getKey({
      kid: options.kid,
      use: 'enc',
      alg: options.alg === 'dir' ? undefined : options.alg,
    });

    const jwt =
      typeof data === 'string'
        ? getProducerByString(data)
        : getProducerByPayload(data);

    jwt.setProtectedHeader({
      alg: options.alg,
      enc: options.enc,
      kid: options.kid ?? jwk.kid,
      jwk: options.jwk,
      typ: options.typ,
    });

    return jwt.encrypt(jwk.key);

    function getProducerByPayload(payload: JWTPayload) {
      const jwt = new EncryptJWT(payload);
      JWT.setupJwt(jwt, options);
      return jwt;
    }

    function getProducerByString(data: string) {
      const encoder = new TextEncoder();
      return new CompactEncrypt(encoder.encode(data));
    }
  }

  // ========== HELPER ===============

  static setupJwt(jwt: ProduceJWT, options: ToJWTOptions) {
    options.issuer && jwt.setIssuer(options.issuer);
    options.audience && jwt.setAudience(options.audience);
    options.subject && jwt.setSubject(options.subject);
    options.exp && jwt.setExpirationTime(options.exp);
    options.jti && jwt.setJti(options.jti);
    options.notBefore && jwt.setNotBefore(options.notBefore);
    // To UTC timestamp
    // https://stackoverflow.com/questions/9756120/how-do-i-get-a-utc-timestamp-in-javascript
    options.iat && jwt.setIssuedAt(Math.floor(options.iat.getTime() / 1000));
  }

  static verifyJWTClaims(
    payload: JWTPayload,
    header: JoseHeaderParameters,
    options?: JWTClaimVerificationOptions & FromJWTOptions,
  ) {
    if (options === undefined) return;

    if (options.typ && options.typ !== header.typ) {
      throwError('Claim', 'typ', header.typ, options.typ);
    }

    if (options.jti && options.jti !== payload.jti) {
      throwError('Claim', 'jti', payload.jti, options.jti);
    }
  }
}
