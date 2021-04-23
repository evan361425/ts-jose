import { EmbeddedJWK } from 'jose/jwk/embedded';
import SignJWT from 'jose/jwt/sign';
import jwtVerify, { JWTVerifyGetKey } from 'jose/jwt/verify';
import { decodeProtectedHeader } from 'jose/util/decode_protected_header';
import { throwError } from './helper';
import { JWK } from './jwk';
import { JWKS } from './jwks';
import {
  JWKey,
  JWSHeaderParameters,
  JWTCompleteResult,
  JWTPayload,
  JWTSignOptions,
  JWTVerifyOptions,
} from './types';

export class JWT {
  static async verify(
    token: string,
    key?: JWK | JWKS,
    option?: JWTVerifyOptions<false>,
  ): Promise<JWTPayload>;
  static async verify(
    token: string,
    key?: JWK | JWKS,
    option?: JWTVerifyOptions<true>,
  ): Promise<JWTCompleteResult>;
  static async verify<
    T extends JWTVerifyOptions<false> | JWTVerifyOptions<true>
  >(
    token: string,
    key?: JWK | JWKS,
    options?: T,
  ): Promise<JWTPayload | JWTCompleteResult> {
    const result = await jwtVerify(token, getKey(), options);

    verifyCustomClaims();

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

    function verifyCustomClaims() {
      if (
        options?.typ !== undefined &&
        options.typ !== result.protectedHeader.typ
      ) {
        throwError('Claim', 'typ', result.protectedHeader.typ, options.typ);
      }

      if (options?.jti !== undefined && options.jti !== result.payload.jti) {
        throwError('Claim', 'jti', result.payload.jti, options.jti);
      }
    }
  }

  static sign(
    key: JWK | JWKS,
    options: JWTSignOptions,
    payload: JWTPayload = {},
  ): Promise<string> {
    const jwk = key.getKey({ kid: options.kid, use: 'sig' });
    const jwt = new SignJWT(payload);

    jwt.setProtectedHeader({
      typ: options.typ ?? 'jwt',
      kid: options.kid ?? jwk.kid,
      alg: options.alg ?? jwk.alg,
      jwk: options.jwk,
    });

    options.issuer && jwt.setIssuer(options.issuer);
    options.audience && jwt.setAudience(options.audience);
    options.subject && jwt.setSubject(options.subject);
    options.exp && jwt.setExpirationTime(options.exp);
    options.jti && jwt.setJti(options.jti);
    options.notBefore && jwt.setNotBefore(options.notBefore);
    // To UTC timestamp
    // https://stackoverflow.com/questions/9756120/how-do-i-get-a-utc-timestamp-in-javascript
    options.iat && jwt.setIssuedAt(Math.floor(options.iat.getTime() / 1000));

    return jwt.sign(jwk.key);
  }
}
