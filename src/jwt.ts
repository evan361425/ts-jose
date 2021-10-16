import {
  EncryptJWT,
  JWTClaimVerificationOptions,
  jwtDecrypt,
  jwtVerify,
  JWTVerifyResult,
  ProduceJWT,
  SignJWT,
} from 'jose';
import { JWKey } from './';
import { JoseError } from './error';
import { JWE } from './jwe';
import { JWK } from './jwk';
import { JWKS } from './jwks';
import { JWS } from './jws';
import {
  EmbeddedKey,
  FromJWTOptions,
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
    T extends JWTVerifyOptions<false> | JWTVerifyOptions<true>,
  >(
    token: string,
    jwk?: JWK | JWKS,
    options?: T,
  ): Promise<JWTPayload | JWTCompleteResult> {
    const key = await JWS.getKeyFrom(token, jwk, options);

    const result = (await (typeof key === 'function'
      ? jwtVerify(token, key, options)
      : jwtVerify(token, key, options))) as JWTVerifyResult & { key?: JWKey };

    this.verifyJWTClaims(result.payload, options);

    return options?.complete
      ? {
          payload: result.payload,
          header: result.protectedHeader,
          key: result.key,
        }
      : result.payload;
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
      jwk: options?.jwk ? (jwk.toObject() as EmbeddedKey) : undefined,
    });

    this.setupJwt(jwt, options ?? {});

    return jwt.sign(jwk.key);
  }

  // ========== JWE ===============

  static async decrypt(
    cypher: string,
    key: JWK | JWKS,
    options?: JWTDecryptOptions<false>,
  ): Promise<JWTPayload>;
  static async decrypt(
    cypher: string,
    key: JWK | JWKS,
    options?: JWTDecryptOptions<true>,
  ): Promise<JWTCompleteResult>;
  static async decrypt<
    T extends JWTDecryptOptions<false> | JWTDecryptOptions<true>,
  >(cypher: string, key: JWK | JWKS, options?: T): Promise<JWTPayload> {
    const jwk = await JWE.getKeyFrom(cypher, key, options);

    if (typeof options?.enc === 'string') options.enc = [options.enc];
    if (typeof options?.alg === 'string') options.alg = [options.alg];

    const result = await jwtDecrypt(cypher, jwk.key, {
      contentEncryptionAlgorithms: options?.enc,
      keyManagementAlgorithms: options?.alg,
      ...options,
    });

    this.verifyJWTClaims(result.payload, options);

    return options?.complete
      ? {
          payload: result.payload,
          header: result.protectedHeader,
        }
      : result.payload;
  }

  static encrypt(
    payload: JWTPayload,
    key: JWK | JWKS,
    options: JWTEncryptOptions,
  ): Promise<string> {
    const jwk = key.getKey({
      kid: options.kid,
      use: 'enc',
    });

    const jwt = new EncryptJWT(payload);
    this.setupJwt(jwt, options);

    jwt.setProtectedHeader({
      alg: options.alg,
      enc: options.enc,
      kid: options.kid ?? jwk.kid,
      typ: options.typ ?? 'jwt',
    });

    return jwt.encrypt(jwk.key);
  }

  // ========== HELPER ===============

  static setupJwt(jwt: ProduceJWT, options: ToJWTOptions): void {
    options.issuer && jwt.setIssuer(options.issuer);
    options.audience && jwt.setAudience(options.audience);
    options.subject && jwt.setSubject(options.subject);
    options.exp && jwt.setExpirationTime(options.exp);
    options.jti && jwt.setJti(options.jti);
    options.notBefore && jwt.setNotBefore(options.notBefore);
    // To UTC timestamp
    // https://stackoverflow.com/questions/9756120/how-do-i-get-a-utc-timestamp-in-javascript
    options.iat && jwt.setIssuedAt(options.iat);
  }

  static verifyJWTClaims(
    payload: JWTPayload,
    options?: JWTClaimVerificationOptions & FromJWTOptions,
  ): void {
    if (options === undefined) return;

    if (options.jti && options.jti !== payload.jti) {
      throw new JoseError('Claim', 'jti', payload.jti, options.jti);
    }
  }
}
