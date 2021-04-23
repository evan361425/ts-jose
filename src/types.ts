import { JWTDecryptOptions as JoseJWTDecryptOptions } from 'jose/jwt/decrypt';
import { JWTVerifyOptions as JoseJWTVerifyOptions } from 'jose/jwt/verify';
import * as jose from 'jose/types';

export type JWKObject = jose.JWK & {
  use?: KeyUsages;
  alg?: JWKAlgorithms;
  crv?: JWKCurves;
  kty: KeyTypes;
};
export type JWKey = jose.KeyLike;
export type JWTPayload = jose.JWTPayload;
export type JWKSObject = { keys: JWKObject[] };
export type KeyOptions = {
  kid?: string;
  use?: KeyUsages;
  alg?: JWKAlgorithms;
};
export type EmbeddedKey = Pick<
  JWKObject,
  'kty' | 'crv' | 'x' | 'y' | 'e' | 'n'
>;

export type FromJWTOptions = {
  typ?: string;
  jti?: string;
};
export type ToJWTOptions = {
  issuer?: string;
  audience?: string;
  subject?: string;
  exp?: string | number;
  jti?: string;
  notBefore?: string | number;
  iat?: Date;
};

export type JWTVerifyOptions<complete> = JoseJWTVerifyOptions &
  FromJWTOptions & { complete?: complete };

export type JWTSignOptions = ToJWTOptions & {
  // header
  typ?: string;
  kid?: string;
  alg?: JWKAlgorithms;
  // embedded key
  jwk?: EmbeddedKey;
};

export type JWTDecryptOptions<text> = JoseJWTDecryptOptions &
  FromJWTOptions & { useText?: text };

export type JWTEncryptOptions = ToJWTOptions & {
  // header
  alg: JWEManagement;
  enc: JWEAlgorithms;
  typ?: string;
  kid?: string;
  keyAlg?: JWKAlgorithms;
  // embedded key
  jwk?: Pick<jose.JWK, 'kty' | 'crv' | 'x' | 'y' | 'e' | 'n'>;
};

export type JWSHeaderParameters = jose.JWSHeaderParameters & {
  alg?: JWKAlgorithms;
};

export type JWTCompleteResult = {
  payload: JWTPayload;
  header: JWSHeaderParameters;
};

export type JWKGenerateOptions = {
  kid?: string;
  use?: KeyUsages;
  alg?: JWKAlgorithms;
  crv?: JWKCurves;
  modulusLength?: number;
};

export type KeyUsages = 'sig' | 'enc';

export type KeyTypes = 'RSA' | 'EC' | 'OKP' | 'oct';

export type JWKAlgorithms =
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'ES256'
  | 'ES256K'
  | 'ES384'
  | 'ES512'
  | 'EdDSA'
  | 'HS256'
  | 'HS384'
  | 'HS512';

export type JWKCurves =
  | 'P-256'
  | 'secp256k1'
  | 'P-384'
  | 'P-521'
  | 'Ed25519'
  | 'Ed448'
  | 'X25519'
  | 'X448';

export type JWEAlgorithms =
  | 'A128GCM'
  | 'A192GCM'
  | 'A256GCM'
  | 'A128CBC-HS256'
  | 'A192CBC-HS384'
  | 'A256CBC-HS512';

export type JWEManagement =
  | 'A128KW'
  | 'A192KW'
  | 'A256KW'
  | 'A128GCMKW'
  | 'A192GCMKW'
  | 'A256GCMKW'
  | 'dir'
  | 'RSA-OAEP'
  | 'RSA-OAEP-256'
  | 'RSA-OAEP-384'
  | 'RSA-OAEP-512'
  | 'RSA1_5'
  | 'PBES2-HS256+A128KW'
  | 'PBES2-HS384+A192KW'
  | 'PBES2-HS512+A256KW'
  | 'ECDH-ES'
  | 'ECDH-ES+A128KW'
  | 'ECDH-ES+A192KW'
  | 'ECDH-ES+A256KW';
