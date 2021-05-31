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
export type JWKSObject = { keys: JWKObject[]; [key: string]: unknown };
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
  typ?: typ;
  jti?: string;
};
export type ToJWTOptions = {
  issuer?: string;
  audience?: string | string[];
  subject?: string;
  exp?: string | number;
  jti?: string;
  notBefore?: string | number;
  iat?: number;
};
export type JWSSignOptions = {
  // header
  typ?: typ;
  kid?: string;
  alg?: JWSAlgorithms;
  // embedded key
  jwk?: boolean;
};
export type JWSVerifyOptions = jose.VerifyOptions & {
  algorithms?: JWSAlgorithms[];
  typ?: typ;
};

export type JWTVerifyOptions<complete> = JoseJWTVerifyOptions &
  FromJWTOptions & { complete?: complete };

export type JWTSignOptions = ToJWTOptions & JWSSignOptions;

export type JWEKeyOptions = { kid?: string };

export type JWTDecryptOptions<complete> = JWEKeyOptions &
  jose.JWTClaimVerificationOptions &
  FromJWTOptions & {
    complete?: complete;
    enc?: JWEEncryptAlgorithms | JWEEncryptAlgorithms[];
    alg?: JWEKeyManagement | JWEKeyManagement[];
  };
export type JWEDecryptOptions = JWEKeyOptions & {
  alg?: JWEKeyManagement | JWEKeyManagement[];
  enc?: JWEEncryptAlgorithms | JWEEncryptAlgorithms[];
};

export type JWTEncryptOptions = jose.EncryptOptions &
  JWEKeyOptions &
  ToJWTOptions & {
    // header
    alg: JWEKeyManagement;
    enc: JWEEncryptAlgorithms;
    typ?: typ;
  };
export type JWEEncryptOptions = jose.EncryptOptions &
  JWEKeyOptions & {
    alg: JWEKeyManagement;
    enc: JWEEncryptAlgorithms;
  };

export type JWSHeaderParameters = jose.JWSHeaderParameters & {
  alg?: JWSAlgorithms;
};

export type JWTCompleteResult = {
  payload: JWTPayload;
  header: JWSHeaderParameters;
};

export type JWKGenerateOptions = {
  kid?: string;
  use?: KeyUsages;
  crv?: JWKCurves;
  modulusLength?: number;
};

export type KeyUsages = 'sig' | 'enc';

export type KeyTypes = 'RSA' | 'EC' | 'OKP' | 'oct';

export type thumbprintConfig = {
  digestAlgorithm?: 'sha256' | 'sha384' | 'sha512';
};

export type JWSAlgorithms =
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

export type JWEEncryptAlgorithms =
  | 'A128GCM'
  | 'A192GCM'
  | 'A256GCM'
  | 'A128CBC-HS256'
  | 'A192CBC-HS384'
  | 'A256CBC-HS512';

export type JWEKeyManagement =
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

export type JWKAlgorithms = Exclude<
  JWSAlgorithms | JWEEncryptAlgorithms | JWEKeyManagement,
  'dir'
>;

type typ = 'jwt' | 'id-token+jwt' | 'ac+jwt' | '+jwt' | string;
