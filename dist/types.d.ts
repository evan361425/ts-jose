import { JWTVerifyOptions as JoseJWTVerifyOptions } from 'jose/jwt/verify';
import * as jose from 'jose/types';
export declare type JWKObject = jose.JWK & {
    use?: KeyUsages;
    alg?: JWKAlgorithms;
    crv?: JWKCurves;
    kty: KeyTypes;
};
export declare type JWKey = jose.KeyLike;
export declare type JWTPayload = jose.JWTPayload;
export declare type JWKSObject = {
    keys: JWKObject[];
    [key: string]: unknown;
};
export declare type KeyOptions = {
    kid?: string;
    use?: KeyUsages;
    alg?: JWKAlgorithms;
};
export declare type EmbeddedKey = Pick<JWKObject, 'kty' | 'crv' | 'x' | 'y' | 'e' | 'n'>;
export declare type FromJWTOptions = {
    typ?: typ;
    jti?: string;
};
export declare type ToJWTOptions = {
    issuer?: string;
    audience?: string | string[];
    subject?: string;
    exp?: string | number;
    jti?: string;
    notBefore?: string | number;
    iat?: number;
};
export declare type JWSSignOptions = {
    typ?: typ;
    kid?: string;
    alg?: JWSAlgorithms;
    jwk?: boolean;
};
export declare type JWSVerifyOptions = jose.VerifyOptions & {
    algorithms?: JWSAlgorithms[];
    typ?: typ;
};
export declare type JWTVerifyOptions<complete> = JoseJWTVerifyOptions & FromJWTOptions & {
    complete?: complete;
};
export declare type JWTSignOptions = ToJWTOptions & JWSSignOptions;
export declare type JWEKeyOptions = {
    kid?: string;
};
export declare type JWTDecryptOptions<complete> = JWEKeyOptions & jose.JWTClaimVerificationOptions & FromJWTOptions & {
    complete?: complete;
    enc?: JWEEncryptAlgorithms | JWEEncryptAlgorithms[];
    alg?: JWEKeyManagement | JWEKeyManagement[];
};
export declare type JWEDecryptOptions = JWEKeyOptions & {
    alg?: JWEKeyManagement | JWEKeyManagement[];
    enc?: JWEEncryptAlgorithms | JWEEncryptAlgorithms[];
};
export declare type JWTEncryptOptions = jose.EncryptOptions & JWEKeyOptions & ToJWTOptions & {
    alg: JWEKeyManagement;
    enc: JWEEncryptAlgorithms;
    typ?: typ;
};
export declare type JWEEncryptOptions = jose.EncryptOptions & JWEKeyOptions & {
    alg: JWEKeyManagement;
    enc: JWEEncryptAlgorithms;
};
export declare type JWSHeaderParameters = jose.JWSHeaderParameters & {
    alg?: JWSAlgorithms;
};
export declare type JWTCompleteResult = {
    payload: JWTPayload;
    header: JWSHeaderParameters;
};
export declare type JWKGenerateOptions = {
    kid?: string;
    use?: KeyUsages;
    crv?: JWKCurves;
    modulusLength?: number;
};
export declare type KeyUsages = 'sig' | 'enc';
export declare type KeyTypes = 'RSA' | 'EC' | 'OKP' | 'oct';
export declare type JWSAlgorithms = 'RS256' | 'RS384' | 'RS512' | 'PS256' | 'PS384' | 'PS512' | 'ES256' | 'ES256K' | 'ES384' | 'ES512' | 'EdDSA' | 'HS256' | 'HS384' | 'HS512';
export declare type JWKCurves = 'P-256' | 'secp256k1' | 'P-384' | 'P-521' | 'Ed25519' | 'Ed448' | 'X25519' | 'X448';
export declare type JWEEncryptAlgorithms = 'A128GCM' | 'A192GCM' | 'A256GCM' | 'A128CBC-HS256' | 'A192CBC-HS384' | 'A256CBC-HS512';
export declare type JWEKeyManagement = 'A128KW' | 'A192KW' | 'A256KW' | 'A128GCMKW' | 'A192GCMKW' | 'A256GCMKW' | 'dir' | 'RSA-OAEP' | 'RSA-OAEP-256' | 'RSA-OAEP-384' | 'RSA-OAEP-512' | 'RSA1_5' | 'PBES2-HS256+A128KW' | 'PBES2-HS384+A192KW' | 'PBES2-HS512+A256KW' | 'ECDH-ES' | 'ECDH-ES+A128KW' | 'ECDH-ES+A192KW' | 'ECDH-ES+A256KW';
export declare type JWKAlgorithms = Exclude<JWSAlgorithms | JWEEncryptAlgorithms | JWEKeyManagement, 'dir'>;
declare type typ = 'jwt' | 'id-token+jwt' | 'ac+jwt' | '+jwt' | string;
export {};
