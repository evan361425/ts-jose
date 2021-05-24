import { CompactVerifyGetKey } from 'jose/jws/compact/verify';
import { JWK } from './jwk';
import { JWKS } from './jwks';
import { JWKey, JWSSignOptions, JWSVerifyOptions } from './types';
export declare class JWS {
    static verify(signature: string, jwk?: JWK | JWKS, options?: JWSVerifyOptions): Promise<string>;
    static sign(data: string, key: JWK | JWKS, options?: JWSSignOptions): Promise<string>;
    static getKeyFrom(signature: string, key?: JWK | JWKS): Promise<JWKey | CompactVerifyGetKey>;
}
