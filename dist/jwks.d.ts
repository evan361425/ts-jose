import { JWK } from './jwk';
import { JWKAlgorithms, JWKSObject, KeyOptions, KeyUsages } from './types';
export declare class JWKS {
    readonly keys: JWK[];
    constructor(keys: JWK[]);
    getKey(options?: KeyOptions): JWK;
    getKeyByKid(kid: string): JWK | undefined;
    getKeyByUse(use: KeyUsages, keys?: JWK[]): JWK[];
    getKeyByAlg(alg: JWKAlgorithms, keys?: JWK[]): JWK[];
    static fromObject(jwks: JWKSObject): Promise<JWKS>;
}
