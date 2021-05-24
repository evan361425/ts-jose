import { JWK } from './jwk';
import { JWKS } from './jwks';
import { JWEDecryptOptions, JWEEncryptOptions, JWEKeyOptions } from './types';
export declare class JWE {
    static decrypt(cypher: string, key: JWK | JWKS, options?: JWEDecryptOptions): Promise<string>;
    static encrypt(data: string, key: JWK | JWKS, options: JWEEncryptOptions): Promise<string>;
    static getKeyFrom(cypher: string, jwk: JWK | JWKS, options?: JWEKeyOptions): Promise<JWK>;
}
