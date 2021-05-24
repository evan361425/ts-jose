import ProduceJWT from 'jose/lib/jwt_producer';
import { JoseHeaderParameters, JWTClaimVerificationOptions } from 'jose/types';
import { JWK } from './jwk';
import { JWKS } from './jwks';
import { FromJWTOptions, JWTCompleteResult, JWTDecryptOptions, JWTEncryptOptions, JWTPayload, JWTSignOptions, JWTVerifyOptions, ToJWTOptions } from './types';
export declare class JWT {
    static verify(token: string, key?: JWK | JWKS, options?: JWTVerifyOptions<false>): Promise<JWTPayload>;
    static verify(token: string, key?: JWK | JWKS, options?: JWTVerifyOptions<true>): Promise<JWTCompleteResult>;
    static sign(payload: JWTPayload, key: JWK | JWKS, options?: JWTSignOptions): Promise<string>;
    static decrypt(cypher: string, key: JWK | JWKS, options?: JWTDecryptOptions<false>): Promise<JWTPayload>;
    static decrypt(cypher: string, key: JWK | JWKS, options?: JWTDecryptOptions<true>): Promise<JWTCompleteResult>;
    static encrypt(payload: JWTPayload, key: JWK | JWKS, options: JWTEncryptOptions): Promise<string>;
    static setupJwt(jwt: ProduceJWT, options: ToJWTOptions): void;
    static verifyJWTClaims(payload: JWTPayload, header: JoseHeaderParameters, options?: JWTClaimVerificationOptions & FromJWTOptions): void;
}
