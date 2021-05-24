import { JWKAlgorithms, JWKey, JWKGenerateOptions, JWKObject, KeyOptions, KeyTypes, KeyUsages } from './types';
export declare class JWK {
    readonly key: JWKey;
    readonly metadata: JWKObject;
    constructor(key: JWKey, metadata: JWKObject);
    get kid(): string | undefined;
    get alg(): JWKAlgorithms | undefined;
    get use(): KeyUsages | undefined;
    get kty(): KeyTypes;
    get isPrivate(): boolean;
    getKey(options: KeyOptions): JWK;
    toPublic(): Promise<JWK>;
    toObject(asPrivate?: boolean): JWKObject;
    static fromObject(keyObject: JWKObject): Promise<JWK>;
    static generate(algorithm: JWKAlgorithms, options?: JWKGenerateOptions): Promise<JWK>;
}
