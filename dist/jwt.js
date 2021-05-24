"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JWT = void 0;
const decrypt_1 = __importDefault(require("jose/jwt/decrypt"));
const encrypt_1 = require("jose/jwt/encrypt");
const sign_1 = __importDefault(require("jose/jwt/sign"));
const verify_1 = __importDefault(require("jose/jwt/verify"));
const error_1 = require("./error");
const jwe_1 = require("./jwe");
const jws_1 = require("./jws");
class JWT {
    static verify(token, jwk, options) {
        return __awaiter(this, void 0, void 0, function* () {
            const key = yield jws_1.JWS.getKeyFrom(token, jwk);
            const result = yield verify_1.default(token, key, options);
            this.verifyJWTClaims(result.payload, result.protectedHeader, options);
            return (options === null || options === void 0 ? void 0 : options.complete)
                ? {
                    payload: result.payload,
                    header: result.protectedHeader,
                }
                : result.payload;
        });
    }
    static sign(payload, key, options) {
        var _a, _b, _c;
        const jwk = key.getKey({
            kid: options === null || options === void 0 ? void 0 : options.kid,
            use: 'sig',
            alg: options === null || options === void 0 ? void 0 : options.alg,
        });
        const jwt = new sign_1.default(payload);
        jwt.setProtectedHeader({
            typ: (_a = options === null || options === void 0 ? void 0 : options.typ) !== null && _a !== void 0 ? _a : 'jwt',
            kid: (_b = options === null || options === void 0 ? void 0 : options.kid) !== null && _b !== void 0 ? _b : jwk.kid,
            alg: (_c = options === null || options === void 0 ? void 0 : options.alg) !== null && _c !== void 0 ? _c : jwk.alg,
            jwk: (options === null || options === void 0 ? void 0 : options.jwk) ? jwk.toObject() : undefined,
        });
        this.setupJwt(jwt, options !== null && options !== void 0 ? options : {});
        return jwt.sign(jwk.key);
    }
    static decrypt(cypher, key, options) {
        return __awaiter(this, void 0, void 0, function* () {
            const jwk = yield jwe_1.JWE.getKeyFrom(cypher, key, options);
            if (typeof (options === null || options === void 0 ? void 0 : options.enc) === 'string')
                options.enc = [options.enc];
            if (typeof (options === null || options === void 0 ? void 0 : options.alg) === 'string')
                options.alg = [options.alg];
            const result = yield decrypt_1.default(cypher, jwk.key, Object.assign({ contentEncryptionAlgorithms: options === null || options === void 0 ? void 0 : options.enc, keyManagementAlgorithms: options === null || options === void 0 ? void 0 : options.alg }, options));
            this.verifyJWTClaims(result.payload, result.protectedHeader, options);
            return (options === null || options === void 0 ? void 0 : options.complete)
                ? {
                    payload: result.payload,
                    header: result.protectedHeader,
                }
                : result.payload;
        });
    }
    static encrypt(payload, key, options) {
        var _a, _b;
        const jwk = key.getKey({
            kid: options.kid,
            use: 'enc',
        });
        const jwt = new encrypt_1.EncryptJWT(payload);
        this.setupJwt(jwt, options);
        jwt.setProtectedHeader({
            alg: options.alg,
            enc: options.enc,
            kid: (_a = options.kid) !== null && _a !== void 0 ? _a : jwk.kid,
            typ: (_b = options.typ) !== null && _b !== void 0 ? _b : 'jwt',
        });
        return jwt.encrypt(jwk.key);
    }
    // ========== HELPER ===============
    static setupJwt(jwt, options) {
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
    static verifyJWTClaims(payload, header, options) {
        if (options === undefined)
            return;
        if (options.typ && options.typ !== header.typ) {
            throw new error_1.JoseError('Claim', 'typ', header.typ, options.typ);
        }
        if (options.jti && options.jti !== payload.jti) {
            throw new error_1.JoseError('Claim', 'jti', payload.jti, options.jti);
        }
    }
}
exports.JWT = JWT;
