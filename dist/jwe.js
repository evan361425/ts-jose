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
Object.defineProperty(exports, "__esModule", { value: true });
exports.JWE = void 0;
const decrypt_1 = require("jose/jwe/compact/decrypt");
const encrypt_1 = require("jose/jwe/compact/encrypt");
const decode_protected_header_1 = require("jose/util/decode_protected_header");
class JWE {
    static decrypt(cypher, key, options) {
        return __awaiter(this, void 0, void 0, function* () {
            const jwk = yield this.getKeyFrom(cypher, key, options);
            if (typeof (options === null || options === void 0 ? void 0 : options.enc) === 'string')
                options.enc = [options.enc];
            if (typeof (options === null || options === void 0 ? void 0 : options.alg) === 'string')
                options.alg = [options.alg];
            const result = yield decrypt_1.compactDecrypt(cypher, jwk.key, {
                contentEncryptionAlgorithms: (options === null || options === void 0 ? void 0 : options.enc) ? [...options.enc] : undefined,
                keyManagementAlgorithms: (options === null || options === void 0 ? void 0 : options.alg) ? [...options.alg] : undefined,
            });
            const decoder = new TextDecoder();
            return decoder.decode(result.plaintext);
        });
    }
    static encrypt(data, key, options) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const jwk = key.getKey({
                use: 'enc',
                kid: options.kid,
            });
            const encoder = new TextEncoder();
            const jwe = new encrypt_1.CompactEncrypt(encoder.encode(data));
            jwe.setProtectedHeader({
                alg: options.alg,
                enc: options.enc,
                kid: (_a = options.kid) !== null && _a !== void 0 ? _a : jwk.kid,
            });
            return jwe.encrypt((yield jwk.toPublic()).key);
        });
    }
    static getKeyFrom(cypher, jwk, options) {
        return __awaiter(this, void 0, void 0, function* () {
            const header = decode_protected_header_1.decodeProtectedHeader(cypher);
            return jwk.getKey({
                use: 'enc',
                kid: (options === null || options === void 0 ? void 0 : options.kid) ? options.kid : header.kid,
            });
        });
    }
}
exports.JWE = JWE;
