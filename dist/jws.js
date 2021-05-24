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
exports.JWS = void 0;
const embedded_1 = __importDefault(require("jose/jwk/embedded"));
const sign_1 = require("jose/jws/compact/sign");
const verify_1 = require("jose/jws/compact/verify");
const decode_protected_header_1 = __importDefault(require("jose/util/decode_protected_header"));
const error_1 = require("./error");
class JWS {
    static verify(signature, jwk, options) {
        return __awaiter(this, void 0, void 0, function* () {
            const key = yield this.getKeyFrom(signature, jwk);
            const result = yield verify_1.compactVerify(signature, key, options);
            if ((options === null || options === void 0 ? void 0 : options.typ) !== undefined &&
                result.protectedHeader.typ !== options.typ) {
                throw new error_1.JoseError('JWS', 'typ', options.typ);
            }
            return result.payload.toString();
        });
    }
    static sign(data, key, options) {
        var _a, _b;
        return __awaiter(this, void 0, void 0, function* () {
            const jwk = key.getKey({
                kid: options === null || options === void 0 ? void 0 : options.kid,
                use: 'sig',
                alg: options === null || options === void 0 ? void 0 : options.alg,
            });
            const encoder = new TextEncoder();
            const jws = new sign_1.CompactSign(encoder.encode(data));
            jws.setProtectedHeader({
                typ: options === null || options === void 0 ? void 0 : options.typ,
                kid: (_a = options === null || options === void 0 ? void 0 : options.kid) !== null && _a !== void 0 ? _a : jwk.kid,
                alg: (_b = options === null || options === void 0 ? void 0 : options.alg) !== null && _b !== void 0 ? _b : jwk.alg,
                jwk: (options === null || options === void 0 ? void 0 : options.jwk) ? jwk.toObject() : undefined,
            });
            return jws.sign(jwk.key);
        });
    }
    // HELPER
    static getKeyFrom(signature, key) {
        return __awaiter(this, void 0, void 0, function* () {
            if (key === undefined)
                return embedded_1.default;
            const header = decode_protected_header_1.default(signature);
            const publicKey = yield key
                .getKey({
                use: 'sig',
                kid: header.kid,
                alg: header.alg,
            })
                .toPublic();
            return publicKey.key;
        });
    }
}
exports.JWS = JWS;
