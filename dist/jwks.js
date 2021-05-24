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
exports.JWKS = void 0;
const error_1 = require("./error");
const jwk_1 = require("./jwk");
class JWKS {
    constructor(keys) {
        this.keys = keys;
    }
    getKey(options = {}) {
        if (options.kid !== undefined) {
            const key = this.getKeyByKid(options.kid);
            if (key === undefined) {
                throw new error_1.JoseError('Keys', 'kid', options.kid);
            }
            else if (options.use !== undefined && key.use !== options.use) {
                throw new error_1.JoseError('Keys', 'use', key.use, options.use);
            }
            else if (options.alg !== undefined && key.alg !== undefined) {
                if (key.alg !== options.alg) {
                    throw new error_1.JoseError('Keys', 'alg', key.alg, options.alg);
                }
            }
            return key;
        }
        const keys1 = options.use !== undefined ? this.getKeyByUse(options.use) : this.keys;
        if (keys1.length === 0)
            throw new error_1.JoseError('Keys', 'use', options.use);
        const keys2 = options.alg !== undefined ? this.getKeyByAlg(options.alg, keys1) : keys1;
        if (keys2.length === 0)
            throw new error_1.JoseError('Keys', 'alg', options.alg);
        return keys2[0];
    }
    getKeyByKid(kid) {
        return this.keys.find((key) => key.kid === kid);
    }
    getKeyByUse(use, keys) {
        if (keys === undefined) {
            keys = this.keys;
        }
        return keys.filter((key) => key.use === use);
    }
    getKeyByAlg(alg, keys) {
        if (keys === undefined) {
            keys = this.keys;
        }
        return keys.filter((key) => key.alg === alg);
    }
    static fromObject(jwks) {
        return __awaiter(this, void 0, void 0, function* () {
            const keys = [];
            for (const key of jwks.keys) {
                keys.push(yield jwk_1.JWK.fromObject(key));
            }
            return new JWKS(keys);
        });
    }
}
exports.JWKS = JWKS;
