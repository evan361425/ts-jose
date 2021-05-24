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
var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JWK = void 0;
const from_key_like_1 = require("jose/jwk/from_key_like");
const parse_1 = require("jose/jwk/parse");
const generate_key_pair_1 = __importDefault(require("jose/util/generate_key_pair"));
const generate_secret_1 = __importDefault(require("jose/util/generate_secret"));
const error_1 = require("./error");
const RSAPrivateProperties = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'];
class JWK {
    constructor(key, metadata) {
        this.key = key;
        this.metadata = deleteUndefined(metadata);
    }
    get kid() {
        return this.metadata.kid;
    }
    get alg() {
        return this.metadata.alg;
    }
    get use() {
        return this.metadata.use;
    }
    get kty() {
        return this.metadata.kty;
    }
    // https://tools.ietf.org/id/draft-jones-jose-json-private-and-symmetric-key-00.html#rfc.section.3.2.7
    get isPrivate() {
        switch (this.kty) {
            case 'oct':
                return true;
            case 'EC':
            case 'OKP':
                return this.metadata.d !== undefined;
            case 'RSA':
                return Object.entries(this.metadata)
                    .filter((entry) => RSAPrivateProperties.includes(entry[0]))
                    .some((entry) => entry[1] !== undefined);
        }
    }
    getKey(options) {
        if (options.kid !== undefined && options.kid !== this.kid) {
            throw new error_1.JoseError('Key', 'kid', options.kid, this.kid);
        }
        if (options.use !== undefined && this.use !== undefined) {
            if (options.use !== this.use) {
                throw new error_1.JoseError('Key', 'use', options.use, this.use);
            }
        }
        if (options.alg !== undefined && this.alg !== undefined) {
            if (options.alg !== this.alg) {
                throw new error_1.JoseError('Key', 'alg', options.alg, this.alg);
            }
        }
        return this;
    }
    toPublic() {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.isPrivate)
                return this;
            return JWK.fromObject(this.toObject());
        });
    }
    toObject(asPrivate = false) {
        if (this.isPrivate && !asPrivate) {
            const { kid, alg, use, kty, crv, x, y, e, n } = this.metadata;
            return deleteUndefined({ kid, alg, use, kty, crv, x, y, e, n });
        }
        // return new object
        const key = __rest(this.metadata, []);
        return key;
    }
    static fromObject(keyObject) {
        return __awaiter(this, void 0, void 0, function* () {
            const key = yield parse_1.parseJwk(keyObject);
            return new JWK(key, keyObject);
        });
    }
    static generate(algorithm, options) {
        return __awaiter(this, void 0, void 0, function* () {
            const key = yield getKey();
            const metadata = (yield from_key_like_1.fromKeyLike(key));
            return new JWK(key, Object.assign({ kid: options === null || options === void 0 ? void 0 : options.kid, use: options === null || options === void 0 ? void 0 : options.use, alg: algorithm }, metadata));
            function getKey() {
                return __awaiter(this, void 0, void 0, function* () {
                    if (algorithm.startsWith('HS') || algorithm.startsWith('A')) {
                        return generate_secret_1.default(algorithm);
                    }
                    const keyPair = yield generate_key_pair_1.default(algorithm, options);
                    return keyPair.privateKey;
                });
            }
        });
    }
}
exports.JWK = JWK;
function deleteUndefined(data) {
    Object.entries(data).forEach((entry) => {
        if (entry[1] === undefined) {
            delete data[entry[0]];
        }
    });
    return data;
}
