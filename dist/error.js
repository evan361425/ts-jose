"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.JoseError = void 0;
class JoseError extends Error {
    constructor(place, key, got, expected) {
        const message = expected === undefined
            ? `${place} found "${key}" is not equal to ${got}`
            : `${place} "${key}" is got ${got}, expected ${expected}`;
        super(message);
    }
}
exports.JoseError = JoseError;
