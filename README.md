# TS JOSE

[![test](https://github.com/evan361425/ts-jose/actions/workflows/test.yml/badge.svg)](https://github.com/evan361425/ts-jose)
[![Version](https://img.shields.io/npm/v/ts-jose)](https://www.npmjs.com/package/ts-jose)

[![codecov](https://codecov.io/gh/evan361425/ts-jose/branch/master/graph/badge.svg)](https://codecov.io/gh/evan361425/ts-jose)
[![Quality](https://img.shields.io/codefactor/grade/github/evan361425/ts-jose)](https://www.codefactor.io/repository/github/evan361425/ts-jose)

[![Dependencies](https://img.shields.io/librariesio/github/evan361425/ts-jose)](https://github.com/panva/jose/releases/latest)
![Node Version](https://img.shields.io/node/v/ts-jose)
[![Activity](https://img.shields.io/github/commits-since/evan361425/ts-jose/latest)](https://github.com/evan361425/ts-jose/releases/latest)
[![License](https://img.shields.io/github/license/evan361425/ts-jose)](LICENSE)

Wrap functions of [JOSE](https://github.com/panva/jose) in steady interface.

> [!Note]
>
> This package's version will FOLLOW the version of JOSE

-   [JWT](#jwt)
    -   [verify](#verify)
    -   [sign](#sign)
    -   [decrypt](#decrypt)
    -   [encrypt](#encrypt)
-   [JWS](#jws)
    -   [verify](#verify-1)
    -   [sign](#sign-1)
-   [JWE](#jwe)
    -   [decrypt](#decrypt-1)
    -   [encrypt](#encrypt-1)
-   [JWK](#jwk)
-   [JWKS](#jwks)

## JWT

### verify

[JOSE ref](https://github.com/panva/jose/blob/main/docs/interfaces/jwt_verify.JWTVerifyOptions.md)

Additional options

| name | Description                  |
| ---- | ---------------------------- |
| kid  | Using specific key in `JWKS` |
| jti  | Verify payload `jti`         |

```ts
// `key` must be JWK or JWKS.
await JWT.verify(token, key, options);
// Use embedded key instead given one.
await JWT.verify(token, undefined, options);
```

### sign

-   [JOSE ref for payload](https://github.com/panva/jose/blob/main/docs/classes/jwt_sign.SignJWT.md)
-   [JOSE ref for header](https://github.com/panva/jose/blob/main/docs/interfaces/types.JWSHeaderParameters.md)

Using JOSE options

| name      | Referrer          |
| --------- | ----------------- |
| issuer    | setIssuer         |
| audience  | setAudience       |
| subject   | setSubject        |
| exp       | setExpirationTime |
| jti       | setJti            |
| notBefore | setNotBefore      |
| iat       | setIssuedAt       |
| typ       | Header            |
| kid       | Header            |
| alg       | Header            |

Additional options

| name | type      | default | description                    |
| ---- | --------- | ------- | ------------------------------ |
| jwk  | _boolean_ | `false` | Whether embedded key to header |

```ts
await JWT.sign(payload, key, options); // key must be JWK or JWKS
```

### decrypt

[JOSE ref](https://github.com/panva/jose/blob/main/docs/interfaces/jwt_decrypt.JWTDecryptOptions.md)

Additional options

| name | Description                  |
| ---- | ---------------------------- |
| kid  | Using specific key in `JWKS` |
| enc  | Encrypt algorithm            |
| alg  | Key management algorithm     |

```ts
await JWT.decrypt(cypher, key, options);
```

### encrypt

[JOSE ref](https://github.com/panva/jose/blob/main/docs/classes/jwt_encrypt.EncryptJWT.md)

Using JOSE options

| name      | Referrer          |
| --------- | ----------------- |
| issuer    | setIssuer         |
| audience  | setAudience       |
| subject   | setSubject        |
| exp       | setExpirationTime |
| jti       | setJti            |
| notBefore | setNotBefore      |
| iat       | setIssuedAt       |
| typ       | Header            |
| kid       | Header            |
| enc       | Header            |
| alg       | Header            |

```ts
await JWT.encrypt(payload, key, options);
```

## JWS

You can sign pure string.

### verify

[JOSE ref](https://github.com/panva/jose/blob/main/docs/functions/jws_compact_verify.compactVerify.md)

```ts
await JWS.verify(data, key, options);
```

### sign

[JOSE ref](https://github.com/panva/jose/blob/main/docs/classes/jws_compact_sign.CompactSign.md)

Only using below [JWT.sign](#sign)'s options:

-   `typ`
-   `kid`
-   `alg`
-   `jwk`

```ts
await JWS.sign('some-data', key, options);
```

## JWE

You can encrypt pure string.

### decrypt

[JOSE ref](https://github.com/panva/jose/blob/main/docs/functions/jwe_compact_decrypt.compactDecrypt.md)

Additional options

Same as [JWT.decrypt](#decrypt)

```ts
await JWE.decrypt(cypher, key, options);
```

### encrypt

[JOSE ref](https://github.com/panva/jose/blob/main/docs/classes/jwe_compact_encrypt.CompactEncrypt.md)

Only using below [JWT.encrypt](#encrypt)'s options:

-   `kid`
-   `alg`
-   `enc`

```ts
await JWE.encrypt('some-data', key, options);
```

## JWK

[JOSE ref](https://github.com/panva/jose/blob/main/docs/interfaces/types.JWK.md)

```ts
// generate key
const key: JWK = await JWK.generate('ES256', {
  kid: 'some-id',
  use: 'sig',
  // crv: string, some algorithms need to add curve - EdDSA
  // modulusLength: number, some algorithms need to add length - RSA
});

// object to JWK
const key: JWK = await JWK.fromObject({
  kid: 'some-id',
  alg: 'ES256',
  kty: 'EC',
  crv: 'P-256',
  x: '123',
  y: '456',
  d: '789',
});

// JWK to object
const keyObject: JWKObject = key.toObject(false); // true to output private object, default: false

// private JWK to public JWK
const newKey: JWK = await key.toPublic();

// get key's status
key.isPrivate;

// check key "id", "use", "alg"
try {
  // return `this` if all pass
  key.getKey({ kid: 'some-id', use: 'sig', alg: 'ES256' });
} catch (err) {
  // throw error if this key has different metadata from options
}
```

## JWKS

```ts
// object to JWKS
const keys = await JWKS.fromObject({
  keys: [
    {
      alg: 'ES256',
      kty: 'EC',
      x: '123',
      y: '456',
    },
  ],
});

// get key from store in specific options
try {
  const key: JWK = keys.getKey({ kid: 'some-id', use: 'sig', alg: 'ES256' });
} catch (err) {
  // throw error if not found
}
const key: JWK = keys.getKeyByKid('some-id');
const key: JWK = keys.getKeyByUse('sig');
const key: JWK = keys.getKeyByAlg('ES256');
```
