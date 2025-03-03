# TS JOSE

![Node Version](https://img.shields.io/node/v/ts-jose)
[![Version](https://img.shields.io/npm/v/ts-jose)](https://www.npmjs.com/package/ts-jose)
[![codecov](https://codecov.io/gh/evan361425/ts-jose/branch/master/graph/badge.svg)](https://codecov.io/gh/evan361425/ts-jose)
[![License](https://img.shields.io/github/license/evan361425/ts-jose)](LICENSE)

Wrap functions of [JOSE](https://github.com/panva/jose) in steady interface.

> [!Note]
>
> This package's version **will follow the version of JOSE** but should not
> provide any breaking changes.

- [JWT](#jwt)
  - [verify](#verify)
  - [sign](#sign)
  - [decrypt](#decrypt)
  - [encrypt](#encrypt)
- [JWS](#jws)
  - [verify](#verify-1)
  - [sign](#sign-1)
- [JWE](#jwe)
  - [decrypt](#decrypt-1)
  - [encrypt](#encrypt-1)
- [JWK](#jwk)
- [JWKS](#jwks)

## JWT

### verify

[JOSE ref](https://github.com/panva/jose/blob/v6.x/docs/jwt/verify/interfaces/JWTVerifyOptions.md)

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

- [JOSE ref](https://github.com/panva/jose/blob/v6.x/docs/jwt/sign/classes/SignJWT.md)

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

[JOSE ref](https://github.com/panva/jose/blob/v6.x/docs/jwt/decrypt/interfaces/JWTDecryptOptions.md)

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

[JOSE ref](https://github.com/panva/jose/blob/v6.x/docs/jwt/encrypt/classes/EncryptJWT.md)

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

[JOSE ref](https://github.com/panva/jose/blob/v6.x/docs/jws/general/verify/functions/generalVerify.md)

```ts
await JWS.verify(data, key, options);
```

### sign

[JOSE ref](https://github.com/panva/jose/blob/v6.x/docs/jws/general/sign/classes/GeneralSign.md)

Only using below [JWT.sign](#sign)'s options:

- `typ`
- `kid`
- `alg`
- `jwk`

```ts
await JWS.sign('some-data', key, options);
```

## JWE

You can encrypt pure string.

### decrypt

[JOSE ref](https://github.com/panva/jose/blob/v6.x/docs/jwe/general/decrypt/functions/generalDecrypt.md)

Additional options

Same as [JWT.decrypt](#decrypt)

```ts
await JWE.decrypt(cypher, key, options);
```

### encrypt

[JOSE ref](https://github.com/panva/jose/blob/v6.x/docs/jwe/general/encrypt/classes/GeneralEncrypt.md)

Only using below [JWT.encrypt](#encrypt)'s options:

- `kid`
- `alg`
- `enc`

```ts
await JWE.encrypt('some-data', key, options);
```

## JWK

[JOSE ref](https://github.com/panva/jose/blob/v6.x/docs/key/import/functions/importJWK.md)

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
const publicKeys = await keys.toPublic();
```
