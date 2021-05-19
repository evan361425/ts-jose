# TS JOSE

![CI](https://github.com/evan361425/ts-jose/actions/workflows/CI.yml/badge.svg)
[![codecov](https://codecov.io/gh/evan361425/ts-jose/branch/master/graph/badge.svg)](https://codecov.io/gh/evan361425/ts-jose)
![Quality](https://img.shields.io/codefactor/grade/github/evan361425/ts-jose)

Wrap functions of [JOSE](https://github.com/panva/jose) in steady interface.

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

[ref](https://github.com/panva/jose/blob/main/docs/interfaces/jwt_verify.jwtverifyoptions.md)

<details>
<summary>Example code</summary>

```ts
const options = {
  algorithms: ['a1', 'a2'], // accepted algorithms
  audience: 'hi', // string or string[], accept audience
  clockTolerance: '3s',
  complete: true, // true to return header+payload else return payload only, default: false
  crit: { 'some-key': true },
  currentDate: new Date(),
  issuer: 'some-issuer', // issuer, who made this token
  jti: 'some-token-id', // token id, often be random
  maxTokenAge: '5m', // expiration
  subject: 'some-user-id', // what this token represent, often be user ID
  typ: 'ac+jwt', // make it easy to decide what token is this
};

await JWT.verify(token, key, options); // key must be JWK or JWKS
await JWT.verify(token, undefined, options); // this will try to verify by embedded key
```

</details>

### sign

[ref](https://github.com/panva/jose/blob/main/docs/classes/jwt_sign.signjwt.md)

<details>
<summary>Example code</summary>

```ts
const options = {
  alg: 'ES256',
  audience: 'hi', // string or string[]
  exp: '3h', // string or number, 3h means expired in 3 hours, detail in [ref]
  iat: 123,
  issuer: 'some-issuer', // issuer, who made this token
  jti: 'some-token-id', // token id, often be random
  jwk: true, // true to embedded key, default: false
  kid: 'some-key-id', // often use to specify key in key store
  notBefore: '1s', // string or number, invalid if earlier than this time
  subject: 'some-user-id', // what this token represent, often be user ID
  typ: 'ac+jwt', // make it easy to decide what token is this
};

await JWT.sign(payload, key, options); // key must be JWK or JWKS
```

</details>

### decrypt

[ref](https://github.com/panva/jose/blob/main/docs/functions/jwe_compact_decrypt.compactdecrypt.md#readme)

<details>
<summary>Example code</summary>

```ts
const options = {
  audience: 'hi', // string or string[]
  clockTolerance: '3s',
  complete: true, // true to return header+payload else return payload only, default: false
  enc: ['A128GCM'], // string or string[], content encryption algorithms
  crit: { 'some-key': true },
  currentDate: new Date(),
  issuer: 'some-issuer',
  jti: 'some-token-id',
  alg: ['ECDH-ES+A128KW'], // string or string[], key management algorithms
  kid: 'some-key-id',
  maxTokenAge: '5m',
  typ: 'ac+jwt', // make it easy to decide what token is this
};

await JWT.decrypt(cypher, key, options);
```

</details>

### encrypt

[ref](https://github.com/panva/jose/blob/main/docs/classes/jwt_encrypt.encryptjwt.md#readme)

<details>
<summary>Example code</summary>

```ts
const options = {
  alg: 'A128GCMKW', // key management
  audience: 'hi', // string or string[], accepted audience
  crit: { 'some-key': true },
  enc: 'A128CBC-HS256', // encrypt algorithm
  exp: '3h', // string or number
  iat: 123,
  issuer: 'some-issuer',
  jti: 'some-token-id',
  kid: 'some-key-id',
  notBefore: '1s',
};

await JWT.encrypt(payload, key, options);
```

</details>

## JWS

You can sign pure string.

### verify

[ref](https://github.com/panva/jose/blob/main/docs/functions/jws_compact_verify.compactverify.md#readme)

<details>
<summary>Example code</summary>

```ts
const options = {
  algorithms: ['ES256', 'ES192'],
  crit: { key: true },
  typ: 'some-type',
};

await JWS.verify(data, key, options);
```

</details>

### sign

[ref](https://github.com/panva/jose/blob/main/docs/classes/jws_compact_sign.compactsign.md#readme)

<details>
<summary>Example code</summary>

```ts
const options = {
  alg: 'ES256',
  kid: 'some-key-id',
  jwk: true, // embedded key
  typ: 'some-type',
};

await JWS.sign('some-data', key, options);
```

</details>

## JWE

You can encrypt pure string.

### decrypt

[ref](https://github.com/panva/jose/blob/main/docs/functions/jwe_compact_decrypt.compactdecrypt.md#readme)

<details>
<summary>Example code</summary>

```ts
const options = {
  alg: 'ECDH-ES+A128KW', // string or string[]
  enc: ['A128GCM'], // string or string[]
  kid: 'some-key-id',
};

await JWE.decrypt(cypher, key, options);
```

</details>

### encrypt

[ref](https://github.com/panva/jose/blob/main/docs/classes/jwe_compact_encrypt.compactencrypt.md#readme)

<details>
<summary>Example code</summary>

```ts
const options = {
  alg: 'ECDH-ES+A128KW', // string
  enc: 'A128GCM', // string
  crit: { 'some-key': true },
  kid: 'some-key-id',
};

await JWE.encrypt(cypher, key, options);
```

</details>

## JWK

[ref](https://github.com/panva/jose/blob/main/docs/interfaces/types.jwk.md)

<details>
<summary>Example code</summary>

```ts
// generate key
await JWK.generate('ES256', {
  kid: 'some-id',
  use: 'sig',
  // crv: string, some algorithms need to add curve - EdDSA
  // modulusLength: number, some algorithms need to add length - RSA
});

// object to JWK
await JWK.fromObject({
  kid: 'some-id',
  alg: 'ES256',
  kty: 'EC',
  crv: 'P-256',
  x: '123',
  y: '456',
  d: '789',
});

// JWK to object
key.toObject(false); // true to output private object, default: false

// private JWK to public JWK
await key.toPublic();

// get key's status
key.isisPrivate;

// check key "id", "use", "alg"
try {
  key.getKey({
    kid: 'some-id',
    use: 'sig',
    alg: 'ES256',
  });
} catch (err) {
  // throw error if this key has different metadata from options
}
```

</details>

## JWKS

<details>
<summary>Example code</summary>

```ts
// object to JWKS
const keys = await JWKS.fromObject('ES256', {
  keys: [
    {
      alg: 'ES256',
      kty: 'EC',
      x: '123',
      y: '456',
    },
  ],
});

keys.getKey({ kid: 'some-id', use: 'sig', alg: 'ES256' });
keys.getKeyByKid('some-id');
keys.getKeyByUse('sig');
keys.getKeyByAlg('ES256');
```

</details>
