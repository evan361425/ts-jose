import { expect } from 'chai';
import { decodeProtectedHeader } from 'jose';
import { JWK, JWKS, JWS } from '../src/index.js';
import { getKey } from './mock-key.js';

describe('JWS', function () {
  describe('#verify()', function () {
    it('should ok', async function () {
      const payload = await JWS.verify(token, publicKey);
      expect(payload.toString()).is.eq('some-data');
    });

    it('should select key from JWKS by kid', async function () {
      const keys = new JWKS([publicKey]);
      const result = await JWS.verify(token, keys, {
        kid: 'some-id',
        complete: true,
      });
      expect(result.header.kid).is.eq('some-id');
    });

    it('should throw error if algorithms is not correct', async function () {
      return JWS.verify(token, publicKey, { algorithms: ['ES384'] })
        .then(() => expect.fail('should not pass if "typ" is wrong'))
        .catch((reason) => expect((reason as Error).message).is.contain('alg'));
    });

    it('should throw error if typ is wrong', async function () {
      return JWS.verify(token, publicKey, { typ: 'OKP' })
        .then(() => expect.fail('should not pass if "typ" is wrong'))
        .catch((reason) => expect((reason as Error).message).is.contain('typ'));
    });

    let token: string;
    let publicKey: JWK;

    before(async function () {
      const key = await getKey('sig');
      publicKey = await key.toPublic();
      // sign!
      token = await JWS.sign('some-data', key, { typ: 'EC' });
    });
  });

  describe('#sign()', function () {
    it('should throw error in wrong "kid"', async function () {
      return JWS.sign('some-data', key, { kid: 'second-id' })
        .then(() => expect.fail('should not pass if "kid" is wrong'))
        .catch((reason) => expect((reason as Error).message).is.contain('kid'));
    });

    it('should throw error in wrong "alg"', async function () {
      return JWS.sign('some-data', key, { alg: 'ES384' })
        .then(() => expect.fail('should not pass if "alg" is wrong'))
        .catch((reason) => expect((reason as Error).message).is.contain('alg'));
    });

    it('should throw error if missing "alg"', async function () {
      const withoutAlgKey = await getKey('sig');
      withoutAlgKey.metadata.alg = undefined;

      return JWS.sign('some-data', withoutAlgKey)
        .then(() => expect.fail('should not pass if "alg" is wrong'))
        .catch((reason) => expect((reason as Error).message).is.contain('alg'));
    });

    it('should use key metadata if option not set', async function () {
      const signature = await JWS.sign('some-data', key);
      const header = decodeProtectedHeader(signature);
      expect(header.alg).is.eq('ES256');
      expect(header.kid).is.eq('some-id');
    });

    it('should use option metadata', async function () {
      key.metadata.kid = 'second-id';
      const signature = await JWS.sign('some-data', key, {
        kid: 'second-id',
        alg: 'ES256',
        typ: 'EC',
      });
      const header = decodeProtectedHeader(signature);
      expect(header.alg).is.eq('ES256');
      expect(header.kid).is.eq('second-id');
      expect(header.typ).is.eq('EC');
      key.metadata.kid = 'some-id';
    });

    let key: JWK;

    before(async function () {
      key = await getKey('sig');
    });
  });

  describe('Embedded Key', function () {
    it('should sign with embedded key', async function () {
      const key = await getKey('sig');
      const token = await JWS.sign('some-data', key, { jwk: true });
      const result = await JWS.verify(token, undefined, { complete: true });
      expect(result.header.kid).is.eq('some-id');
      expect(result.key).is.not.undefined;
      expect(result.payload).is.eq('some-data');
    });
  });
});
