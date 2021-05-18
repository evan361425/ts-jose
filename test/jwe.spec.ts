import { expect } from 'chai';
import decodeProtectedHeader from 'jose/util/decode_protected_header';
import { JWE, JWK, JWS } from '../src';
import { getKey } from './mock-key';

describe('JWE', function () {
  describe('#verify()', function () {
    it('should ok', async function () {
      const payload = await JWE.decrypt(token, key);
      expect(payload).is.eq('some-data');
    });

    it('should throw error if enc is not correct', async function () {
      return JWE.decrypt(token, key, { enc: 'A256GCM' })
        .then((_) => expect.fail('should not pass if "enc" is wrong'))
        .catch((reason) => expect(reason.message).is.contain('enc'));
    });

    it('should throw error if typ is wrong', async function () {
      return JWE.decrypt(token, key, { alg: 'ECDH-ES+A256KW' })
        .then((_) => expect.fail('should not pass if "alg" is wrong'))
        .catch((reason) => expect(reason.message).is.contain('alg'));
    });

    let token: string;

    before(async function () {
      token = await JWE.encrypt('some-data', key, {
        alg: 'ECDH-ES+A128KW',
        enc: 'A128GCM',
      });
    });
  });

  describe('#encrypt()', function () {
    it('should throw error in wrong "kid"', async function () {
      try {
        await JWE.encrypt('some-data', key, {
          kid: 'second-id',
          alg: 'ECDH-ES+A128KW',
          enc: 'A128GCM',
        });
        expect.fail('should not pass if "kid" is wrong');
      } catch (error) {
        expect(error.message).is.contain('kid');
      }
    });

    it('should use key metadata if option not set', async function () {
      const signature = await JWE.encrypt('some-data', key, {
        alg: 'ECDH-ES+A128KW',
        enc: 'A128GCM',
      });
      const header = decodeProtectedHeader(signature);
      expect(header.alg).is.eq('ECDH-ES+A128KW');
      expect(header.enc).is.eq('A128GCM');
      expect(header.kid).is.eq('some-id');
    });

    it('should use option metadata', async function () {
      key.metadata.kid = 'second-id';
      const signature = await JWE.encrypt('some-data', key, {
        kid: 'second-id',
        alg: 'ECDH-ES+A128KW',
        enc: 'A128GCM',
      });
      const header = decodeProtectedHeader(signature);
      expect(header.kid).is.eq('second-id');
      key.metadata.kid = 'some-id';
    });
  });

  describe('Embedded Key', function () {
    it('should sign with embedded key', async function () {
      const token = await JWS.sign('some-data', key, { jwk: true });
      const data = await JWS.verify(token);
      expect(data).is.eq('some-data');
    });
  });

  let key: JWK;

  before(async function () {
    key = await getKey();
  });
});
