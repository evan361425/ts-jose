import { expect } from 'chai';
import { JWK, JWKey, JWKObject } from '../src';
import { getKey } from './mock-key';

describe('JWK', function () {
  describe('generate()', function () {
    it('no specific usage', async function () {
      const key = await JWK.generate('ES256', { kid: 'some-id' });
      expect(key.alg).to.eq('ES256');
      expect(key.kid).to.eq('some-id');
      expect(key.use).to.be.undefined;
      expect(key.kty).to.eq('EC');
    });

    it('with curve', async function () {
      const key = await JWK.generate('EdDSA', { crv: 'Ed448' });
      expect(key.alg).to.eq('EdDSA');
      expect(key.metadata.crv).to.eq('Ed448');
      expect(key.use).to.be.undefined;
      expect(key.kty).to.eq('OKP');
    });

    it('use encryption', async function () {
      const key = await JWK.generate('RS256', { use: 'enc' });
      expect(key.alg).to.eq('RS256');
      expect(key.kid).to.be.undefined;
      expect(key.use).to.eq('enc');
      expect(key.kty).to.eq('RSA');
    });

    it('use sign', async function () {
      const key = await JWK.generate('A128KW');
      expect(key.alg).to.eq('A128KW');
      expect(key.kty).to.eq('oct');
    });
  });

  describe('fromObject() and #toObject()', function () {
    it('are reversible', async function () {
      const jwk = await getKey();
      const key = jwk.metadata;

      expect(jwk.kid).to.eq('some-id');
      expect(jwk.alg).to.eq('ES256');
      expect(jwk.kty).to.eq('EC');
      expect(jwk.use).to.be.undefined;
      expect(jwk.isPrivate).to.true;
      // private key are identical from original, but not same
      expect(jwk.toObject(true)).not.to.equal(key);
      expect(jwk.toObject(true)).to.eql(key);
      // public key
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { d, ...publicKey } = key;
      expect(jwk.toObject().d).to.be.undefined;
      expect(jwk.toObject()).to.eql(publicKey);
    });
  });

  describe('#toPublic() and #isPrivate', function () {
    it('should get identical from public key', async function () {
      const key: JWKObject = {
        alg: 'EdDSA',
        kty: 'OKP',
        crv: 'Ed448',
        x: 'wab008wlsu54qQt4lQvwMGbUqb8qQOhGiMQTKzuQ1w7HQD2-8gyIQiOf6-6jKZO1gD0usuE1CVYA',
      };

      const jwk = await JWK.fromObject(key);
      expect(await jwk.toPublic()).to.equal(jwk);
    });

    it('should get new key from private key', async function () {
      const key: JWKObject = {
        use: 'enc',
        alg: 'RS256',
        kty: 'RSA',
        n: '2BcZ...',
        e: 'AQAB',
        d: 'CZn9...',
        p: '-ODb...',
        q: '3kYO...',
        dp: 'MH2X...',
        dq: 'RFcZ...',
        qi: 'poQw...',
      };
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { d, p, q, dp, dq, qi, ...publicKey } = key;

      const jwk = await JWK.fromObject(key);
      const publicJWK = await jwk.toPublic();
      expect(publicJWK).not.to.equal(jwk);
      expect(publicJWK.metadata).to.eql(publicKey);
    });

    it('oct key is always private', async function () {
      const key: JWKObject = {
        use: 'sig',
        alg: 'A128KW',
        kty: 'oct',
        k: 'uwGYzlVh_yV9CAOVOpPHrQ',
      };

      const jwk = await JWK.fromObject(key);
      expect(jwk.isPrivate).to.true;
    });
  });

  describe('#getKey()', function () {
    it('should ok if all is correct', function () {
      const jwk = new JWK({} as JWKey, {
        kid: 'some-id',
        use: 'sig',
        alg: 'ES256',
        kty: 'EC',
      });
      expect(jwk.getKey({ kid: 'some-id', alg: 'ES256', use: 'sig' })).be.ok;
    });

    it('should ok if alg or use all undefined', function () {
      const jwk = new JWK({} as JWKey, { kty: 'EC' });
      expect(jwk.getKey({ alg: 'ES256', use: 'sig' })).be.ok;
    });

    it('should ok if kid is same', function () {
      const jwk = new JWK({} as JWKey, {
        kid: 'some-id',
        use: 'sig',
        alg: 'ES256',
        kty: 'EC',
      });
      expect(jwk.getKey({ kid: 'some-id' })).be.ok;
    });

    it('should throw error if kid is different', function () {
      const jwk = new JWK({} as JWKey, {
        use: 'sig',
        alg: 'ES256',
        kty: 'EC',
      });
      expect(() => jwk.getKey({ kid: 'some-id' })).to.throw('kid');
      jwk.metadata.kid = 'some-id';
      expect(() => jwk.getKey({ kid: 'wrong-id' })).to.throw('kid');
    });

    it('should throw error if alg or use is different', function () {
      const jwk = new JWK({} as JWKey, {
        kid: 'some-id',
        use: 'sig',
        alg: 'ES256',
        kty: 'EC',
      });
      expect(() => jwk.getKey({ alg: 'ES384' })).to.throw('alg');
      expect(() => jwk.getKey({ use: 'enc' })).to.throw('use');
    });
  });
});
