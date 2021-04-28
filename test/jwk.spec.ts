import { expect } from 'chai';
import CompactSign from 'jose/jws/compact/sign';
import { JWK, JWKey, JWKObject } from '../src';

describe('JWK', () => {
  describe('generate()', () => {
    it('no specific usage', async () => {
      const key = await JWK.generate('ES256', { kid: 'some-id' });
      expect(key.alg).to.eq('ES256');
      expect(key.kid).to.eq('some-id');
      expect(key.use).to.be.undefined;
      expect(key.kty).to.eq('EC');
    });

    it('with curve', async () => {
      const key = await JWK.generate('EdDSA', { crv: 'Ed448' });
      expect(key.alg).to.eq('EdDSA');
      expect(key.metadata.crv).to.eq('Ed448');
      expect(key.use).to.be.undefined;
      expect(key.kty).to.eq('OKP');
    });

    it('use encryption', async () => {
      const key = await JWK.generate('RS256', { use: 'enc' });
      expect(key.alg).to.eq('RS256');
      expect(key.kid).to.be.undefined;
      expect(key.use).to.eq('enc');
      expect(key.kty).to.eq('RSA');
    });

    it('use sign', async () => {
      const key = await JWK.generate('A128KW', { use: 'sig' });
      expect(key.alg).to.eq('A128KW');
      expect(key.use).to.eq('sig');
      expect(key.kty).to.eq('oct');
    });
  });

  describe('fromObject() and #toObject()', () => {
    it('are reversible', async () => {
      const key: JWKObject = {
        kid: 'some-id',
        alg: 'ES256',
        kty: 'EC',
        crv: 'P-256',
        x: 'Y238GrLSO5GyAEM-NfgmRqWmqOXAJMKH6P-a2MqrDXU',
        y: 'm0xXso5NdQQpDdHh397OzA7FnxK78wIpkemNV1Ly0Mc',
        d: 'e-dWiLsa4E3oaLtN4h-lmHxkvZJitEiKE3Xk9PqYofk',
      };

      const jwk = await JWK.fromObject(key);
      expect(jwk.kid).to.eq('some-id');
      expect(jwk.alg).to.eq('ES256');
      expect(jwk.kty).to.eq('EC');
      expect(jwk.use).to.be.undefined;
      expect(jwk.metadata).to.equal(key);
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

  describe('#toPublic() and #isPrivate', () => {
    it('should get identical from public key', async () => {
      const key: JWKObject = {
        alg: 'EdDSA',
        kty: 'OKP',
        crv: 'Ed448',
        x:
          'wab008wlsu54qQt4lQvwMGbUqb8qQOhGiMQTKzuQ1w7HQD2-8gyIQiOf6-6jKZO1gD0usuE1CVYA',
      };

      const jwk = await JWK.fromObject(key);
      expect(await jwk.toPublic()).to.equal(jwk);
    });

    it('should get new key from private key', async () => {
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

    it('oct key is always private', async () => {
      const key: JWKObject = {
        use: 'sig',
        alg: 'A128KW',
        kty: 'oct',
        k: 'uwGYzlVh_yV9CAOVOpPHrQ',
      };

      const jwk = await JWK.fromObject(key);
      expect(jwk.isPrivate).to.true;
    });

    it('private key is signable', async () => {
      const key: JWKObject = {
        kid: 'some-id',
        alg: 'ES256',
        kty: 'EC',
        crv: 'P-256',
        x: 'Y238GrLSO5GyAEM-NfgmRqWmqOXAJMKH6P-a2MqrDXU',
        y: 'm0xXso5NdQQpDdHh397OzA7FnxK78wIpkemNV1Ly0Mc',
        d: 'e-dWiLsa4E3oaLtN4h-lmHxkvZJitEiKE3Xk9PqYofk',
      };

      const jwk = await JWK.fromObject(key);
      const data = 'some text';
      const encoder = new TextEncoder();
      const jws = new CompactSign(encoder.encode(data));
      jws.setProtectedHeader({ alg: 'ES256' });

      expect(jwk.isPrivate).to.true;
      expect(await jws.sign(jwk.key)).be.ok;
    });
  });

  describe('#getKey()', () => {
    it('should ok if all is correct', () => {
      const jwk = new JWK({} as JWKey, {
        kid: 'some-id',
        use: 'sig',
        alg: 'ES256',
        kty: 'EC',
      });
      expect(jwk.getKey({ kid: 'some-id', alg: 'ES256', use: 'sig' })).be.ok;
    });

    it('should ok if alg or use all undefined', () => {
      const jwk = new JWK({} as JWKey, { kty: 'EC' });
      expect(jwk.getKey({ alg: 'ES256', use: 'sig' })).be.ok;
    });

    it('should ok if alg or use all undefined', () => {
      const jwk = new JWK({} as JWKey, {
        kid: 'some-id',
        use: 'sig',
        alg: 'ES256',
        kty: 'EC',
      });
      expect(jwk.getKey({ kid: 'some-id' })).be.ok;
    });

    it('should throw error if kid is different', () => {
      const jwk = new JWK({} as JWKey, {
        use: 'sig',
        alg: 'ES256',
        kty: 'EC',
      });
      expect(() => jwk.getKey({ kid: 'some-id' })).to.throw('kid');
      jwk.metadata.kid = 'some-id';
      expect(() => jwk.getKey({ kid: 'wrong-id' })).to.throw('kid');
    });

    it('should throw error if alg or use is different', () => {
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
