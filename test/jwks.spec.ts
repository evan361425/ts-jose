import { expect } from 'chai';
import { stub } from 'sinon';
import { JWK, JWKObject, JWKS } from '../src/index.js';

describe('JWKS', function () {
  describe('#getKey()', function () {
    it('should get first key if no options given', function () {
      const jwks = new JWKS([{ kid: 'k1' } as JWK, { kid: 'k2' } as JWK]);
      const result = jwks.getKey();

      expect(result.kid).is.eq('k1');
    });

    describe('kid', function () {
      it('should get key in specific "kid"', function () {
        const jwks = new JWKS([]);
        stub(jwks, 'getKeyByKid').returns({} as JWK);

        expect(jwks.getKey({ kid: 'k1' })).is.ok;
      });

      it('should throw error if not found key in "kid"', function () {
        const jwks = new JWKS([]);
        stub(jwks, 'getKeyByKid').returns(undefined);

        expect(() => jwks.getKey({ kid: 'some-id' })).to.throw('kid');
      });

      it('should throw error if found key in "kid" has wrong "use"', function () {
        const jwks = new JWKS([]);
        stub(jwks, 'getKeyByKid').returns({ use: 'sig' } as JWK);

        expect(() => jwks.getKey({ kid: 'some-id', use: 'enc' })).to.throw(
          'use',
        );
      });

      it('should ok if found key in "kid" has no "alg"', function () {
        const jwks = new JWKS([]);
        stub(jwks, 'getKeyByKid').returns({} as JWK);

        expect(jwks.getKey({ kid: 'id', alg: 'ES384' })).be.ok;
      });

      it('should throw error if found key in "kid" has wrong "alg"', function () {
        const jwks = new JWKS([]);
        stub(jwks, 'getKeyByKid').returns({ alg: 'ES256' } as JWK);

        expect(() => jwks.getKey({ kid: 'id', alg: 'ES384' })).to.throw('alg');
      });

      it('should pass if found key in "kid" has correct "alg"', function () {
        const jwks = new JWKS([]);
        stub(jwks, 'getKeyByKid').returns({ alg: 'ES256' } as JWK);

        expect(() => jwks.getKey({ kid: 'id', alg: 'ES256' })).not.to.throw();
      });
    });

    it('should throw error if not found in "use"', function () {
      const jwks = new JWKS([]);
      stub(jwks, 'getKeyByUse').returns([]);

      expect(() => jwks.getKey({ use: 'sig' })).be.throw('use');
    });

    it('should throw error if not found in "alg"', function () {
      const jwks = new JWKS([{} as JWK]);
      stub(jwks, 'getKeyByAlg').returns([]);

      expect(() => jwks.getKey({ alg: 'ES256' })).be.throw('alg');
    });
  });

  describe('#getKeyByKid()', function () {
    it('should get undefined if kid not found', function () {
      const candidates = [{ kid: 'some-id' } as JWK];
      const jwks = new JWKS(candidates);

      const result = jwks.getKeyByKid('wrong-id');
      expect(result).be.undefined;
    });

    it('should get first key even two same kid', function () {
      const candidates = [
        { kid: 'some-id', alg: 'ES256' } as JWK,
        { kid: 'some-id', alg: 'ES384' } as JWK,
      ];
      const jwks = new JWKS(candidates);

      const result = jwks.getKeyByKid('some-id');
      expect(result?.alg).to.eq('ES256');
    });
  });

  describe('#getKeyByUse()', function () {
    it('should get empty keys if "use" not found', function () {
      const candidates = [{ use: 'enc' } as JWK];
      const jwks = new JWKS(candidates);

      const result = jwks.getKeyByUse('sig');
      expect(result).to.be.empty;
    });

    it('should get all keys in matched', function () {
      const candidates = [
        { use: 'enc', kid: 'k1' } as JWK,
        { use: 'sig', kid: 'k2' } as JWK,
        { use: 'enc', kid: 'k3' } as JWK,
      ];
      const jwks = new JWKS(candidates);

      const result = jwks.getKeyByUse('enc');
      expect(result.length).to.eq(2);
      expect(result[0]!.kid).to.eq('k1');
      expect(result[1]!.kid).to.eq('k3');
    });

    it('should get all keys in matched by passing keys', function () {
      const candidates = [
        { use: 'enc', kid: 'k1' } as JWK,
        { use: 'sig', kid: 'k2' } as JWK,
        { use: 'enc', kid: 'k3' } as JWK,
      ];
      const jwks = new JWKS([]);

      const result = jwks.getKeyByUse('enc', candidates);
      expect(result.length).to.eq(2);
      expect(result[0]!.kid).to.eq('k1');
      expect(result[1]!.kid).to.eq('k3');
    });
  });

  describe('#getKeyByAlg()', function () {
    it('should get empty keys if "alg" not found', function () {
      const candidates = [{ alg: 'ES256' } as JWK];
      const jwks = new JWKS(candidates);

      const result = jwks.getKeyByAlg('ES384');
      expect(result).to.be.empty;
    });

    it('should get all keys in matched', function () {
      const candidates = [
        { alg: 'ES256', kid: 'k1' } as JWK,
        { alg: 'ES384', kid: 'k2' } as JWK,
        { alg: 'ES256', kid: 'k3' } as JWK,
      ];
      const jwks = new JWKS(candidates);

      const result = jwks.getKeyByAlg('ES256');
      expect(result.length).to.eq(2);
      expect(result[0]!.kid).to.eq('k1');
      expect(result[1]!.kid).to.eq('k3');
    });

    it('should get all keys in matched by passing keys', function () {
      const candidates = [
        { alg: 'ES256', kid: 'k1' } as JWK,
        { alg: 'ES384', kid: 'k2' } as JWK,
        { alg: 'ES256', kid: 'k3' } as JWK,
      ];
      const jwks = new JWKS([]);

      const result = jwks.getKeyByAlg('ES256', candidates);
      expect(result.length).to.eq(2);
      expect(result[0]!.kid).to.eq('k1');
      expect(result[1]!.kid).to.eq('k3');
    });
  });

  describe('#toObject()', function () {
    it('should same with input', function () {
      const keyMetadata = { a: 'b' };
      const key: JWK = { metadata: keyMetadata as unknown } as never;
      const keys = new JWKS([key]);
      expect(keys.toObject()).to.eql({ keys: [keyMetadata] });
      // should be new object
      expect(keys.toObject().keys[0]).to.not.equal(keyMetadata);
    });
  });

  describe('fromObject()', function () {
    it('should get empty keys if input is empty', async function () {
      const jwks = await JWKS.fromObject({ keys: [] });
      expect(jwks.keys).is.empty;
    });

    it('should get correct keys', async function () {
      const stubJWK = stub(JWK, 'fromObject');
      stubJWK.callsFake((key) => {
        return Promise.resolve({
          kid: key.kid,
        } as JWK);
      });

      const jwks = await JWKS.fromObject({
        keys: [
          { kid: 'k1' } as JWKObject,
          { kid: 'k2' } as JWKObject,
          { kid: 'k3' } as JWKObject,
        ],
      });

      expect(jwks.keys.length).is.eq(3);
      expect(jwks.keys[0]!.kid).is.eq('k1');
      expect(jwks.keys[1]!.kid).is.eq('k2');
      expect(jwks.keys[2]!.kid).is.eq('k3');

      stubJWK.restore();
    });
  });

  it('should get public keys', async function () {
    const props: JWKObject = {
      alg: 'EdDSA',
      kty: 'OKP',
      crv: 'Ed25519',
      x: 'yy-w_l9460d_O-KsBR1Ln2zH7UAH723aCZen5GJb8aA',
    };
    const key1 = await JWK.fromObject({ kid: 'k1', ...props });
    const key2 = await JWK.fromObject({ kid: 'k2', ...props });

    const jwks = new JWKS([key1, key2]);
    const result = await jwks.toPublic();

    expect(result.keys.length).is.eq(2);
    expect(result.keys[0]!.kid).is.eq('k1');
    expect(result.keys[0]!.isPrivate).is.false;
    expect(result.keys[1]!.kid).is.eq('k2');
    expect(result.keys[1]!.isPrivate).is.false;
  });
});
