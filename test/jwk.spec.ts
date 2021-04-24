import { expect } from 'chai';
import { JWK } from '../src';

describe('JWK', () => {
  describe('Generate Key', () => {
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

    it('encryption', async () => {
      const key = await JWK.generate('RS256', { use: 'enc' });
      expect(key.alg).to.eq('RS256');
      expect(key.kid).to.be.undefined;
      expect(key.use).to.eq('enc');
      expect(key.kty).to.eq('RSA');
    });

    it('sign', async () => {
      const key = await JWK.generate('A128KW', { use: 'sig' });
      expect(key.alg).to.eq('A128KW');
      expect(key.use).to.eq('sig');
      expect(key.kty).to.eq('oct');
    });
  });
});
