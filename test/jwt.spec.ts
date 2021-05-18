import { expect } from 'chai';
import { SinonStub, stub } from 'sinon';
import { JWK, JWS, JWT } from '../src';
import { getKey } from './mock-key';

describe.only('JWT', function () {
  describe('#verify', function () {
    it('should get complete result', async function () {
      const token = await JWS.sign('{"iss":"some-issuer"}', key, {
        typ: 'JWT',
      });
      // Action
      const result = await JWT.verify(token, key, { complete: true });
      // Assertion
      expect(result.payload.iss).to.eq('some-issuer');
      expect(result.header.typ).to.eq('JWT');
    });

    it('should get payload', async function () {
      const token = await JWS.sign('{"iss":"some-issuer"}', key, {
        typ: 'JWT',
      });
      // Action
      const result = await JWT.verify(token, key);
      // Assertion
      expect(result.iss).to.eq('some-issuer');
    });

    let stubJWS: SinonStub;
    let stubJWT: SinonStub;
    let key: JWK;

    before(async function () {
      key = await getKey();
      stubJWS = stub(JWS, 'getKeyFrom');
      stubJWT = stub(JWT, 'verifyJWTClaims');
      stubJWS.resolves(key.key);
    });

    after(function () {
      stubJWS.restore();
      stubJWT.restore();
    });
  });

  describe('#sign', function () {
    it('should get default header and payload', async function () {
      const payload = { a: 'b' };
      // Action
      const result = await JWT.sign(payload, key);
      // Assertion
      const splits = result.split('.');
      const headerRaw = Buffer.from(splits[0], 'base64').toString('ascii');
      const payloadRaw = Buffer.from(splits[1], 'base64').toString('ascii');
      const tokenHeader = JSON.parse(headerRaw);
      const tokenPayload = JSON.parse(payloadRaw);

      expect(tokenPayload.a).to.eq('b');
      expect(tokenHeader.typ).to.eq('jwt');
      expect(tokenHeader.kid).to.eq('some-id');
      expect(tokenHeader.alg).to.eq('ES256');
    });

    it('should get config header and payload', async function () {
      const payload = { a: 'b' };
      const now = Math.floor(new Date().getTime() / 1000);
      // Action
      const result = await JWT.sign(payload, key, {
        alg: 'ES256', // alg must stay same as key
        audience: ['hi', 'there'],
        exp: now + 300,
        iat: now,
        issuer: 'some-issuer',
        jti: 'some-token-id',
        kid: 'some-id', // kid must stay same as key
        notBefore: now + 100,
        subject: 'some-user-id',
        typ: 'custom+jwt',
      });
      // Assertion
      const splits = result.split('.');
      const headerRaw = Buffer.from(splits[0], 'base64').toString('ascii');
      const payloadRaw = Buffer.from(splits[1], 'base64').toString('ascii');
      const tokenHeader = JSON.parse(headerRaw);
      const tokenPayload = JSON.parse(payloadRaw);

      expect(tokenPayload.a).to.eq('b');
      expect(tokenPayload.aud).to.have.lengthOf(2);
      expect(tokenPayload.aud).contains('hi');
      expect(tokenPayload.exp).to.eq(now + 300);
      expect(tokenPayload.iat).to.eq(now);
      expect(tokenPayload.iss).to.eq('some-issuer');
      expect(tokenPayload.jti).to.eq('some-token-id');
      expect(tokenPayload.nbf).to.eq(now + 100);
      expect(tokenPayload.sub).to.eq('some-user-id');
      expect(tokenHeader.typ).to.eq('custom+jwt');
    });

    let key: JWK;

    before(async function () {
      key = await getKey();
    });
  });

  describe('#decrypt', function () {
    return null;
  });

  describe('#encrypt', function () {
    return null;
  });

  describe('#setupJwt', function () {
    return null;
  });

  describe('#verifyJWTClaims', function () {
    return null;
  });
});
