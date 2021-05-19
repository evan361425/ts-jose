import { expect } from 'chai';
import { SinonStub, stub } from 'sinon';
import { JWE, JWK, JWS, JWT } from '../src';
import { getKey } from './mock-key';

describe('JWT', function () {
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

    it('embeded key', async function () {
      const token = await JWT.sign({ a: 'b' }, key, { jwk: true });
      const result = await JWT.verify(token, undefined, { complete: true });
      // Assertion
      expect(result.header.jwk).to.be.ok;
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
    it('should decrypt without config', async function () {
      const token = await JWE.encrypt('{"iss":"some-issuer"}', key, {
        alg: 'ECDH-ES+A128KW',
        enc: 'A128GCM',
      });
      // Action
      const result = await JWT.decrypt(token, key);
      // Assertion
      expect(result.iss).to.eq('some-issuer');
    });

    it('should decrypt with specific config', async function () {
      const nowD = new Date();
      const now = Math.floor(nowD.getTime() / 1000);
      const payload = {
        iss: 'some-issuer',
        jit: 'some-token-id',
        sub: 'some-user-id',
        aud: ['hi', 'there'],
        exp: now + 300,
        iat: now + 1, // check clock tolerance
      };
      const token = await JWE.encrypt(JSON.stringify(payload), key, {
        alg: 'ECDH-ES+A128KW',
        enc: 'A128GCM',
      });
      // Action
      const result = await JWT.decrypt(token, key, {
        audience: 'hi',
        enc: ['A128GCM'],
        alg: ['ECDH-ES+A128KW'],
        clockTolerance: '3s',
        currentDate: nowD,
        issuer: 'some-issuer',
        jti: 'some-token-id',
        maxTokenAge: '5m',
        subject: 'some-user-id',
        complete: true,
      });
      // Assertion
      expect(result.header.epk).to.be.ok;
      expect(result.header.enc).to.eq('A128GCM');
      expect(result.header.alg).to.eq('ECDH-ES+A128KW');
      expect(result.payload).to.be.ok;
    });

    let stubJWT: SinonStub;
    let key: JWK;

    before(async function () {
      key = await getKey();
      stubJWT = stub(JWT, 'verifyJWTClaims');
    });

    after(function () {
      stubJWT.restore();
    });
  });

  describe('#encrypt', function () {
    it('should get default header and payload', async function () {
      // Action
      const cypher = await JWT.encrypt({ a: 'b' }, key, {
        alg: 'ECDH-ES+A128KW',
        enc: 'A128GCM',
      });
      // Assertion
      const result = await JWT.decrypt(cypher, key, { complete: true });
      const header = result.header;
      const payload = result.payload;

      expect(payload.a).to.eq('b');
      expect(header.typ).to.eq('jwt');
      expect(header.kid).to.eq('some-id');
      expect(header.alg).to.eq('ECDH-ES+A128KW');
      expect(header.enc).to.eq('A128GCM');
    });

    it('should get config header and payload', async function () {
      const now = Math.floor(Date.now() / 1000);
      // Action
      const cypher = await JWT.encrypt({ a: 'b' }, key, {
        alg: 'ECDH-ES+A128KW',
        enc: 'A128GCM',
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
      const result = await JWT.decrypt(cypher, key, {
        complete: true,
        enc: 'A128GCM', // fulfill coverage
        alg: 'ECDH-ES+A128KW', // fulfill coverage
        currentDate: new Date((now + 150) * 1000), // pass nbf
      });
      const header = result.header;
      const payload = result.payload;

      expect(payload.a).to.eq('b');
      expect(payload.aud).to.have.lengthOf(2);
      expect(payload.aud).contains('hi');
      expect(payload.exp).to.eq(now + 300);
      expect(payload.iat).to.eq(now);
      expect(payload.iss).to.eq('some-issuer');
      expect(payload.jti).to.eq('some-token-id');
      expect(payload.nbf).to.eq(now + 100);
      expect(payload.sub).to.eq('some-user-id');
      expect(header.typ).to.eq('custom+jwt');
    });

    let key: JWK;

    before(async function () {
      key = await getKey();
    });
  });

  describe('#verifyJWTClaims', function () {
    it('should throw error if wrong header', function () {
      const act = () => JWT.verifyJWTClaims({}, { typ: 'jwt' }, { typ: 'JWT' });
      expect(act).throw('JWT');
    });

    it('should throw error if wrong payload', function () {
      const act = () => JWT.verifyJWTClaims({ jti: 'hi' }, {}, { jti: 'ho' });
      expect(act).throw('ho');
    });

    it('should do nothing without option', function () {
      const act = () => JWT.verifyJWTClaims({ jti: 'hi' }, {});
      expect(act).not.throw();
    });
  });
});
