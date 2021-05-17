import { JWK } from '../src';

export const getKey = async (): Promise<JWK> => {
  return await JWK.fromObject({
    kid: 'some-id',
    alg: 'ES256',
    kty: 'EC',
    crv: 'P-256',
    x: 'Y238GrLSO5GyAEM-NfgmRqWmqOXAJMKH6P-a2MqrDXU',
    y: 'm0xXso5NdQQpDdHh397OzA7FnxK78wIpkemNV1Ly0Mc',
    d: 'e-dWiLsa4E3oaLtN4h-lmHxkvZJitEiKE3Xk9PqYofk',
  });
};
