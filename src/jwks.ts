import { JoseError } from './error';
import { JWK } from './jwk';
import { JWKAlgorithms, JWKSObject, KeyOptions, KeyUsages } from './types';

export class JWKS {
  constructor(readonly keys: JWK[]) {}

  getKey(options: KeyOptions = {}): JWK {
    if (options.kid !== undefined) {
      const key = this.getKeyByKid(options.kid);

      if (key === undefined) {
        throw new JoseError('Keys', 'kid', options.kid);
      } else if (options.use !== undefined && key.use !== options.use) {
        throw new JoseError('Keys', 'use', key.use, options.use);
      } else if (options.alg !== undefined && key.alg !== undefined) {
        if (key.alg !== options.alg) {
          throw new JoseError('Keys', 'alg', key.alg, options.alg);
        }
      }

      return key;
    }

    const keys1 =
      options.use !== undefined ? this.getKeyByUse(options.use) : this.keys;
    if (keys1.length === 0) throw new JoseError('Keys', 'use', options.use);

    const keys2 =
      options.alg !== undefined ? this.getKeyByAlg(options.alg, keys1) : keys1;
    if (keys2.length === 0) throw new JoseError('Keys', 'alg', options.alg);

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return keys2[0]!;
  }

  getKeyByKid(kid: string): JWK | undefined {
    return this.keys.find((key) => key.kid === kid);
  }

  getKeyByUse(use: KeyUsages, keys?: JWK[]): JWK[] {
    if (keys === undefined) {
      keys = this.keys;
    }
    return keys.filter((key) => key.use === use);
  }

  getKeyByAlg(alg: JWKAlgorithms, keys?: JWK[]): JWK[] {
    if (keys === undefined) {
      keys = this.keys;
    }
    return keys.filter((key) => key.alg === alg);
  }

  toObject(): JWKSObject {
    return { keys: this.keys.map((key) => ({ ...key.metadata })) };
  }

  static async fromObject(jwks: JWKSObject): Promise<JWKS> {
    const keys: JWK[] = [];
    for (const key of jwks.keys) {
      keys.push(await JWK.fromObject(key));
    }

    return new JWKS(keys);
  }
}
