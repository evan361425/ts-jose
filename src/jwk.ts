import { fromKeyLike } from 'jose/jwk/from_key_like';
import { parseJwk } from 'jose/jwk/parse';
import generateKeyPair from 'jose/util/generate_key_pair';
import generateSecret from 'jose/util/generate_secret';
import { JoseError } from './error';
import {
  JWKAlgorithms,
  JWKey,
  JWKGenerateOptions,
  JWKObject,
  KeyOptions,
  KeyTypes,
  KeyUsages,
} from './types';

const RSAPrivateProperties = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'];

export class JWK {
  readonly metadata: JWKObject;
  constructor(readonly key: JWKey, metadata: JWKObject) {
    this.metadata = deleteUndefined(metadata);
  }

  get kid(): string | undefined {
    return this.metadata.kid;
  }
  get alg(): JWKAlgorithms | undefined {
    return this.metadata.alg;
  }
  get use(): KeyUsages | undefined {
    return this.metadata.use;
  }
  get kty(): KeyTypes {
    return this.metadata.kty;
  }

  // https://tools.ietf.org/id/draft-jones-jose-json-private-and-symmetric-key-00.html#rfc.section.3.2.7
  get isPrivate(): boolean {
    switch (this.kty) {
      case 'oct':
        return true;
      case 'EC':
      case 'OKP':
        return this.metadata.d !== undefined;
      case 'RSA':
        return Object.entries(this.metadata)
          .filter((entry) => RSAPrivateProperties.includes(entry[0]))
          .some((entry) => entry[1] !== undefined);
    }
  }

  getKey(options: KeyOptions): JWK {
    if (options.kid !== undefined && options.kid !== this.kid) {
      throw new JoseError('Key', 'kid', options.kid, this.kid);
    }

    if (options.use !== undefined && this.use !== undefined) {
      if (options.use !== this.use) {
        throw new JoseError('Key', 'use', options.use, this.use);
      }
    }

    if (options.alg !== undefined && this.alg !== undefined) {
      if (options.alg !== this.alg) {
        throw new JoseError('Key', 'alg', options.alg, this.alg);
      }
    }

    return this;
  }

  async toPublic(): Promise<JWK> {
    if (!this.isPrivate) return this;

    return JWK.fromObject(this.toObject());
  }

  toObject(asPrivate = false): JWKObject {
    if (this.isPrivate && !asPrivate) {
      const { kid, alg, use, kty, crv, x, y, e, n } = this.metadata;

      return deleteUndefined({ kid, alg, use, kty, crv, x, y, e, n });
    }

    // return new object
    const { ...key } = this.metadata;

    return key;
  }

  static async fromObject(keyObject: JWKObject): Promise<JWK> {
    const key = await parseJwk(keyObject);
    return new JWK(key, keyObject);
  }

  static async generate(
    algorithm: JWKAlgorithms,
    options?: JWKGenerateOptions,
  ): Promise<JWK> {
    const key = await getKey();
    const metadata = (await fromKeyLike(key)) as JWKObject;

    return new JWK(key, {
      kid: options?.kid,
      use: options?.use,
      alg: algorithm,
      ...metadata,
    });

    async function getKey(): Promise<JWKey> {
      if (algorithm.startsWith('HS') || algorithm.startsWith('A')) {
        return generateSecret(algorithm);
      }
      const keyPair = await generateKeyPair(algorithm, options);
      return keyPair.privateKey;
    }
  }
}

function deleteUndefined<T>(data: T): T {
  Object.entries(data).forEach((entry) => {
    if (entry[1] === undefined) {
      delete data[entry[0] as keyof T];
    }
  });
  return data;
}
