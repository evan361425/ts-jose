export class JoseError extends Error {
  constructor(place: string, key: string, got?: string, expected?: string) {
    const message =
      expected === undefined
        ? `${place} found "${key}" is not equal to ${got ?? 'unknown'}`
        : `${place} "${key}" is got ${got ?? 'unknown'}, expected ${expected}`;

    super(message);
  }
}
