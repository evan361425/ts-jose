export class JoseError extends Error {
  constructor(place: string, key: string, got?: string, expected?: string) {
    const message =
      expected === undefined
        ? // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
          `${place} found "${key}" is not equal to ${got}`
        : // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
          `${place} "${key}" is got ${got}, expected ${expected}`;

    super(message);
  }
}
