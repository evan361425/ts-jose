export function throwError(
  place: string,
  key: string,
  got?: string,
  expected?: string,
): never {
  if (expected === undefined) {
    throw new Error(`${place} found "${key}" is not equal to ${got}`);
  } else {
    throw new Error(`${place} "${key}" is got ${got}, expected ${expected}`);
  }
}
