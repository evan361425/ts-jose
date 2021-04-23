export function throwError(
  place: string,
  key: string,
  got?: string,
  expected?: string,
): any {
  if (expected === undefined) {
    throw new Error(`${place} not found "${key}" as ${got}`);
  } else {
    throw new Error(`${place} "${key}" is got ${got}, expected ${expected}`);
  }
}
