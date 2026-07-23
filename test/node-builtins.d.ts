/**
 * Minimal ambient declarations for the two Node builtins the suite uses.
 *
 * @types/node is not a dependency of this package on purpose. src/ must run
 * unchanged in a browser, and pulling the whole Node global surface into the
 * compiler makes it far too easy for someone to reach for `Buffer` or
 * `node:crypto` in the core and not find out until runtime. Declaring only
 * what the tests actually call keeps that guardrail intact.
 */

declare module 'node:test' {
  type TestFn = () => void | Promise<void>;
  export function test(name: string, fn: TestFn): Promise<void>;
  export function describe(name: string, fn: () => void): void;
  export function it(name: string, fn: TestFn): void;
}

declare module 'node:assert/strict' {
  interface AssertStrict {
    (value: unknown, message?: string): asserts value;
    ok(value: unknown, message?: string): asserts value;
    equal(actual: unknown, expected: unknown, message?: string): void;
    notEqual(actual: unknown, expected: unknown, message?: string): void;
    deepEqual(actual: unknown, expected: unknown, message?: string): void;
    notDeepEqual(actual: unknown, expected: unknown, message?: string): void;
    throws(fn: () => unknown, message?: string): void;
    fail(message?: string): never;
  }
  const assert: AssertStrict;
  export default assert;
}
