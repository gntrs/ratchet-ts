/**
 * Minimal ambient declarations for the Node builtins the suite uses.
 *
 * @types/node is not a dependency of this package on purpose. src/ must run
 * unchanged in a browser, and pulling the whole Node global surface into the
 * compiler makes it far too easy for someone to reach for `Buffer` or
 * `node:crypto` in the core and not find out until runtime. Declaring only
 * what the tests actually call keeps that guardrail intact.
 *
 * `node:buffer` is declared as a module import rather than the `Buffer` global
 * for that reason: a test has to ask for it by name, so src/ still cannot
 * reach it by accident. One test needs it, and needs it for a real reason.
 * The binary decoder rejects anything that is not a Uint8Array, and Buffer is
 * the shape a socket hands the CLI on every frame, so "Buffer still passes"
 * is a property worth pinning rather than assuming.
 */

declare module 'node:test' {
  type TestFn = () => void | Promise<void>;
  export function test(name: string, fn: TestFn): Promise<void>;
  export function describe(name: string, fn: () => void): void;
  export function it(name: string, fn: TestFn): void;
}

declare module 'node:buffer' {
  interface BufferCtor {
    from(source: Uint8Array): Uint8Array;
  }
  export const Buffer: BufferCtor;
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
