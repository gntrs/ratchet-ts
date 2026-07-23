import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  treeshake: true,
  // The noble packages are runtime dependencies, not bundled in. Consumers
  // resolve them from their own node_modules, so a single copy is shared.
  external: [
    '@noble/ciphers',
    '@noble/curves',
    '@noble/hashes',
    '@noble/post-quantum',
  ],
  outExtension({ format }) {
    return { js: format === 'cjs' ? '.cjs' : '.js' };
  },
});
