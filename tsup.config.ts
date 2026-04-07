import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: ['src/index.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: false,
    clean: true,
    target: 'es2022',
    platform: 'neutral',
    treeshake: true,
    splitting: false,
    outExtension({ format }) {
      return { js: format === 'esm' ? '.mjs' : '.cjs' };
    },
  },
  {
    entry: ['src/node.ts'],
    format: ['esm', 'cjs'],
    dts: { entry: 'src/node.ts' },
    sourcemap: false,
    clean: false,
    target: 'es2022',
    platform: 'node',
    treeshake: true,
    splitting: false,
    outExtension({ format }) {
      return { js: format === 'esm' ? '.mjs' : '.cjs' };
    },
  },
]);

