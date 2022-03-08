import resolve from '@rollup/plugin-node-resolve';

export default {
  input: 'lib/esm/index.js',
  output: {
    file: 'build/musig.js',
    format: 'umd',
    name: 'musig',
    exports: 'named',
    preferConst: true,
  },
  plugins: [resolve({ browser: true })],
};
