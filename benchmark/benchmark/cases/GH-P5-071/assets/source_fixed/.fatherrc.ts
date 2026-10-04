import { defineConfig } from 'father';
import { readFileSync } from 'fs';
import { join } from 'path';

const pkg = JSON.parse(readFileSync(join(__dirname, 'package.json'), 'utf-8'));

export default defineConfig({
  esm: {},
  define: {
    'process.env.PACKAGE_VERSION': JSON.stringify(pkg.version),
  },
});
