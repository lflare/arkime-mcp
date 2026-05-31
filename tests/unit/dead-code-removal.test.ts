import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';

describe('Dead code removal', () => {
  const packageJson = JSON.parse(
    readFileSync(resolve(__dirname, '../../package.json'), 'utf-8')
  );

  it('should not have @types/axios (deprecated, axios ships own types)', () => {
    expect(packageJson.devDependencies?.['@types/axios']).toBeUndefined();
  });

  it('should not have @mhoc/axios-digest-auth (unused, we implement our own)', () => {
    expect(packageJson.devDependencies?.['@mhoc/axios-digest-auth']).toBeUndefined();
    expect(packageJson.dependencies?.['@mhoc/axios-digest-auth']).toBeUndefined();
  });
});

describe('query-builder.ts removal', () => {
  it('should not have query-builder.ts', () => {
    expect(existsSync(resolve(__dirname, '../../src/services/query-builder.ts'))).toBe(false);
  });
});
