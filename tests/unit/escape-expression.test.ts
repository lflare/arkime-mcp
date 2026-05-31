import { describe, it, expect } from 'vitest';
import { escapeExpressionValue } from '@/utils/formatters';

describe('escapeExpressionValue', () => {
  it('should escape double quotes', () => {
    expect(escapeExpressionValue('user"name')).toBe('user\\"name');
  });

  it('should escape backslashes', () => {
    // input: path\to\file (backslashes)
    // output: path\\to\\file (each \ becomes \\)
    expect(escapeExpressionValue('path\\to\\file')).toBe('path\\\\to\\\\file');
  });

  it('should escape backslashes before quotes', () => {
    // input: admin\)"  -> output: admin\\\")
    expect(escapeExpressionValue('admin\\)')).toBe('admin\\\\)');
  });

  it('should leave safe strings unchanged', () => {
    expect(escapeExpressionValue('normal-user')).toBe('normal-user');
    expect(escapeExpressionValue('192.168.1.1')).toBe('192.168.1.1');
  });
});
