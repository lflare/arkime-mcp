import { describe, it, expect } from 'vitest';
import { escapeExpressionValue, validateIPv4 } from '@/utils/formatters';

describe('expression injection defenses', () => {
  describe('escapeExpressionValue', () => {
    it('should prevent quote injection by escaping quotes', () => {
      const malicious = 'admin" || "x"=="';
      const escaped = escapeExpressionValue(malicious);
      // Each unescaped quote should become \"
      // Check that no bare quote remains (all are preceded by backslash)
      const bareQuotes = escaped.match(/(?<!\\)"/g);
      expect(bareQuotes).toBeNull();
    });

    it('should prevent backslash injection', () => {
      const malicious = 'path\\to\\evil';
      const escaped = escapeExpressionValue(malicious);
      expect(escaped).toBe('path\\\\to\\\\evil');
    });

    it('should handle combined backslash and quote injection', () => {
      // Input: user\" + "
      const malicious = 'user\\name"';
      const escaped = escapeExpressionValue(malicious);
      // Backslash escaped first (\\), then quote escaped (\")
      expect(escaped).toBe('user\\\\name\\"');
    });
  });

  describe('validateIPv4', () => {
    it('should reject IP injection attempts', () => {
      expect(validateIPv4('10.0.0.1 || 1==1')).toBe(false);
      expect(validateIPv4('10.0.0.1; DROP TABLE')).toBe(false);
    });

    it('should reject command injection in IP field', () => {
      expect(validateIPv4('10.0.0.1"; evil(); //')).toBe(false);
    });
  });
});
