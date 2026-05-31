import { describe, it, expect } from 'vitest';
import { getFlowSchema } from '@/tools/schemas';

describe('Zod schema IP validation', () => {
  describe('getFlowSchema', () => {
    it('should accept valid IPv4 addresses', () => {
      const result = getFlowSchema.safeParse({
        sourceIp: '192.168.1.1',
        destIp: '10.0.0.1',
        destPort: 445,
      });
      expect(result.success).toBe(true);
    });

    it('should reject injection attempts in sourceIp', () => {
      const result = getFlowSchema.safeParse({
        sourceIp: '10.0.0.1 || 1==1',
        destIp: '192.168.1.1',
      });
      expect(result.success).toBe(false);
    });

    it('should reject injection attempts in destIp', () => {
      const result = getFlowSchema.safeParse({
        sourceIp: '10.0.0.1',
        destIp: '192.168.1.1"; evil(); //',
      });
      expect(result.success).toBe(false);
    });

    it('should reject non-IP strings', () => {
      const result = getFlowSchema.safeParse({
        sourceIp: 'localhost',
        destIp: '10.0.0.1',
      });
      expect(result.success).toBe(false);
    });
  });
});
