import { describe, it, expect } from 'vitest';
import { validateIPv4 } from '@/utils/formatters';

describe('validateIPv4', () => {
  it('should accept valid IPv4 addresses', () => {
    expect(validateIPv4('192.168.1.1')).toBe(true);
    expect(validateIPv4('10.0.0.1')).toBe(true);
    expect(validateIPv4('0.0.0.0')).toBe(true);
    expect(validateIPv4('255.255.255.255')).toBe(true);
  });

  it('should reject invalid IPv4 addresses', () => {
    expect(validateIPv4('256.0.0.1')).toBe(false);
    expect(validateIPv4('10.0.0')).toBe(false);
    expect(validateIPv4('abc.def.ghi.jkl')).toBe(false);
    expect(validateIPv4('')).toBe(false);
  });

  it('should reject injection attempts', () => {
    expect(validateIPv4('10.0.0.1; evil')).toBe(false);
    expect(validateIPv4('1.2.3.4" || "x"=="')).toBe(false);
    expect(validateIPv4('port.dst == 443')).toBe(false);
  });
});
