import { describe, it, expect } from 'vitest';
import { McpError, ErrorCode } from '@/utils/errors';

describe('McpError', () => {
  describe('constructor', () => {
    it('should create error with code and message', () => {
      const error = new McpError(ErrorCode.AUTH_MISSING, 'API credentials not configured');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(McpError);
      expect(error.code).toBe(ErrorCode.AUTH_MISSING);
      expect(error.message).toBe('API credentials not configured');
      expect(error.name).toBe('McpError');
    });

    it('should capture stack trace', () => {
      const error = new McpError(ErrorCode.API_ERROR, 'Request failed');

      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('McpError');
    });

    it('should preserve cause when provided', () => {
      const cause = new Error('Original error');
      const error = new McpError(ErrorCode.NETWORK_ERROR, 'Connection failed', cause);

      expect(error.cause).toBe(cause);
    });
  });

  describe('error codes', () => {
    it('should support AUTH_MISSING code', () => {
      const error = new McpError(ErrorCode.AUTH_MISSING, 'Missing credentials');
      expect(error.code).toBe('AUTH_MISSING');
    });

    it('should support AUTH_INVALID code', () => {
      const error = new McpError(ErrorCode.AUTH_INVALID, 'Invalid credentials');
      expect(error.code).toBe('AUTH_INVALID');
    });

    it('should support API_ERROR code', () => {
      const error = new McpError(ErrorCode.API_ERROR, 'API returned 500');
      expect(error.code).toBe('API_ERROR');
    });

    it('should support NETWORK_ERROR code', () => {
      const error = new McpError(ErrorCode.NETWORK_ERROR, 'Connection timeout');
      expect(error.code).toBe('NETWORK_ERROR');
    });

    it('should support INVALID_INPUT code', () => {
      const error = new McpError(ErrorCode.INVALID_INPUT, 'Invalid expression');
      expect(error.code).toBe('INVALID_INPUT');
    });

    it('should support NOT_FOUND code', () => {
      const error = new McpError(ErrorCode.NOT_FOUND, 'Session not found');
      expect(error.code).toBe('NOT_FOUND');
    });

    it('should support CONFIG_ERROR code', () => {
      const error = new McpError(ErrorCode.CONFIG_ERROR, 'Configuration missing');
      expect(error.code).toBe('CONFIG_ERROR');
    });
  });

  describe('toJSON', () => {
    it('should serialize error for MCP response', () => {
      const error = new McpError(ErrorCode.INVALID_INPUT, 'Expression too long');

      const json = error.toJSON();

      expect(json).toEqual({
        code: ErrorCode.INVALID_INPUT,
        message: 'Expression too long',
      });
    });
  });

  describe('isMcpError', () => {
    it('should return true for McpError instances', () => {
      const error = new McpError(ErrorCode.API_ERROR, 'Failed');
      expect(McpError.isMcpError(error)).toBe(true);
    });

    it('should return false for regular errors', () => {
      const error = new Error('Regular error');
      expect(McpError.isMcpError(error)).toBe(false);
    });

    it('should return false for non-error values', () => {
      expect(McpError.isMcpError(null)).toBe(false);
      expect(McpError.isMcpError(undefined)).toBe(false);
      expect(McpError.isMcpError('error')).toBe(false);
      expect(McpError.isMcpError({ code: 'test' })).toBe(false);
    });
  });

});
