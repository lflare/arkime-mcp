import { describe, it, expect } from 'vitest';
import {
  isSession,
  isFieldDefinition,
  isSessionsResponse,
  type Session,
  type FieldDefinition,
  type SessionsResponse,
} from '@/types/arkime';

describe('Arkime Types', () => {
  describe('isSession', () => {
    it('should validate a minimal session object', () => {
      const session: unknown = {
        id: 'session-123',
        lastPacket: 1704067200000,
      };

      expect(isSession(session)).toBe(true);
    });

    it('should validate a complete session object', () => {
      const session: unknown = {
        id: 'session-456',
        lastPacket: 1704067200000,
        source: {
          ip: '192.168.1.100',
          port: 45678,
          bytes: 1500,
          packets: 10,
        },
        destination: {
          ip: '10.0.0.50',
          port: 443,
          bytes: 5000,
          packets: 15,
        },
        ipProtocol: 6,
        node: 'arkime-node-1',
        firstPacket: 1704067100000,
      };

      expect(isSession(session)).toBe(true);
    });

    it('should reject objects missing required id', () => {
      const session: unknown = {
        lastPacket: 1704067200000,
      };

      expect(isSession(session)).toBe(false);
    });

    it('should reject objects missing lastPacket', () => {
      const session: unknown = {
        id: 'session-123',
      };

      expect(isSession(session)).toBe(false);
    });

    it('should reject non-objects', () => {
      expect(isSession(null)).toBe(false);
      expect(isSession(undefined)).toBe(false);
      expect(isSession('session')).toBe(false);
      expect(isSession(123)).toBe(false);
    });
  });

  describe('isFieldDefinition', () => {
    it('should validate a field definition', () => {
      const field: unknown = {
        dbName: 'source.ip',
        friendlyName: 'Source IP',
        type: 'ip',
        group: 'general',
      };

      expect(isFieldDefinition(field)).toBe(true);
    });

    it('should validate field with all optional properties', () => {
      const field: unknown = {
        dbName: 'port.dst',
        friendlyName: 'Destination Port',
        type: 'integer',
        group: 'general',
        description: 'Destination TCP/UDP port',
      };

      expect(isFieldDefinition(field)).toBe(true);
    });

    it('should reject objects missing dbName', () => {
      const field: unknown = {
        friendlyName: 'Test Field',
        type: 'string',
        group: 'general',
      };

      expect(isFieldDefinition(field)).toBe(false);
    });

    it('should reject non-objects', () => {
      expect(isFieldDefinition(null)).toBe(false);
      expect(isFieldDefinition('field')).toBe(false);
    });
  });

  describe('isSessionsResponse', () => {
    it('should validate a sessions response', () => {
      const response: unknown = {
        data: [
          { id: 'session-1', lastPacket: 1704067200000 },
          { id: 'session-2', lastPacket: 1704067300000 },
        ],
        recordsTotal: 2,
        recordsFiltered: 2,
      };

      expect(isSessionsResponse(response)).toBe(true);
    });

    it('should validate empty sessions array', () => {
      const response: unknown = {
        data: [],
        recordsTotal: 0,
        recordsFiltered: 0,
      };

      expect(isSessionsResponse(response)).toBe(true);
    });

    it('should reject response with invalid sessions', () => {
      const response: unknown = {
        data: [{ id: 123 }],
        recordsTotal: 1,
        recordsFiltered: 1,
      };

      expect(isSessionsResponse(response)).toBe(false);
    });

    it('should reject non-objects', () => {
      expect(isSessionsResponse(null)).toBe(false);
      expect(isSessionsResponse({})).toBe(false);
    });
  });
});
