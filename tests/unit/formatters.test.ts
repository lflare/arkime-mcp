import { describe, it, expect } from 'vitest';
import { formatTable, formatSession, formatFieldList } from '@/utils/formatters';
import type { Session, FieldDefinition } from '@/types/arkime';

describe('formatters', () => {
  describe('formatTable', () => {
    it('should format empty array', () => {
      const result = formatTable([], ['id', 'name']);
      expect(result).toBe('No data');
    });

    it('should format single row', () => {
      const data = [{ id: '1', name: 'Test' }];
      const result = formatTable(data, ['id', 'name']);

      expect(result).toContain('id');
      expect(result).toContain('name');
      expect(result).toContain('1');
      expect(result).toContain('Test');
    });

    it('should format multiple rows', () => {
      const data = [
        { id: '1', name: 'Alice' },
        { id: '2', name: 'Bob' },
      ];

      const result = formatTable(data, ['id', 'name']);

      expect(result).toContain('Alice');
      expect(result).toContain('Bob');
    });

    it('should handle nested properties', () => {
      const data = [
        { id: '1', source: { ip: '192.168.1.1', port: 443 } },
      ];

      const result = formatTable(data, ['id', 'source.ip', 'source.port']);

      expect(result).toContain('192.168.1.1');
      expect(result).toContain('443');
    });

    it('should handle missing properties gracefully', () => {
      const data = [{ id: '1' }];
      const result = formatTable(data, ['id', 'missing']);

      expect(result).toContain('1');
    });
  });

  describe('formatSession', () => {
    it('should format minimal session', () => {
      const session: Session = {
        id: 'session-123',
        lastPacket: 1704067200000,
      };

      const result = formatSession(session);

      expect(result).toContain('session-123');
    });

    it('should format complete session', () => {
      const session: Session = {
        id: 'session-456',
        lastPacket: 1704067200000,
        source: { ip: '192.168.1.100', port: 45678, bytes: 1500 },
        destination: { ip: '10.0.0.50', port: 443, bytes: 5000 },
        ipProtocol: 6,
      };

      const result = formatSession(session);

      expect(result).toContain('192.168.1.100');
      expect(result).toContain('45678');
      expect(result).toContain('10.0.0.50');
      expect(result).toContain('443');
      expect(result).toContain('TCP');
    });
  });

  describe('formatFieldList', () => {
    it('should format empty list', () => {
      const result = formatFieldList([]);
      expect(result).toBe('No fields available');
    });

    it('should format field definitions', () => {
      const fields: FieldDefinition[] = [
        { dbName: 'source.ip', friendlyName: 'Source IP', type: 'ip', group: 'general' },
        { dbName: 'port.dst', friendlyName: 'Dest Port', type: 'integer', group: 'general' },
      ];

      const result = formatFieldList(fields);

      expect(result).toContain('source.ip');
      expect(result).toContain('Source IP');
      expect(result).toContain('port.dst');
      expect(result).toContain('Dest Port');
    });

    it('should group fields by category', () => {
      const fields: FieldDefinition[] = [
        { dbName: 'source.ip', friendlyName: 'Source IP', type: 'ip', group: 'general' },
        { dbName: 'http.uri', friendlyName: 'HTTP URI', type: 'string', group: 'http' },
      ];

      const result = formatFieldList(fields);

      expect(result).toContain('[general]');
      expect(result).toContain('[http]');
    });
  });
});
