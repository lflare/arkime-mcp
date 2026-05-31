import { describe, it, expect } from 'vitest';
import {
  formatNum,
  isoToTimestamp,
  unixToISO,
  isPrivateIp,
  getProtocolFromPort,
  LATERAL_MOVEMENT_PORTS,
  AUTH_PORTS,
  PORT_PROTOCOL_MAP,
  PROTOCOL_MAP,
} from '@/utils/formatters';

describe('formatNum', () => {
  it('should format 0', () => {
    expect(formatNum(0)).toBe('0');
  });

  it('should format 1', () => {
    expect(formatNum(1)).toBe('1');
  });

  it('should format 100', () => {
    expect(formatNum(100)).toBe('100');
  });

  it('should format 1000 with thousands separator', () => {
    expect(formatNum(1000)).toBe('1,000');
  });

  it('should format 1234567 with thousands separators', () => {
    expect(formatNum(1234567)).toBe('1,234,567');
  });

  it('should format 999999999 with thousands separators', () => {
    expect(formatNum(999999999)).toBe('999,999,999');
  });
});

describe('isoToTimestamp', () => {
  it('should convert known date 2025-01-01T00:00:00Z', () => {
    expect(isoToTimestamp('2025-01-01T00:00:00Z')).toBe(1735689600);
  });

  it('should convert known date 2025-12-31T23:59:59Z', () => {
    expect(isoToTimestamp('2025-12-31T23:59:59Z')).toBe(1767225599);
  });

  it('should convert epoch 1970-01-01T00:00:00Z to 0', () => {
    expect(isoToTimestamp('1970-01-01T00:00:00Z')).toBe(0);
  });

  it('should return integer timestamp', () => {
    const result = isoToTimestamp('2025-06-15T12:30:00Z');
    expect(Number.isInteger(result)).toBe(true);
  });
});

describe('unixToISO', () => {
  it('should convert 0 to epoch ISO string', () => {
    expect(unixToISO(0)).toBe('1970-01-01T00:00:00.000Z');
  });

  it('should convert 1735689600 to 2025-01-01 ISO string', () => {
    expect(unixToISO(1735689600)).toBe('2025-01-01T00:00:00.000Z');
  });

  it('should roundtrip with isoToTimestamp', () => {
    const iso = '2025-06-15T12:30:00Z';
    const ts = isoToTimestamp(iso);
    const roundtrip = unixToISO(ts);
    const reparse = isoToTimestamp(roundtrip);
    expect(reparse).toBe(ts);
  });
});

describe('isPrivateIp', () => {
  it('should identify 10.0.0.1 as private', () => {
    expect(isPrivateIp('10.0.0.1')).toBe(true);
  });

  it('should identify 10.255.255.255 as private', () => {
    expect(isPrivateIp('10.255.255.255')).toBe(true);
  });

  it('should identify 192.168.0.1 as private', () => {
    expect(isPrivateIp('192.168.0.1')).toBe(true);
  });

  it('should identify 192.168.255.255 as private', () => {
    expect(isPrivateIp('192.168.255.255')).toBe(true);
  });

  it('should identify 127.0.0.1 as private', () => {
    expect(isPrivateIp('127.0.0.1')).toBe(true);
  });

  it('should identify 169.254.1.1 as private', () => {
    expect(isPrivateIp('169.254.1.1')).toBe(true);
  });

  it('should identify 172.16.0.1 as private', () => {
    expect(isPrivateIp('172.16.0.1')).toBe(true);
  });

  it('should identify 172.31.255.255 as private', () => {
    expect(isPrivateIp('172.31.255.255')).toBe(true);
  });

  it('should identify 8.8.8.8 as public', () => {
    expect(isPrivateIp('8.8.8.8')).toBe(false);
  });

  it('should identify 1.1.1.1 as public', () => {
    expect(isPrivateIp('1.1.1.1')).toBe(false);
  });

  it('should identify 172.15.0.1 as public', () => {
    expect(isPrivateIp('172.15.0.1')).toBe(false);
  });

  it('should identify 172.32.0.1 as public', () => {
    expect(isPrivateIp('172.32.0.1')).toBe(false);
  });

  it('should identify 11.0.0.1 as public', () => {
    expect(isPrivateIp('11.0.0.1')).toBe(false);
  });

  it('should identify 193.168.1.1 as public', () => {
    expect(isPrivateIp('193.168.1.1')).toBe(false);
  });

  it('should return false for empty string', () => {
    expect(isPrivateIp('')).toBe(false);
  });

  it('should return false for non-IP string', () => {
    expect(isPrivateIp('not-an-ip')).toBe(false);
  });
});

describe('getProtocolFromPort', () => {
  it('should map 139 to smb', () => {
    expect(getProtocolFromPort(139)).toBe('smb');
  });

  it('should map 445 to smb', () => {
    expect(getProtocolFromPort(445)).toBe('smb');
  });

  it('should map 389 to ldap', () => {
    expect(getProtocolFromPort(389)).toBe('ldap');
  });

  it('should map 636 to ldaps', () => {
    expect(getProtocolFromPort(636)).toBe('ldaps');
  });

  it('should map 3389 to rdp', () => {
    expect(getProtocolFromPort(3389)).toBe('rdp');
  });

  it('should map 5985 to winrm', () => {
    expect(getProtocolFromPort(5985)).toBe('winrm');
  });

  it('should map 5986 to winrms', () => {
    expect(getProtocolFromPort(5986)).toBe('winrms');
  });

  it('should map 22 to ssh', () => {
    expect(getProtocolFromPort(22)).toBe('ssh');
  });

  it('should return port-80 for unmapped port 80', () => {
    expect(getProtocolFromPort(80)).toBe('port-80');
  });

  it('should return port-443 for unmapped port 443', () => {
    expect(getProtocolFromPort(443)).toBe('port-443');
  });

  it('should return port-9999 for unmapped port 9999', () => {
    expect(getProtocolFromPort(9999)).toBe('port-9999');
  });
});

describe('LATERAL_MOVEMENT_PORTS', () => {
  it('should contain SSH port 22', () => {
    expect(LATERAL_MOVEMENT_PORTS).toContain(22);
  });

  it('should contain Telnet port 23', () => {
    expect(LATERAL_MOVEMENT_PORTS).toContain(23);
  });

  it('should contain RPC port 135', () => {
    expect(LATERAL_MOVEMENT_PORTS).toContain(135);
  });

  it('should contain NetBIOS port 139', () => {
    expect(LATERAL_MOVEMENT_PORTS).toContain(139);
  });

  it('should contain SMB port 445', () => {
    expect(LATERAL_MOVEMENT_PORTS).toContain(445);
  });

  it('should contain LDAPS port 636', () => {
    expect(LATERAL_MOVEMENT_PORTS).toContain(636);
  });

  it('should contain RDP port 3389', () => {
    expect(LATERAL_MOVEMENT_PORTS).toContain(3389);
  });

  it('should contain VNC port 5900', () => {
    expect(LATERAL_MOVEMENT_PORTS).toContain(5900);
  });

  it('should contain VNC port 5901', () => {
    expect(LATERAL_MOVEMENT_PORTS).toContain(5901);
  });

  it('should contain VNC port 5902', () => {
    expect(LATERAL_MOVEMENT_PORTS).toContain(5902);
  });

  it('should contain Metasploit port 4444', () => {
    expect(LATERAL_MOVEMENT_PORTS).toContain(4444);
  });

  it('should contain IRC port 6667', () => {
    expect(LATERAL_MOVEMENT_PORTS).toContain(6667);
  });
});

describe('AUTH_PORTS', () => {
  it('should contain Kerberos port 88', () => {
    expect(AUTH_PORTS).toContain(88);
  });

  it('should contain NetBIOS port 139', () => {
    expect(AUTH_PORTS).toContain(139);
  });

  it('should contain LDAP port 389', () => {
    expect(AUTH_PORTS).toContain(389);
  });

  it('should contain HTTPS port 443', () => {
    expect(AUTH_PORTS).toContain(443);
  });

  it('should contain SMB port 445', () => {
    expect(AUTH_PORTS).toContain(445);
  });

  it('should contain LDAPS port 636', () => {
    expect(AUTH_PORTS).toContain(636);
  });

  it('should contain Global Catalog LDAP port 3268', () => {
    expect(AUTH_PORTS).toContain(3268);
  });

  it('should contain Global Catalog LDAPS port 3269', () => {
    expect(AUTH_PORTS).toContain(3269);
  });
});

describe('PORT_PROTOCOL_MAP', () => {
  it('should map 139 to smb', () => {
    expect(PORT_PROTOCOL_MAP[139]).toBe('smb');
  });

  it('should map 445 to smb', () => {
    expect(PORT_PROTOCOL_MAP[445]).toBe('smb');
  });

  it('should map 389 to ldap', () => {
    expect(PORT_PROTOCOL_MAP[389]).toBe('ldap');
  });

  it('should map 636 to ldaps', () => {
    expect(PORT_PROTOCOL_MAP[636]).toBe('ldaps');
  });

  it('should map 3268 to ldap', () => {
    expect(PORT_PROTOCOL_MAP[3268]).toBe('ldap');
  });

  it('should map 3269 to ldaps', () => {
    expect(PORT_PROTOCOL_MAP[3269]).toBe('ldaps');
  });

  it('should map 3389 to rdp', () => {
    expect(PORT_PROTOCOL_MAP[3389]).toBe('rdp');
  });

  it('should map 5985 to winrm', () => {
    expect(PORT_PROTOCOL_MAP[5985]).toBe('winrm');
  });

  it('should map 5986 to winrms', () => {
    expect(PORT_PROTOCOL_MAP[5986]).toBe('winrms');
  });

  it('should map 22 to ssh', () => {
    expect(PORT_PROTOCOL_MAP[22]).toBe('ssh');
  });
});

describe('PROTOCOL_MAP', () => {
  it('should map 1 to ICMP', () => {
    expect(PROTOCOL_MAP[1]).toBe('ICMP');
  });

  it('should map 6 to TCP', () => {
    expect(PROTOCOL_MAP[6]).toBe('TCP');
  });

  it('should map 17 to UDP', () => {
    expect(PROTOCOL_MAP[17]).toBe('UDP');
  });

  it('should map 47 to GRE', () => {
    expect(PROTOCOL_MAP[47]).toBe('GRE');
  });

  it('should map 50 to ESP', () => {
    expect(PROTOCOL_MAP[50]).toBe('ESP');
  });

  it('should map 51 to AH', () => {
    expect(PROTOCOL_MAP[51]).toBe('AH');
  });

  it('should map 58 to ICMPv6', () => {
    expect(PROTOCOL_MAP[58]).toBe('ICMPv6');
  });

  it('should map 89 to OSPF', () => {
    expect(PROTOCOL_MAP[89]).toBe('OSPF');
  });

  it('should map 132 to SCTP', () => {
    expect(PROTOCOL_MAP[132]).toBe('SCTP');
  });
});
