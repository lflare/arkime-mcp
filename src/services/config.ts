import { McpError, ErrorCode } from '@/utils/errors.js';

export interface ArkimeConfig {
  host: string;
  user: string;
  password: string;
  timeout: number;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

const DEFAULT_TIMEOUT = 30000;

/**
 * Check if a URL points to localhost or 127.0.0.1
 * Uses URL parsing to avoid false positives like localhost.evil.com
 */
function isLocalhost(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
  } catch {
    return false;
  }
}

export function loadConfig(): ArkimeConfig {
  return {
    host: process.env.ARKIME_HOST ?? '',
    user: process.env.ARKIME_USER ?? '',
    password: process.env.ARKIME_PASSWORD ?? '',
    timeout: parseInt(process.env.ARKIME_TIMEOUT ?? String(DEFAULT_TIMEOUT), 10),
  };
}

export function validateConfig(config: ArkimeConfig): ValidationResult {
  const errors: string[] = [];

  if (!config.host) {
    errors.push('ARKIME_HOST is required');
  } else if (!config.host.startsWith('https://') &&
             !isLocalhost(config.host)) {
    errors.push('ARKIME_HOST must use HTTPS or be localhost/127.0.0.1');
  }

  if (!config.user) {
    errors.push('ARKIME_USER is required');
  }

  if (!config.password) {
    errors.push('ARKIME_PASSWORD is required');
  }

  if (config.timeout <= 0) {
    errors.push('ARKIME_TIMEOUT must be positive');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

export function loadValidatedConfig(): ArkimeConfig {
  const config = loadConfig();
  const result = validateConfig(config);

  if (!result.valid) {
    const authErrors = result.errors.filter(e =>
      e.includes('ARKIME_USER') || e.includes('ARKIME_PASSWORD')
    );

    if (authErrors.length > 0) {
      throw new McpError(
        ErrorCode.AUTH_MISSING,
        `Missing required environment variables: ${authErrors.join(', ')}`
      );
    }

    throw new McpError(
      ErrorCode.CONFIG_ERROR,
      `Invalid configuration: ${result.errors.join(', ')}`
    );
  }

  return config;
}
