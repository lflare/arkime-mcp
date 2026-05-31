/**
 * Error codes for classifying MCP errors
 */
export enum ErrorCode {
  AUTH_MISSING = 'AUTH_MISSING',
  AUTH_INVALID = 'AUTH_INVALID',
  API_ERROR = 'API_ERROR',
  NETWORK_ERROR = 'NETWORK_ERROR',
  INVALID_INPUT = 'INVALID_INPUT',
  NOT_FOUND = 'NOT_FOUND',
  CONFIG_ERROR = 'CONFIG_ERROR',
}

/**
 * Custom error class for MCP server operations
 * Provides structured error classification for better error handling
 */
export class McpError extends Error {
  public readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string, cause?: Error) {
    super(message, { cause });
    this.name = 'McpError';
    this.code = code;

    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, McpError.prototype);
  }

  /**
   * Serialize error for MCP response
   */
  toJSON(): { code: ErrorCode; message: string } {
    return {
      code: this.code,
      message: this.message,
    };
  }

  /**
   * Type guard to check if an error is an McpError
   */
  static isMcpError(error: unknown): error is McpError {
    return error instanceof McpError;
  }

}
