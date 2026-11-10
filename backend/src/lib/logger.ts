/**
 * Structured logger with mandatory redaction. Credentials, tokens, cookies and any
 * third-party payload fields are censored before a log line is emitted, which is part
 * of the zero-data-retention control for connector payloads.
 */
import { pino } from 'pino';
import { env } from '../config/env.js';

export const logger = pino({
  level: env.LOG_LEVEL,
  base: { service: 'ciso-api', version: env.APP_VERSION },
  timestamp: pino.stdTimeFunctions.isoTime,
  messageKey: 'msg',
  redact: {
    paths: [
      'req.headers.cookie',
      'req.headers.authorization',
      'req.headers["x-csrf-token"]',
      'res.headers["set-cookie"]',
      '*.password',
      '*.passphrase',
      '*.secret',
      '*.clientSecret',
      '*.apiKey',
      '*.apiSecret',
      '*.token',
      '*.accessToken',
      '*.refreshToken',
      '*.idToken',
      '*.credentials',
      '*.clientKey',
      '*.payload',
      '*.raw',
      '*.body',
    ],
    censor: '[REDACTED]',
  },
});
