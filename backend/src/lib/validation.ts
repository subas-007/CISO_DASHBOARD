/**
 * Shared Zod primitives. All request bodies use .strict() objects so unknown keys are
 * rejected (mass-assignment protection). Free text rejects control characters; output
 * encoding is handled by React on the client (no HTML rendering of user content).
 */
import { z } from 'zod';

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;

export const safeText = (max: number, min = 0) =>
  z
    .string()
    .trim()
    .min(min)
    .max(max)
    .refine((v) => !CONTROL_CHARS.test(v), 'contains control characters');

export const singleLine = (max: number, min = 0) =>
  safeText(max, min).refine((v) => !/[\r\n]/.test(v), 'must be a single line');

export const IdParam = z.object({ id: z.string().uuid() }).strict();

export const Pagination = z.object({
  limit: z.coerce.number().int().min(1).max(500).default(50),
  offset: z.coerce.number().int().min(0).max(1_000_000).default(0),
});

export const SeverityEnum = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);

export const isoDate = z.coerce.date().refine((d) => !Number.isNaN(d.getTime()), 'invalid date');

/** Comma-separated list in a query string → validated enum array. */
export const csvEnum = <const T extends [string, ...string[]]>(values: T) =>
  z
    .string()
    .optional()
    .transform((v) => (v ? v.split(',').map((s) => s.trim()).filter(Boolean) : []))
    .pipe(z.array(z.enum(values)).max(values.length));
