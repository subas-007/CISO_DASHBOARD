/** Pure metric functions (unit tested). */
import type { KriDirection, RagStatus } from '@prisma/client';

const HOUR = 3_600_000;
const DAY = 86_400_000;

/** Mean of (end - start) in hours over pairs where both ends exist and end >= start. */
export function meanDurationHours(pairs: { start: Date; end: Date | null }[]): number | null {
  const durations = pairs
    .filter((p): p is { start: Date; end: Date } => p.end != null && p.end.getTime() >= p.start.getTime())
    .map((p) => (p.end.getTime() - p.start.getTime()) / HOUR);
  if (durations.length === 0) return null;
  return round(durations.reduce((a, b) => a + b, 0) / durations.length, 1);
}

export function percentage(part: number, total: number): number | null {
  if (total <= 0) return null;
  return round((part / total) * 100, 1);
}

/** Findings remediated per week over the window. */
export function velocityPerWeek(remediatedCount: number, windowDays: number): number {
  if (windowDays <= 0) return 0;
  return round(remediatedCount / (windowDays / 7), 1);
}

export function meanDays(pairs: { start: Date; end: Date | null }[]): number | null {
  const h = meanDurationHours(pairs);
  return h == null ? null : round((h * HOUR) / DAY, 1);
}

/** Red/Amber/Green evaluation against KRI thresholds. */
export function ragStatus(
  value: number | null,
  def: { direction: KriDirection; amberThreshold: number; redThreshold: number },
): RagStatus | null {
  if (value == null) return null;
  if (def.direction === 'HIGHER_IS_WORSE') {
    if (value >= def.redThreshold) return 'RED';
    if (value >= def.amberThreshold) return 'AMBER';
    return 'GREEN';
  }
  if (value <= def.redThreshold) return 'RED';
  if (value <= def.amberThreshold) return 'AMBER';
  return 'GREEN';
}

/** Thresholds must be ordered consistently with the KRI direction. */
export function thresholdsValid(direction: KriDirection, amber: number, red: number): boolean {
  return direction === 'HIGHER_IS_WORSE' ? red > amber : red < amber;
}

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/** ISO 31000-aligned 5x5 scoring bands (score = likelihood × impact). */
export function riskLevel(likelihood: number, impact: number): RiskLevel {
  const score = likelihood * impact;
  if (score >= 15) return 'CRITICAL';
  if (score >= 10) return 'HIGH';
  if (score >= 5) return 'MEDIUM';
  return 'LOW';
}

export function round(n: number, dp: number): number {
  const f = 10 ** dp;
  return Math.round(n * f) / f;
}
