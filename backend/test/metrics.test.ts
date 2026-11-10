import { describe, expect, it } from 'vitest';
import { meanDurationHours, percentage, ragStatus, riskLevel, thresholdsValid, velocityPerWeek } from '../src/modules/kpi/metrics.js';

const d = (h: number) => new Date(Date.UTC(2026, 0, 1) + h * 3_600_000);

describe('KPI metrics', () => {
  it('computes MTTD/MTTR as mean hours and ignores incomplete pairs', () => {
    expect(meanDurationHours([{ start: d(0), end: d(2) }, { start: d(0), end: d(4) }, { start: d(0), end: null }])).toBe(3);
    expect(meanDurationHours([])).toBeNull();
  });

  it('computes patch compliance percentage', () => {
    expect(percentage(45, 50)).toBe(90);
    expect(percentage(0, 0)).toBeNull();
  });

  it('computes remediation velocity per week', () => {
    expect(velocityPerWeek(60, 30)).toBe(14);
  });
});

describe('KRI RAG evaluation', () => {
  const higher = { direction: 'HIGHER_IS_WORSE' as const, amberThreshold: 10, redThreshold: 25 };
  const lower = { direction: 'LOWER_IS_WORSE' as const, amberThreshold: 95, redThreshold: 85 };

  it('higher-is-worse thresholds', () => {
    expect(ragStatus(5, higher)).toBe('GREEN');
    expect(ragStatus(10, higher)).toBe('AMBER');
    expect(ragStatus(30, higher)).toBe('RED');
  });

  it('lower-is-worse thresholds', () => {
    expect(ragStatus(98, lower)).toBe('GREEN');
    expect(ragStatus(90, lower)).toBe('AMBER');
    expect(ragStatus(80, lower)).toBe('RED');
    expect(ragStatus(null, lower)).toBeNull();
  });

  it('validates threshold ordering', () => {
    expect(thresholdsValid('HIGHER_IS_WORSE', 10, 25)).toBe(true);
    expect(thresholdsValid('HIGHER_IS_WORSE', 25, 10)).toBe(false);
    expect(thresholdsValid('LOWER_IS_WORSE', 95, 85)).toBe(true);
  });
});

describe('ISO 31000 5x5 matrix banding', () => {
  it('maps likelihood x impact to levels', () => {
    expect(riskLevel(1, 4)).toBe('LOW');
    expect(riskLevel(2, 3)).toBe('MEDIUM');
    expect(riskLevel(2, 5)).toBe('HIGH');
    expect(riskLevel(3, 5)).toBe('CRITICAL');
    expect(riskLevel(5, 5)).toBe('CRITICAL');
  });
});
