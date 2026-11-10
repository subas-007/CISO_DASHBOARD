/**
 * Parameter definitions (system-wide tunables) with schema validation, defaults and
 * the permission required to change each one.
 */
import { z } from 'zod';
import type { Prisma } from '@prisma/client';
import { prisma } from '../../lib/prisma.js';
import type { Permission } from '../../auth/rbac.js';

const sla = z
  .object({
    CRITICAL: z.number().int().min(1).max(365),
    HIGH: z.number().int().min(1).max(365),
    MEDIUM: z.number().int().min(1).max(730),
    LOW: z.number().int().min(1).max(1095),
  })
  .strict();

export const SETTINGS = {
  riskAppetiteScore: {
    label: 'Risk appetite (max tolerated inherent score, 1-25)',
    schema: z.number().int().min(1).max(25),
    default: 12,
    permission: 'parameters:manage',
  },
  vulnSlaDays: {
    label: 'Vulnerability remediation SLA (days by severity)',
    schema: sla,
    default: { CRITICAL: 15, HIGH: 30, MEDIUM: 90, LOW: 180 },
    permission: 'parameters:manage',
  },
  riskAcceptanceMaxDays: {
    label: 'Maximum risk acceptance validity (days)',
    schema: z.number().int().min(1).max(365),
    default: 180,
    permission: 'parameters:manage',
  },
  kpiWindowDays: {
    label: 'KPI rolling window (days) for MTTD / MTTR / velocity',
    schema: z.number().int().min(7).max(365),
    default: 30,
    permission: 'parameters:manage',
  },
  threatRetentionDays: {
    label: 'Threat intel retention (days) — data minimisation',
    schema: z.number().int().min(30).max(3650),
    default: 365,
    permission: 'system:manage',
  },
  snapshotRetentionDays: {
    label: 'KPI snapshot retention (days)',
    schema: z.number().int().min(30).max(3650),
    default: 400,
    permission: 'system:manage',
  },
} as const satisfies Record<string, { label: string; schema: z.ZodTypeAny; default: unknown; permission: Permission }>;

export type SettingKey = keyof typeof SETTINGS;
export type SettingValue<K extends SettingKey> = z.infer<(typeof SETTINGS)[K]['schema']>;
export const SETTING_KEYS = Object.keys(SETTINGS) as [SettingKey, ...SettingKey[]];

const cache = new Map<SettingKey, { value: unknown; until: number }>();

export async function getSetting<K extends SettingKey>(key: K): Promise<SettingValue<K>> {
  const hit = cache.get(key);
  if (hit && hit.until > Date.now()) return hit.value as SettingValue<K>;
  const row = await prisma.systemSetting.findUnique({ where: { key } });
  const parsed = SETTINGS[key].schema.safeParse(row?.value);
  const value = (parsed.success ? parsed.data : SETTINGS[key].default) as SettingValue<K>;
  cache.set(key, { value, until: Date.now() + 30_000 });
  return value;
}

export async function getAllSettings() {
  const out: Record<string, { value: unknown; label: string; permission: Permission }> = {};
  for (const key of SETTING_KEYS) {
    out[key] = { value: await getSetting(key), label: SETTINGS[key].label, permission: SETTINGS[key].permission };
  }
  return out;
}

export function invalidateSettingsCache(): void {
  cache.clear();
}

export async function ensureDefaultSettings(): Promise<void> {
  for (const key of SETTING_KEYS) {
    await prisma.systemSetting.upsert({
      where: { key },
      create: { key, value: SETTINGS[key].default as Prisma.InputJsonValue },
      update: {},
    });
  }
}
