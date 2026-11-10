/**
 * Role-Based Access Control — single source of truth for permissions.
 * Every API route declares the permission it needs; the UI receives the computed
 * permission list from /api/auth/me and only uses it for presentation.
 *
 * Separation of duties:
 *  - ADMIN manages the platform (integrations, system, users, parameters) but cannot
 *    approve risk acceptances or change remediation state.
 *  - Risk acceptance approval is CISO-only and an approver can never approve their
 *    own request (enforced in the risk service).
 *  - AUDITOR is strictly read-only.
 */
import type { Role } from '@prisma/client';

export const ROLES: readonly Role[] = ['ADMIN', 'CISO', 'SECOPS', 'PATCH_ADMIN', 'AUDITOR'] as const;
const ALL: Role[] = [...ROLES];

export const PERMISSIONS = {
  'dashboard:read': ALL,
  'kpi:read': ALL,
  'kri:read': ALL,
  'kri:acknowledge': ['CISO', 'SECOPS', 'ADMIN'],
  'parameters:manage': ['CISO', 'ADMIN'],

  'risk:read': ALL,
  'risk:write': ['CISO', 'SECOPS'],
  'risk:acceptance:request': ['CISO', 'SECOPS', 'PATCH_ADMIN'],
  'risk:acceptance:approve': ['CISO'],

  'threat:read': ALL,
  'threat:triage': ['SECOPS', 'CISO'],

  'incident:read': ALL,
  'incident:write': ['SECOPS'],

  'vuln:read': ALL,
  'remediation:write': ['PATCH_ADMIN'],
  'change:link': ['PATCH_ADMIN'],

  'integration:read': ['ADMIN', 'SECOPS', 'CISO'],
  'integration:manage': ['ADMIN', 'SECOPS'],

  'users:read': ['ADMIN', 'CISO'],
  'users:manage': ['ADMIN'],
  'system:manage': ['ADMIN'],

  'audit:read': ['AUDITOR', 'ADMIN', 'CISO'],
  'compliance:read': ['AUDITOR', 'CISO', 'ADMIN'],
} as const satisfies Record<string, readonly Role[]>;

export type Permission = keyof typeof PERMISSIONS;

export function can(roles: readonly Role[], permission: Permission): boolean {
  const allowed = PERMISSIONS[permission] as readonly Role[];
  return roles.some((r) => allowed.includes(r));
}

export function permissionsFor(roles: readonly Role[]): Permission[] {
  return (Object.keys(PERMISSIONS) as Permission[]).filter((p) => can(roles, p));
}

export function isRole(value: string): value is Role {
  return (ROLES as readonly string[]).includes(value);
}
