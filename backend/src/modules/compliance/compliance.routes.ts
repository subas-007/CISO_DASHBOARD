/**
 * Compliance evidence report for auditors: maps implemented technical controls to
 * NIST SP 800-53 Rev.5 AU family and PCI DSS v4.0.1 Requirement 10, with live evidence.
 */
import { Router } from 'express';
import { getSetting } from '../settings/settings.service.js';
import { requirePermission } from '../../auth/middleware.js';
import { audit, auditContext, verifyAuditChain } from '../../audit/audit.service.js';
import { activeEncryptionKeyId } from '../../lib/crypto.js';
import { prisma } from '../../lib/prisma.js';
import { computeKpis } from '../kpi/kpi.service.js';

export const complianceRouter = Router();

complianceRouter.get('/report', requirePermission('compliance:read'), async (req, res) => {
  const since90 = new Date(Date.now() - 90 * 86_400_000);
  const [chain, kpis, authEvents, deniedEvents, configChanges, acceptances, firstAudit] = await Promise.all([
    verifyAuditChain(),
    computeKpis(),
    prisma.auditLog.count({ where: { action: { startsWith: 'auth.' }, ts: { gte: since90 } } }),
    prisma.auditLog.count({ where: { outcome: 'DENIED', ts: { gte: since90 } } }),
    prisma.auditLog.count({ where: { action: { startsWith: 'integration.' }, ts: { gte: since90 } } }),
    prisma.riskAcceptance.groupBy({ by: ['status'], _count: { _all: true } }),
    prisma.auditLog.findFirst({ orderBy: { id: 'asc' }, select: { ts: true } }),
  ]);

  const sp = await getSetting('sessionPolicy');
  const idp = await getSetting('identity');
  const controls = [
    { framework: 'NIST 800-53', id: 'AU-2', title: 'Event logging', status: 'IMPLEMENTED', evidence: `Authentication, admin, configuration, risk acceptance and access-denied events logged (${authEvents} auth events / 90d).` },
    { framework: 'NIST 800-53', id: 'AU-3', title: 'Content of audit records', status: 'IMPLEMENTED', evidence: 'Each record: timestamp (UTC, ms), actor id/name/roles, action, target, outcome, source IP, user agent, details.' },
    { framework: 'NIST 800-53', id: 'AU-6', title: 'Audit review, analysis and reporting', status: 'IMPLEMENTED', evidence: 'Audit viewer with filters and CSV export for Auditor/CISO/Admin roles; exports are themselves audited.' },
    { framework: 'NIST 800-53', id: 'AU-8', title: 'Time stamps', status: 'IMPLEMENTED', evidence: 'timestamptz(3) generated server-side; hosts must be NTP-synchronised (see deployment guide).' },
    { framework: 'NIST 800-53', id: 'AU-9', title: 'Protection of audit information', status: chain.valid ? 'IMPLEMENTED' : 'FAILED', evidence: `Append-only via DB triggers and revoked UPDATE/DELETE privileges. HMAC hash chain ${chain.valid ? 'verified' : 'BROKEN at id ' + chain.firstInvalidId} (${chain.checked} records).` },
    { framework: 'NIST 800-53', id: 'AU-10', title: 'Non-repudiation', status: 'IMPLEMENTED', evidence: 'Actions bound to OIDC-authenticated identities; keyed hash chain prevents silent modification.' },
    { framework: 'NIST 800-53', id: 'AU-11', title: 'Audit record retention', status: 'IMPLEMENTED', evidence: `No application path deletes audit records. Oldest record: ${firstAudit?.ts.toISOString() ?? 'n/a'}.` },
    { framework: 'NIST 800-53', id: 'AU-12', title: 'Audit record generation', status: 'IMPLEMENTED', evidence: 'Audit writes are transactional with the audited change (fail-closed).' },
    { framework: 'PCI DSS 4.0.1', id: '10.2.1', title: 'Audit logs enabled and active', status: 'IMPLEMENTED', evidence: `${deniedEvents} access-denied and ${configChanges} integration configuration events captured / 90d.` },
    { framework: 'PCI DSS 4.0.1', id: '10.2.2', title: 'Audit log content', status: 'IMPLEMENTED', evidence: 'User identity, event type, date/time, success/failure, origination, affected resource recorded.' },
    { framework: 'PCI DSS 4.0.1', id: '10.3.2', title: 'Audit logs protected from modification', status: chain.valid ? 'IMPLEMENTED' : 'FAILED', evidence: 'Immutable table + HMAC-SHA256 chain verification.' },
    { framework: 'PCI DSS 4.0.1', id: '10.3.4', title: 'Integrity monitoring of logs', status: 'IMPLEMENTED', evidence: 'On-demand and report-time chain verification; verification runs are audited.' },
    { framework: 'PCI DSS 4.0.1', id: '8.2.8', title: 'Idle session timeout ≤ 15 min', status: sp.idleTimeoutSec <= 900 ? 'IMPLEMENTED' : 'PARTIAL', evidence: `Access token ${sp.accessTokenTtlSec}s, refresh idle ${sp.idleTimeoutSec}s, absolute ${sp.absoluteTimeoutSec}s (administrator-defined, synchronised to the IdP).` },
    { framework: 'PCI DSS 4.0.1', id: '8.3.6', title: 'Password length ≥ 12 with complexity', status: idp.passwordMinLength >= 12 ? 'IMPLEMENTED' : 'PARTIAL', evidence: `IdP policy: minimum ${idp.passwordMinLength} characters, history ${idp.passwordHistory}, lockout after ${idp.lockoutMaxFailures} failures.` },
    { framework: 'PCI DSS 4.0.1', id: '8.4.2', title: 'MFA for all access', status: idp.mfaRequired ? 'IMPLEMENTED' : 'FAILED', evidence: idp.mfaRequired ? `TOTP (${idp.otpAlgorithm}, ${idp.otpDigits} digits / ${idp.otpPeriodSec}s) enforced at sign-in for every user.` : 'MFA enforcement disabled by an administrator.' },
    { framework: 'PCI DSS 4.0.1', id: '3.5.1', title: 'Stored sensitive data rendered unreadable', status: 'IMPLEMENTED', evidence: `AES-256-GCM field encryption, active key "${activeEncryptionKeyId()}"; HMAC blind indexes for lookups.` },
    { framework: 'PCI DSS 4.0.1', id: '4.2.1', title: 'Strong cryptography in transit', status: 'IMPLEMENTED', evidence: 'TLS 1.3 only at gateway with HSTS; mTLS gateway→API; TLS to PostgreSQL and IdP.' },
  ];

  await audit({ ...auditContext(req), action: 'compliance.report.generate', outcome: 'SUCCESS', targetType: 'report' });
  res.json({
    generatedAt: new Date().toISOString(),
    auditChain: chain,
    controls,
    posture: {
      patchCompliancePct: kpis.patchCompliancePct,
      openCriticalFindings: kpis.openCriticalFindings,
      overdueFindings: kpis.overdueFindings,
      mttdHours: kpis.mttdHours,
      mttrHours: kpis.mttrHours,
    },
    riskAcceptances: Object.fromEntries(acceptances.map((a) => [a.status, a._count._all])),
  });
});
