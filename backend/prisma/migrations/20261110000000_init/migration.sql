-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "Role" AS ENUM ('ADMIN', 'CISO', 'SECOPS', 'PATCH_ADMIN', 'AUDITOR');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');

-- CreateEnum
CREATE TYPE "ConnectorCategory" AS ENUM ('SIEM', 'VULNERABILITY', 'PATCH', 'CHANGE', 'THREAT_INTEL');

-- CreateEnum
CREATE TYPE "AuthMode" AS ENUM ('NONE', 'API_KEY', 'BASIC', 'OAUTH2', 'MTLS');

-- CreateEnum
CREATE TYPE "ConnectorStatus" AS ENUM ('UNTESTED', 'HEALTHY', 'FAILED', 'DISABLED');

-- CreateEnum
CREATE TYPE "VulnStatus" AS ENUM ('OPEN', 'IN_PROGRESS', 'REMEDIATED', 'RISK_ACCEPTED', 'FALSE_POSITIVE');

-- CreateEnum
CREATE TYPE "IncidentStatus" AS ENUM ('NEW', 'TRIAGE', 'CONTAINED', 'RESOLVED', 'CLOSED');

-- CreateEnum
CREATE TYPE "ThreatType" AS ENUM ('CVE', 'RANSOMWARE', 'SUPPLY_CHAIN', 'ADVISORY', 'IOC');

-- CreateEnum
CREATE TYPE "ThreatStatus" AS ENUM ('NEW', 'TRIAGED', 'ACTIONED', 'DISMISSED');

-- CreateEnum
CREATE TYPE "RiskStatus" AS ENUM ('OPEN', 'MITIGATING', 'ACCEPTED', 'CLOSED');

-- CreateEnum
CREATE TYPE "AcceptanceStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'REVOKED');

-- CreateEnum
CREATE TYPE "KriDirection" AS ENUM ('HIGHER_IS_WORSE', 'LOWER_IS_WORSE');

-- CreateEnum
CREATE TYPE "RagStatus" AS ENUM ('GREEN', 'AMBER', 'RED');

-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL,
    "subject" TEXT NOT NULL,
    "emailEnc" TEXT,
    "emailIndex" TEXT,
    "displayName" TEXT NOT NULL,
    "roles" "Role"[],
    "active" BOOLEAN NOT NULL DEFAULT true,
    "lastLoginAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sessions" (
    "id" UUID NOT NULL,
    "userId" UUID NOT NULL,
    "familyId" UUID NOT NULL,
    "refreshHash" TEXT NOT NULL,
    "idpRefreshEnc" TEXT,
    "idTokenEnc" TEXT,
    "ip" TEXT,
    "userAgent" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "absoluteExpiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "revokeReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "connectors" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "vendor" TEXT NOT NULL,
    "category" "ConnectorCategory" NOT NULL,
    "baseUrl" TEXT NOT NULL,
    "authMode" "AuthMode" NOT NULL,
    "pollIntervalSec" INTEGER NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "settings" JSONB NOT NULL DEFAULT '{}',
    "secretEnc" TEXT,
    "status" "ConnectorStatus" NOT NULL DEFAULT 'UNTESTED',
    "lastTestAt" TIMESTAMP(3),
    "lastSyncAt" TIMESTAMP(3),
    "lastSuccessAt" TIMESTAMP(3),
    "lastError" TEXT,
    "lastRecordCount" INTEGER,
    "leaseUntil" TIMESTAMP(3),
    "createdById" UUID,
    "updatedById" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "connectors_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "assets" (
    "id" UUID NOT NULL,
    "hostname" TEXT NOT NULL,
    "ipAddress" TEXT,
    "os" TEXT,
    "businessUnit" TEXT NOT NULL DEFAULT 'Unassigned',
    "owner" TEXT,
    "criticality" INTEGER NOT NULL DEFAULT 3,
    "patchCompliant" BOOLEAN NOT NULL DEFAULT true,
    "missingPatches" INTEGER NOT NULL DEFAULT 0,
    "lastPatchedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "assets_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "vulnerabilities" (
    "id" UUID NOT NULL,
    "assetId" UUID NOT NULL,
    "source" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "cveId" TEXT,
    "title" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "cvss" DOUBLE PRECISION,
    "status" "VulnStatus" NOT NULL DEFAULT 'OPEN',
    "discoveredAt" TIMESTAMP(3) NOT NULL,
    "dueAt" TIMESTAMP(3),
    "remediatedAt" TIMESTAMP(3),
    "remediationNote" TEXT,
    "changeTicketId" UUID,
    "updatedById" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "vulnerabilities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "change_tickets" (
    "id" UUID NOT NULL,
    "system" TEXT NOT NULL,
    "externalKey" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "url" TEXT,
    "sourceUpdatedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "change_tickets_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "incidents" (
    "id" UUID NOT NULL,
    "source" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "descriptionEnc" TEXT,
    "severity" "Severity" NOT NULL,
    "status" "IncidentStatus" NOT NULL DEFAULT 'NEW',
    "category" TEXT NOT NULL DEFAULT 'General',
    "occurredAt" TIMESTAMP(3) NOT NULL,
    "detectedAt" TIMESTAMP(3) NOT NULL,
    "respondedAt" TIMESTAMP(3),
    "resolvedAt" TIMESTAMP(3),
    "assetsAffected" INTEGER NOT NULL DEFAULT 0,
    "createdById" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "incidents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "threat_items" (
    "id" UUID NOT NULL,
    "source" TEXT NOT NULL,
    "sourceRef" TEXT NOT NULL,
    "type" "ThreatType" NOT NULL,
    "title" TEXT NOT NULL,
    "summary" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "cveId" TEXT,
    "publishedAt" TIMESTAMP(3) NOT NULL,
    "impactedAssetCount" INTEGER NOT NULL DEFAULT 0,
    "tags" TEXT[],
    "status" "ThreatStatus" NOT NULL DEFAULT 'NEW',
    "triageNote" TEXT,
    "triagedById" UUID,
    "triagedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "threat_items_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "risks" (
    "id" UUID NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "likelihood" INTEGER NOT NULL,
    "impact" INTEGER NOT NULL,
    "ownerName" TEXT NOT NULL,
    "status" "RiskStatus" NOT NULL DEFAULT 'OPEN',
    "treatment" TEXT,
    "createdById" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "risks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "risk_assets" (
    "riskId" UUID NOT NULL,
    "assetId" UUID NOT NULL,

    CONSTRAINT "risk_assets_pkey" PRIMARY KEY ("riskId","assetId")
);

-- CreateTable
CREATE TABLE "risk_acceptances" (
    "id" UUID NOT NULL,
    "riskId" UUID NOT NULL,
    "justificationEnc" TEXT NOT NULL,
    "requestedById" UUID NOT NULL,
    "requestedByName" TEXT NOT NULL,
    "requestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "status" "AcceptanceStatus" NOT NULL DEFAULT 'PENDING',
    "decidedById" UUID,
    "decidedByName" TEXT,
    "decidedAt" TIMESTAMP(3),
    "decisionNote" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "risk_acceptances_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "kri_definitions" (
    "id" UUID NOT NULL,
    "key" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "metric" TEXT NOT NULL,
    "unit" TEXT NOT NULL,
    "direction" "KriDirection" NOT NULL,
    "amberThreshold" DOUBLE PRECISION NOT NULL,
    "redThreshold" DOUBLE PRECISION NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "updatedById" UUID,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "kri_definitions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "kri_breaches" (
    "id" UUID NOT NULL,
    "kriKey" TEXT NOT NULL,
    "level" "RagStatus" NOT NULL,
    "value" DOUBLE PRECISION NOT NULL,
    "threshold" DOUBLE PRECISION NOT NULL,
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "acknowledgedAt" TIMESTAMP(3),
    "acknowledgedById" UUID,

    CONSTRAINT "kri_breaches_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "metric_snapshots" (
    "id" BIGSERIAL NOT NULL,
    "metric" TEXT NOT NULL,
    "value" DOUBLE PRECISION NOT NULL,
    "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "metric_snapshots_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "system_settings" (
    "key" TEXT NOT NULL,
    "value" JSONB NOT NULL,
    "updatedById" UUID,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "system_settings_pkey" PRIMARY KEY ("key")
);

-- CreateTable
CREATE TABLE "audit_log" (
    "id" BIGSERIAL NOT NULL,
    "ts" TIMESTAMPTZ(3) NOT NULL,
    "actorId" TEXT,
    "actorName" TEXT,
    "actorRoles" TEXT[],
    "action" TEXT NOT NULL,
    "targetType" TEXT,
    "targetId" TEXT,
    "outcome" TEXT NOT NULL,
    "ip" TEXT,
    "userAgent" TEXT,
    "details" JSONB NOT NULL,
    "prevHash" TEXT NOT NULL,
    "hash" TEXT NOT NULL,

    CONSTRAINT "audit_log_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_subject_key" ON "users"("subject");

-- CreateIndex
CREATE UNIQUE INDEX "users_emailIndex_key" ON "users"("emailIndex");

-- CreateIndex
CREATE UNIQUE INDEX "sessions_refreshHash_key" ON "sessions"("refreshHash");

-- CreateIndex
CREATE INDEX "sessions_userId_idx" ON "sessions"("userId");

-- CreateIndex
CREATE INDEX "sessions_familyId_idx" ON "sessions"("familyId");

-- CreateIndex
CREATE UNIQUE INDEX "connectors_name_key" ON "connectors"("name");

-- CreateIndex
CREATE UNIQUE INDEX "assets_hostname_key" ON "assets"("hostname");

-- CreateIndex
CREATE INDEX "assets_businessUnit_idx" ON "assets"("businessUnit");

-- CreateIndex
CREATE INDEX "vulnerabilities_status_severity_idx" ON "vulnerabilities"("status", "severity");

-- CreateIndex
CREATE INDEX "vulnerabilities_cveId_idx" ON "vulnerabilities"("cveId");

-- CreateIndex
CREATE INDEX "vulnerabilities_assetId_idx" ON "vulnerabilities"("assetId");

-- CreateIndex
CREATE UNIQUE INDEX "vulnerabilities_source_externalId_key" ON "vulnerabilities"("source", "externalId");

-- CreateIndex
CREATE UNIQUE INDEX "change_tickets_system_externalKey_key" ON "change_tickets"("system", "externalKey");

-- CreateIndex
CREATE INDEX "incidents_detectedAt_idx" ON "incidents"("detectedAt");

-- CreateIndex
CREATE INDEX "incidents_status_idx" ON "incidents"("status");

-- CreateIndex
CREATE UNIQUE INDEX "incidents_source_externalId_key" ON "incidents"("source", "externalId");

-- CreateIndex
CREATE INDEX "threat_items_publishedAt_idx" ON "threat_items"("publishedAt");

-- CreateIndex
CREATE INDEX "threat_items_type_severity_idx" ON "threat_items"("type", "severity");

-- CreateIndex
CREATE INDEX "threat_items_cveId_idx" ON "threat_items"("cveId");

-- CreateIndex
CREATE UNIQUE INDEX "threat_items_source_sourceRef_key" ON "threat_items"("source", "sourceRef");

-- CreateIndex
CREATE INDEX "risks_likelihood_impact_idx" ON "risks"("likelihood", "impact");

-- CreateIndex
CREATE INDEX "risk_acceptances_status_idx" ON "risk_acceptances"("status");

-- CreateIndex
CREATE UNIQUE INDEX "kri_definitions_key_key" ON "kri_definitions"("key");

-- CreateIndex
CREATE INDEX "kri_breaches_kriKey_detectedAt_idx" ON "kri_breaches"("kriKey", "detectedAt");

-- CreateIndex
CREATE INDEX "metric_snapshots_metric_capturedAt_idx" ON "metric_snapshots"("metric", "capturedAt");

-- CreateIndex
CREATE UNIQUE INDEX "audit_log_hash_key" ON "audit_log"("hash");

-- CreateIndex
CREATE INDEX "audit_log_ts_idx" ON "audit_log"("ts");

-- CreateIndex
CREATE INDEX "audit_log_action_idx" ON "audit_log"("action");

-- CreateIndex
CREATE INDEX "audit_log_actorId_idx" ON "audit_log"("actorId");

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "vulnerabilities" ADD CONSTRAINT "vulnerabilities_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "vulnerabilities" ADD CONSTRAINT "vulnerabilities_changeTicketId_fkey" FOREIGN KEY ("changeTicketId") REFERENCES "change_tickets"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_assets" ADD CONSTRAINT "risk_assets_riskId_fkey" FOREIGN KEY ("riskId") REFERENCES "risks"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_assets" ADD CONSTRAINT "risk_assets_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "assets"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_acceptances" ADD CONSTRAINT "risk_acceptances_riskId_fkey" FOREIGN KEY ("riskId") REFERENCES "risks"("id") ON DELETE CASCADE ON UPDATE CASCADE;

