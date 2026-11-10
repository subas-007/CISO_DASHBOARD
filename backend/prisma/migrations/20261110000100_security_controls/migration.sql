-- =====================================================================
-- Security controls (NIST SP 800-53 AU-9, PCI DSS v4.0.1 Req. 10.3.2)
-- =====================================================================

-- 1. Append-only audit log: block UPDATE / DELETE / TRUNCATE for every role,
--    including the table owner. Tampering would also break the HMAC hash chain.
CREATE OR REPLACE FUNCTION audit_log_block_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only: % is not permitted', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS audit_log_no_update_delete ON "audit_log";
CREATE TRIGGER audit_log_no_update_delete
  BEFORE UPDATE OR DELETE ON "audit_log"
  FOR EACH ROW EXECUTE FUNCTION audit_log_block_mutation();

DROP TRIGGER IF EXISTS audit_log_no_truncate ON "audit_log";
CREATE TRIGGER audit_log_no_truncate
  BEFORE TRUNCATE ON "audit_log"
  FOR EACH STATEMENT EXECUTE FUNCTION audit_log_block_mutation();

-- 2. Domain integrity constraints (defence in depth beyond API validation)
ALTER TABLE "risks" ADD CONSTRAINT risks_likelihood_range CHECK ("likelihood" BETWEEN 1 AND 5);
ALTER TABLE "risks" ADD CONSTRAINT risks_impact_range CHECK ("impact" BETWEEN 1 AND 5);
ALTER TABLE "assets" ADD CONSTRAINT assets_criticality_range CHECK ("criticality" BETWEEN 1 AND 5);
ALTER TABLE "connectors" ADD CONSTRAINT connectors_poll_interval CHECK ("pollIntervalSec" BETWEEN 60 AND 86400);
ALTER TABLE "audit_log" ADD CONSTRAINT audit_log_outcome CHECK ("outcome" IN ('SUCCESS', 'FAILURE', 'DENIED'));

-- 3. Least-privilege runtime role. The API connects as "ciso_app" (created by the
--    database bootstrap script) which has DML only — no DDL, and no ability to
--    modify or delete audit records.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ciso_app') THEN
    GRANT USAGE ON SCHEMA public TO ciso_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ciso_app;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ciso_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON "audit_log" FROM ciso_app;
    REVOKE ALL ON "_prisma_migrations" FROM ciso_app;
    EXECUTE format(
      'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ciso_app',
      current_user);
    EXECUTE format(
      'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO ciso_app',
      current_user);
  END IF;
END
$$;
