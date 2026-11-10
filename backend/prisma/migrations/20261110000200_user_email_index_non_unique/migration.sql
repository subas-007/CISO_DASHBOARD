-- Identity is the OIDC subject. A user re-provisioned in the IdP receives a new `sub`
-- but may keep the same email, so the email blind index must not be unique.
DROP INDEX IF EXISTS "users_emailIndex_key";
CREATE INDEX IF NOT EXISTS "users_emailIndex_idx" ON "users"("emailIndex");
