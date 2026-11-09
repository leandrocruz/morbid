-- Adds a nullable, partially-unique `identifier` column to accounts (e.g. CPF/CNPJ).
-- Also drops the (tenant, name) uniqueness; the business unique key is now `identifier`.
--
-- Idempotent: each statement guards on existence so re-runs are safe.

BEGIN;

ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS identifier VARCHAR(256);

ALTER TABLE accounts
    DROP CONSTRAINT IF EXISTS accounts_tenant_name_key;

CREATE UNIQUE INDEX IF NOT EXISTS accounts_identifier_key
    ON accounts (identifier)
    WHERE identifier IS NOT NULL;

COMMIT;
