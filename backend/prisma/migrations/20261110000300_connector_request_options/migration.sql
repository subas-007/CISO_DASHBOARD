-- Administrator-defined, non-secret API parameters per connector.
ALTER TABLE "connectors" ADD COLUMN "requestOptions" JSONB NOT NULL DEFAULT '{}';
