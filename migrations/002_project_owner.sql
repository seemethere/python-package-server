-- First uploader owns a project; only the owner may publish further files.
-- Nullable so pre-existing projects start ownerless and are claimed by
-- their next uploader (see MetadataStore::claim_project).
ALTER TABLE projects ADD COLUMN IF NOT EXISTS owner TEXT;
