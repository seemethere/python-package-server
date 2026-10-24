-- PEP 592 yank support: yanked files stay downloadable by direct URL but
-- installers skip them unless the exact version is pinned.
ALTER TABLE files ADD COLUMN IF NOT EXISTS yanked BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE files ADD COLUMN IF NOT EXISTS yank_reason TEXT;
