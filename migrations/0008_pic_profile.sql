-- PIC profile versioning — spec.md §15 open question #11.
--
-- Pin a `pic_profile` string on every persisted PCA so the verifier can
-- detect spec evolution. Today every row gets `proxilion.v1`. When the
-- upstream PIC spec adds a new field shape we'd bump to `proxilion.v2`,
-- and the verifier could reject mismatched profiles instead of silently
-- accepting a CBOR shape it doesn't understand.

ALTER TABLE pca_cache
    ADD COLUMN IF NOT EXISTS pic_profile TEXT NOT NULL DEFAULT 'proxilion.v1';

-- All historical rows backfill to v1 via the DEFAULT.
