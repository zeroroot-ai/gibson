# oscalgen

`oscalgen` writes the control list of the catalog Domain Pack `nist-800-53-r5` (gibson#766, ADR-0113).

## Source

| Item | Value |
|---|---|
| Publisher | National Institute of Standards and Technology (NIST) |
| Repository | `usnistgov/oscal-content`, release `v1.5.0` |
| Path | `nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json` |
| Content | SP 800-53 Rev 5.2.0 controls |
| SHA-256 of the uncompressed file | `01f37cf90ea99d92242c936cbfbdebcc338eef1f71454e2acac36cc56e9bc062` |

The file `NIST_SP-800-53_rev5_catalog.json.gz` is that file, compressed with `gzip -9 -n`. The tool checks the SHA-256 before it reads the file. It never downloads.

## Licence

The catalog is a work of the United States government. It is in the public domain in the United States (17 U.S.C. 105). The licence of this repository does not apply to it.

## Use

1. To regenerate the pack file, run `make nist-pack`.
2. To check that the committed pack file matches the catalog, run `make check-nist-pack`. The unit test `TestCommittedPackMatchesTheCatalog` runs the same check.
3. To change a mapping rule, edit `internal/engine/ontology/packs/nist-800-53-r5.rules.json`. A person writes that file. The tool never writes a rule.
4. To move to a new catalog release, replace the `.gz` file, update `CatalogSHA256` and this table, and increment `PackVersion` in `main.go`.

The pack holds each base control that the catalog does not mark as withdrawn. It does not hold control enhancements.
