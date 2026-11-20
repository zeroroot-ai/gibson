# d3fendgen

`d3fendgen` writes the catalog Domain Pack `mitre-d3fend` (gibson#1484, ADR-0133).

The pack holds taxonomy and ontology only. It has the `Countermeasure` label, the countermeasure hierarchy (tactic, then technique), and the ATT&CK techniques that each countermeasure counters. It holds no predicate.

## Source

| Item | Value |
|---|---|
| Publisher | The MITRE Corporation |
| Release | D3FEND ontology `1.6.0` (released 2026-08-31) |
| Ontology | `https://d3fend.mitre.org/ontologies/d3fend.json` |
| ATT&CK mapping | `https://d3fend.mitre.org/api/offensive-technique/attack/<technique id>.json` |
| SHA-256 of the ontology file | `e1546d432c6aa64d45b62dd9e9484b0774ae84de7ff3605ff9dd4e20278957bf` |

The file `d3fend-extract.json.gz` is the extract that `fetch.py` wrote from that release. It holds only the facts that the pack needs. The tool checks the SHA-256 of the uncompressed extract before it reads it. It never downloads.

The mapping of a countermeasure to an ATT&CK technique is the official mapping that the D3FEND API returns for that technique. The extract holds the ATT&CK enterprise techniques (and sub-techniques) of the release that the ontology does not mark as deprecated.

## License

The ontology states the license `MIT` (`dcterms:license`). The ontology also says that its use is subject to the D3FEND Terms of Use, and that D3FEND is a trademark of The MITRE Corporation. The pack records the release, the URL and the license in its `source` field. The license of this repository does not apply to the D3FEND data.

## Use

1. To regenerate the pack file, run `make d3fend-pack`.
2. To check that the committed pack file matches the extract, run `make check-d3fend-pack`. The unit test `TestCommittedPackMatchesTheExtract` runs the same check.
3. To move to a new D3FEND release, make an empty directory and run `python3 -I tools/d3fendgen/fetch.py <empty dir> <extract file>`. The run takes about 15 minutes.
4. Compress the extract with `gzip -9 -n`, replace `d3fend-extract.json.gz`, update `ExtractSHA256` in `main.go` and the table above, and increment `PackVersion`.
