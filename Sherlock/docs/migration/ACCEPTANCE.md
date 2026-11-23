# Migration acceptance: ISB-Sherlock-Dataset on ramius

Session 1, 2026-11-23. Read-only on the dataset: nothing was written under `ISB_DATA`.
Machine output is in `ISB_WORK/reports/migration/`; the scripts are in
`scripts/migration/` (standard library only, re-runnable).

**Status: ready for brownie's acceptance**, with one action (permissions, §2) and the
open items in §7. Every count reconciles exactly, both with DATASET_STRUCTURE.md and
with the dashboard's manifest run 278.

## 1. Roots

| Root | Path on ramius |
|---|---|
| `ISB_DATA` | `/home/soumya/IntelligentSelectionBlock/ISB-Sherlock-Data` |
| `ISB_ZIPS` | `/home/soumya/IntelligentSelectionBlock/Data` (retired 2026-11-23; see below) |
| `ISB_WORK` | `/home/soumya/IntelligentSelectionBlock/ISB-Sherlock-Work` |
| `ISB_SCRATCH` | `/home/soumya/IntelligentSelectionBlock/ISB-Sherlock-Scratch` |

Recorded in `config/roots.yaml` (gitignored).

## 2. Extraction and verification

The starter prompt assumed the archives were already extracted and verified; they
weren't (the dataset arrived as the 113 archives only). Extraction ran in session 1:

- Job **58347** (`scripts/slurm/verify_destination.sbatch`, which runs the archive
  folder's `verify_destination.sh` unchanged), node n26, 2026-11-23 03:55–05:30 UTC,
  1 h 35 min, `COMPLETED 0:0`.
- Log: `ISB_WORK/reports/migration/verify_destination-58347.out`. It ends with
  `DESTINATION VERIFIED` and `status=0`.
  - [1/3] all 113 archive checksums OK.
  - [2/3] 113 archives extracted, each member count equal to `plan.json`
    (118,269 members: 117,999 samples + 270 metadata files).
  - [3/3] 113 lists, **117,999 samples hashed, 0 mismatches**.

**Permissions: not yet read-only.** `malware/` and `goodware/` are writable (118,382
directories and files have a write bit). brownie, please run
(DATASET_STRUCTURE.md §7 step 5):

```bash
chmod -R a-w,o-rwx /home/soumya/IntelligentSelectionBlock/ISB-Sherlock-Data/malware \
                   /home/soumya/IntelligentSelectionBlock/ISB-Sherlock-Data/goodware
```

`metadata/` is left writable by that line. I'd also make it read-only, since the
checkpoint `manifest.sqlite` must stay untouched; your call.

**Archives deleted (2026-11-23, brownie's decision).** After verification, the 113
archives and their `.sha256` files (231,410,257,408 bytes) were removed from
`ISB_ZIPS`, by name from `plan.json`. Their checksums are kept in
`ISB_WORK/reports/migration/archives.sha256` and the names in `archive_names.txt`.
Later the same day the rest of the archive folder was removed too: the two verify
scripts went to `scripts/migration/`, and every other file (131, hash-verified, 18 MB:
`lists/`, `plan.json`, `family_index.csv`, the final `DATASET_STRUCTURE.md`, README,
`dataset_structure.json`) to `ISB_WORK/reports/migration/source/`, checksums in
`source_files.sha256`. `ISB_ZIPS` is retired on this cluster. `ISB_DATA` is now the
only copy of the dataset here (see §7).

## 3. Dataset counts (`acceptance_counts.json`)

| Check | Result |
|---|---|
| Sample files on disk (`malware/`, `goodware/`) | 117,999, all named `<sha256>.bin`; no other files |
| Rows in `metadata/sherlock_manifest.csv` | 117,999, 117,999 unique sha256 |
| Rows whose `dataset_path` doesn't exist | **0** |
| Files on disk with no manifest row | **0** |
| Rows whose path name ≠ `<sha256>.bin` | 0 |
| Folders where disk count ≠ manifest `folder` count | **0** of 25 + 355 family folders |
| Seeded hash sample (seed 20261123, 1,000 files) | **0 mismatches** (all 117,999 were also hashed by job 58347) |

Against DATASET_STRUCTURE.md §1–4, every figure matches:

| | Dataset doc | Disk = manifest |
|---|---:|---:|
| Malware | 95,718 | 95,718 |
| Family folders / files | 355 / 18,018 | 355 / 18,018 |
| Family sizes ≥100 / 40–99 / 20–39 / 10–19 / 1–9 | 38 / 277 / 1 / 2 / 37 | 38 / 277 / 1 / 2 / 37 |
| `_pool_conflicts` | 17 | 17 |
| `_unlabelled` (12 collections) | 77,683 | 77,683, each collection equal |
| Goodware (12 sources) | 22,281 | 22,281, each source equal |
| `folder_basis` (6 values) | as §3 | equal |
| Per family: `n_samples` and `n_motif_tierA` vs `family_index.csv` | 355 rows | 355 folders, 0 mismatches; Tier A 155 = 155 |
| Flags: `archive_member` / `any_softonic` / `selfpacked_child` / `oversized_uninventoried` / `pool_conflict` | 13,760 / 788 / 100 / 85 / 17 | equal |

Kinds: malware PE 69,780, .NET 8,259, ELF 15, archive 500, other 17,117,
uninventoried 47; goodware PE 20,189, .NET 575, ELF 1,470, other 9,
uninventoried 38.

## 4. Reconciliation with the dashboard (manifest run 278) (`reconcile_run278.json`)

The dashboard's 117,944 is the `files` table of the checkpoint `manifest.sqlite`
(117,944 rows; 95,701 malware, 22,243 goodware; `runs` has 278 rows). sha256 by sha256:

```
dataset 117,999 = run 278 117,944 + 85 only in the dataset − 30 only in run 278
malware  95,718 = 95,701 + 47 − 30
goodware 22,281 = 22,243 + 38 − 0
```

- **+85 only in the dataset:** the `oversized_uninventoried` files (47 malware, all
  `vault_bb`; 38 goodware: 17 sourceforge, 11 softonic, 10 cnet). They were too large
  for the inventory, so run 278 never saw them. The organiser hashed them at build
  time, and all 85 match V1's hashes (`v1_crosscheck = match`). They have
  `kind = uninventoried` and no TLSH digest.
- **−30 only in run 278:** 30 MalwareBazaar **export files** (`bazaar_full.csv`,
  `dataset_manifest.csv`, `*_summary.json`, `collection_status.json`) that the
  inventory picked up from the bazaar run folders and counted as malware of kind
  `other`. They aren't samples. 18 still had paths and were migrated as metadata: all
  18 are under `metadata/source_metadata/`, matched by sha256. 12 have no row in
  `file_paths` (`summary.json`: 117,932 hashes with paths), i.e. superseded versions.
  These are README_MIGRATION's "12 manifest rows without an on-disk path": they are
  rows in the DB, not in `sherlock_manifest.csv`.
- **The 17 pool conflicts are not the difference.** All 17 are in run 278 too, in the
  malware pool (and in both counts here). That malware differs by exactly 17 is a
  coincidence (+47 − 30). The claim was in the starter prompt and DIRECTORY_MAP.md §3
  (now corrected); the snapshot doesn't make it, and I can't see whether the live
  dashboard does.

The snapshot's other figures, recomputed from the CSV:

| Snapshot figure | Snapshot | Recomputed | Note |
|---|---:|---:|---|
| Goodware: PE / .NET / ELF / non-exe | 20,189 / 575 / 1,470 / 9 | same | the 38 uninventoried are the whole gap |
| Malware: PE / .NET / ELF | 69,780 / 8,259 / 15 | same | |
| Malware non-exe | 17,647 | 17,617 + 30 export files | archive 500 + other 17,117 |
| Goodware origins (exe): ucsb / win8 / sourceforge / cnet / softonic / winget / selfpacked | 15,029 / 2,868 / 1,062 / 836 / 777 / 151 / 100 | same | counted by `origins` membership, so a file in two sources counts in both; folder counts differ (e.g. softonic folder 758, flag 788) |
| Linux goodware (Ubuntu 26.04/26.10, Debian 13) | 1,470 | 1,470 unique ELF | by membership the five origins sum to 1,708 (packages shared between releases) |
| Malware origins: vault_bb / ucsb / ucsb_jp / stefano / codexgiga / mlsec+apts+evasive_it | 46,451 / 13,367 / 6,521 / 5,698 / 5,395 / 811 | same | by membership; folders differ because MB-labelled samples sit in family folders |
| Bazaar runs 5 / 4 / 1 / 2 / 3 / report-linked | 11,082 / 4,549 / 1,903 / 1,903 / 304 / 42 | 11,076 / 4,547 / 1,900 / 1,900 / 302 / 40 | each excess is that run's export files (6, 2, 3, 3, 2, 2 = 18) |
| Tier X executables (runs I–V) | 17,845 | 17,845 | 17,865 in all: the other 20 come only from `bazaar_report_linked` |
| Tier X families: n / ≥10 / ≥20 / ≥40 / ≥80 | 315 / 315 / 315 / 301 / 38 | same | runs I–V only; with report-linked: 318 / 315 / 315 / 305 / 38 |
| Tier A: samples / families / ≥10 / ≥20 / ≥40 | 155 / 54 / 4 / 1 / 0 | same | |

DATASET_STRUCTURE.md's folder-size buckets (≥40: 315) count all files in a folder,
including report-linked and MOTIF-only samples; the snapshot's (≥40: 301) count
runs I–V executables. Both are right; they measure different things.

**Nothing is left unexplained.**

## 5. Working manifest

| | |
|---|---|
| Original | `ISB_DATA/metadata/project_state/ISB-Corpus-Update/data/manifest.sqlite`, 289,550,336 bytes, no `-wal`/`-shm` beside it |
| sha256 | `14ae5180bafe1616e20803be91d2265ac9f0f5797d5781830b9603e948c83a5a` |
| Working copy | `ISB_WORK/manifest/manifest.sqlite` (copy verified against the hash) |
| Hash record | `ISB_WORK/manifest/CHECKPOINT.sha256` (made read-only) |

Tables (row counts on the working copy, opened `mode=ro`):

| Table | Rows | | Table | Rows |
|---|---:|---|---|---:|
| `archive_extractions` | 306 | | `labels` | 155 |
| `archive_members` | 14,197 | | `packed_from` | 100 |
| `elf_meta` | 1,485 | | `packer_tags` | 199,191 |
| `errors` | 2,159 | | `pe_meta` | 98,803 |
| `family_alias_edges` | 8,810 | | `rule_refs` | 52,682 |
| `family_groups` | 12,995 | | `rule_string_hits` | 626 |
| `file_paths` | 133,664 | | `runs` | 278 |
| `files` | 117,944 | | `tlsh_clusters` | 465 |
| `goodware_meta` | 41,271 | | | |

`file_paths`: all 133,664 rows are old-cluster paths under `/home/soumya/corpus/...`,
covering 117,932 distinct sha256. Code joins on `sha256` and never reads `path`.

Enrichment readiness from the CSV: every Tier X executable (17,865) has a TLSH
digest and an `mb_first_seen` date. The rows without TLSH are 689 `other`,
85 `uninventoried` and 1 `archive`.

## 6. `metadata/project_state/`

244 files, 479 MB. The **TO CONFIRM** rows of DIRECTORY_MAP.md are filled in:

- `ISB-Corpus-Update/data/manifest.sqlite`: the checkpoint DB (§5).
- `ISB-Corpus-Update/reports/`: 48 report files plus `die_probe/` (alias review CSVs
  and JSON, pool conflicts and evidence, coverage reports up to run 278's
  `coverage_2026-10-25.md`, sizing, NSRL, bazaar and goodware-expansion state, and
  `rule_string_pilot.json`: run 152, 50 rules, 581 strings, 108 files; its hits are
  the DB's 626-row `rule_string_hits`).
- `ISB-Corpus-Update/yaragen-dataset-kit/`: the dataset kit (`dskit/`, tests, config,
  `sources.lock.yaml`) with `PLAN.md`, `PROGRESS.md`, `LABEL_PROVENANCE_PLAN.md`,
  `GOODWARE_EXPANSION_PLAN.md`. Kit rules 7 (Softonic) and 8 (Tier X) are the
  numbered safety rules in its `CLAUDE.md`.
- `ISB-Corpus-Update/scratch/`: alias sources, goodware-expansion state including
  `goodware_expansion/2026-10-23/collection_state.json` (320 receipts, each with the
  package URL and sha256),
  bazaar candidate reviews, winget TSVs, schemas.
- `ISB-Corpus-Update/STATUS.md`, `ISB-Corpus-Update/bazaar/` (run V collector and logs).
- `ISB-Current-Corpus/_manifest/`: V1's **corpus** manifest (`corpus_manifest.csv`,
  `corpus_summary.json`, `duplicates.csv`, `cross_label_collisions.csv`). This is not
  V1's experiment split; see §7.
- `ISB/ISB_DATASET_REVIEW_2026-11-22.md`: the dataset library review.

## 7. Differences and open items

1. **Permissions** (§2): brownie to run the `chmod` line; decide on `metadata/`.
   Rechecked after the archives were deleted: still writable (118,382 under
   `malware/` and `goodware/`, 312 under `metadata/`).
1a. **No second copy.** With the archives gone, `ISB_DATA` is the only copy on this
   cluster. A backup (or confirmation that the old cluster's copy is kept) is open.
2. **Stale repo copy of DATASET_STRUCTURE.md.** `docs/dataset/` holds the 16:42
   version (108/113 archives complete, 218.8 GB, five archives "pending"); the
   archive folder had the final 16:47 version (113/113, 231.4 GB), now kept in
   `ISB_WORK/reports/migration/source/`. Sample counts are identical. The repo copy is
   read-only (`r--r--r--`), so it wasn't replaced; your call whether to.
3. **"The malware difference equals the 17 pool conflicts" is wrong** (§4). It was in
   the starter prompt and DIRECTORY_MAP.md §3 (corrected in this session; please
   review that edit). If the live dashboard says it too, §4 is the replacement.
4. **README_MIGRATION.md's "12 manifest rows without an on-disk path"** are rows of
   the DB `files` table, not of `sherlock_manifest.csv` (§4).
5. **The 85 uninventoried files** have no `kind`, no TLSH and no row in `files`,
   `pe_meta`, `elf_meta`, `packer_tags`, `goodware_meta` or `labels`. None is Tier X (47 are unlabelled `vault_bb`, 38 are goodware, 11 of
   them Softonic), so W1's done-when criterion isn't affected, but the 27 non-Softonic
   goodware files are cnet and sourceforge installers that G_stats could use. They
   need an inventory pass (static only) before G1.
6. **V1's experiment split is not on this cluster.** `_manifest/` is V1's corpus
   manifest; `splits/malware_split.json` (D2's 38-family assignment) and
   `goodware_split.json` were not migrated (DIRECTORY_MAP.md §7). This matters for G0
   (parity fixtures) and G2; the G0 note will cover it.
7. **The starter prompt's precondition** (archives already verified and extracted)
   did not hold; extraction was done in this session (§2). P0 lost about two hours to
   it, with no effect on the plan.
8. **The CSV and the DB cover different hashes** (85 CSV-only, 30 DB-only, §4).
   `sherlock/data/manifest.py` must drive from `sherlock_manifest.csv` and treat a
   missing DB row as a recorded condition (`dropped[reason]`), not an error.
9. **`py-tlsh` is not on conda-forge.** `environment.yml` now installs it from PyPI
   (sdist, built with the system g++ 11.5); recorded in `environment.lock.yml`.
