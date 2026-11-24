# ISB-Sherlock-Dataset: structure and new-cluster setup

Checkpoint generated 2026-11-22 16:42 EST from `sherlock_manifest.csv` and `plan.json`.
At generation time, **108/113 archives were complete** (zip + `.sha256` present). The rest of this document assumes every archive finished. Re-run `make_structure_doc.py` to refresh sizes, and confirm all `.zip.sha256` files exist before transferring.

> **LIVE MALWARE.** Static analysis only. Never execute samples. Never upload samples or hashes to online services. Sample archives use the password `infected`; `metadata.zip` is unencrypted and contains no binaries.

## 1. At a glance

| | |
|---|---|
| Unique samples | **117,999** (344.8 GB uncompressed) |
| Malware | 95,718 files: 355 family folders, 77,683 unlabelled, 17 pool conflicts |
| Goodware | 22,281 files in 12 source folders |
| Metadata | 270 files (2.6 GB): manifest, source metadata, project state |
| Archives | 113 independent zips, each < 4 GiB (no ZIP64). Compressed so far: 218.8 GB |
| File naming | every sample is `<sha256>.bin`, so content can be checked against the name |

## 2. Directory tree

```
ISB-Sherlock-Dataset/
├── malware/
│   ├── <family>/<sha256>.bin            355 family folders, 18,018 files, 63.2 GB
│   ├── _pool_conflicts/                          17 files     0.1 GB
│   ├── _unlabelled/apts/                        179 files     0.1 GB
│   ├── _unlabelled/bb/                       32,821 files   111.5 GB
│   ├── _unlabelled/bb_archive_members/       13,633 files     0.1 GB
│   ├── _unlabelled/codexgiga/                 5,324 files     1.8 GB
│   ├── _unlabelled/evasive_it/                  146 files     1.1 GB
│   ├── _unlabelled/mlsec19/                      97 files     0.1 GB
│   ├── _unlabelled/mlsec20/                     172 files     0.1 GB
│   ├── _unlabelled/mlsec21/                     193 files     0.1 GB
│   ├── _unlabelled/report_linked/                14 files     0.0 GB
│   ├── _unlabelled/stefano/                   5,692 files    11.6 GB
│   ├── _unlabelled/ucsb/                     13,340 files     8.3 GB
│   ├── _unlabelled/ucsb_jp/                   6,072 files     4.2 GB
├── goodware/
│   ├── cnet/                                    837 files    38.5 GB
│   ├── debian_13/                               266 files     0.4 GB
│   ├── debian_13_security/                      299 files     0.5 GB
│   ├── selfpacked_upx/                          100 files     0.2 GB
│   ├── softonic/                                758 files    37.4 GB
│   ├── sourceforge/                           1,060 files    38.4 GB
│   ├── ubuntu_2604/                             433 files     0.4 GB
│   ├── ubuntu_2604_security/                    281 files     0.2 GB
│   ├── ubuntu_2610/                             191 files     0.4 GB
│   ├── ucsb/                                 15,029 files    21.9 GB
│   ├── win8/                                  2,867 files     1.5 GB
│   ├── winget/                                  160 files     2.6 GB
└── metadata/
    ├── sherlock_manifest.csv            one row per sample (schema in §6)
    ├── source_metadata/<bazaar_run>/    MalwareBazaar exports: bazaar_full.csv, dataset_manifest.csv, ... (first_seen dates)
    ├── build/                           original_paths.csv, not_migrated.csv, summary.json, organizer script
    └── project_state/                   manifest.sqlite, reports/, yaragen-dataset-kit/, V1 _manifest/, review report
```

## 3. Malware

**How folders were chosen** (`folder_basis` column):

| Basis | Files | Meaning |
|---|---:|---|
| `mb_signature_tierX` | 17,889 | MalwareBazaar `signature` (runs I–V folder; report-linked CSV). AV-derived, **Tier X**: not an evaluation label under the kit rules |
| `motif_tierA` | 129 | No MB family. MOTIF exact-hash label with report provenance, **Tier A** |
| `unlabelled` | 64,050 | Vault collection, no family label |
| `unlabelled_archive_member` | 13,633 | Extracted from a vault BB archive; `parent_sha256` gives the archive |
| `pool_conflict` | 17 | Same bytes recorded in both pools; unadjudicated |
| `goodware_source` | 22,281 | Goodware (§4) |

Family names are normalized to lowercase alphanumerics only (`Smoke_Loader` → `smokeloader`). **No alias merges were applied**; for example, `heodo` (Emotet) has its own folder. The alias review in `project_state/.../reports/alias_review_*.csv` is still pending.

**Family folder sizes:** ≥100: 38, 40–99: 277, 20–39: 1, 10–19: 2, 1–9: 37. The small folders are MOTIF-only and report-linked families. The full list is in `family_index.csv` (family, count, Tier A count, archives).

Largest 15 families:

| Family | Samples | Tier A (MOTIF) |
|---|---:|---:|
| agenttesla | 201 | 1 |
| formbook | 201 | 1 |
| arkeistealer | 200 | 0 |
| asyncrat | 200 | 0 |
| coinminer | 200 | 0 |
| nanocore | 200 | 0 |
| remcosrat | 200 | 0 |
| stealc | 200 | 0 |
| vidar | 200 | 0 |
| gandcrab | 176 | 1 |
| adwareneoreklami | 175 | 0 |
| amadey | 175 | 0 |
| avemariarat | 175 | 0 |
| cobaltstrike | 175 | 0 |
| dcrat | 175 | 0 |

Families with any Tier A sample: 54; Tier A samples in total: 155 (some sit in MB-family folders and carry both labels in the manifest).

## 4. Goodware

| Source folder | Files | GB | Kinds | Notes |
|---|---:|---:|---|---|
| cnet | 837 | 38.5 | pe 823, uninventoried 10, dotnet 4 | Installers |
| debian_13 | 266 | 0.4 | elf 266 | Linux packages (Ubuntu/Debian), ELF |
| debian_13_security | 299 | 0.5 | elf 299 | Linux packages (Ubuntu/Debian), ELF |
| selfpacked_upx | 100 | 0.2 | pe 100 | UPX-packed copies of goodware (`parent_sha256` = unpacked parent); packer ablation |
| softonic | 758 | 37.4 | pe 741, uninventoried 11, dotnet 6 | **Barred from paper splits** (kit rule 7); `any_softonic` flag |
| sourceforge | 1,060 | 38.4 | pe 976, dotnet 67, uninventoried 17 | Installers |
| ubuntu_2604 | 433 | 0.4 | elf 433 | Linux packages (Ubuntu/Debian), ELF |
| ubuntu_2604_security | 281 | 0.2 | elf 281 | Linux packages (Ubuntu/Debian), ELF |
| ubuntu_2610 | 191 | 0.4 | elf 191 | Linux packages (Ubuntu/Debian), ELF |
| ucsb | 15,029 | 21.9 | pe 14,623, dotnet 406 | UCSB goodware set |
| win8 | 2,867 | 1.5 | pe 2,841, dotnet 26 | Windows 8 RTM 6.2.9200 system files |
| winget | 160 | 2.6 | pe 85, dotnet 66, other 9 | Current Windows apps (pilot + 2026-10-23 expansion) |

NSRL/vendor evidence in the manifest DB is membership, not benign vetting. Linux ELF goodware has almost no ELF malware counterpart (15 files).

## 5. Archives → folders

| # | Archive | Files | Input GB | Zip GB | Level | Encrypted |
|---:|---|---:|---:|---:|---|---|
| 0 | `goodware_debian_13_01.zip` | 266 | 0.36 | 0.13 | -6 | yes |
| 1 | `goodware_debian_13_security_01.zip` | 299 | 0.46 | 0.16 | -6 | yes |
| 2 | `goodware_selfpacked_upx_01.zip` | 100 | 0.18 | 0.17 | -6 | yes |
| 3 | `goodware_ubuntu_2604_01.zip` | 433 | 0.41 | 0.15 | -6 | yes |
| 4 | `goodware_ubuntu_2604_security_01.zip` | 281 | 0.15 | 0.06 | -6 | yes |
| 5 | `goodware_ubuntu_2610_01.zip` | 191 | 0.43 | 0.16 | -6 | yes |
| 6 | `goodware_win8_01.zip` | 2,867 | 1.53 | 0.63 | -6 | yes |
| 7 | `goodware_winget_01.zip` | 160 | 2.61 | 2.43 | -1 | yes |
| 8 | `malware_pool_conflicts_01.zip` | 17 | 0.05 | 0.05 | -6 | yes |
| 9 | `malware_unlabelled_apts_01.zip` | 179 | 0.11 | 0.08 | -6 | yes |
| 10 | `malware_unlabelled_bb_03.zip` | 3,710 | 11.49 | 3.33 | -6 | yes |
| 11 | `malware_unlabelled_bb_archive_members_01.zip` | 13,633 | 0.10 | 0.06 | -6 | yes |
| 12 | `malware_unlabelled_codexgiga_01.zip` | 5,324 | 1.81 | 1.16 | -6 | yes |
| 13 | `malware_unlabelled_evasive_it_01.zip` | 146 | 1.12 | 0.27 | -6 | yes |
| 14 | `malware_unlabelled_mlsec19_01.zip` | 97 | 0.13 | 0.05 | -6 | yes |
| 15 | `malware_unlabelled_mlsec20_01.zip` | 172 | 0.10 | 0.05 | -6 | yes |
| 16 | `malware_unlabelled_mlsec21_01.zip` | 193 | 0.13 | 0.08 | -6 | yes |
| 17 | `malware_unlabelled_report_linked_01.zip` | 14 | 0.02 | 0.02 | -6 | yes |
| 18 | `malware_unlabelled_ucsb_jp_01.zip` | 6,072 | 4.23 | 2.99 | -6 | yes |
| 19 | `metadata.zip` | 270 | 2.65 | 1.05 | -6 | no |
| 20 | `goodware_cnet_01.zip` | 66 | 2.33 | 2.31 | -1 | yes |
| 21 | `goodware_cnet_02.zip` | 67 | 3.74 | 3.72 | -1 | yes |
| 22 | `goodware_cnet_03.zip` | 91 | 3.78 | 3.75 | -1 | yes |
| 23 | `goodware_cnet_04.zip` | 106 | 3.80 | 3.77 | -1 | yes |
| 24 | `goodware_cnet_05.zip` | 100 | 3.79 | 3.76 | -1 | yes |
| 25 | `goodware_cnet_06.zip` | 47 | 3.51 | 3.48 | -1 | yes |
| 26 | `goodware_cnet_07.zip` | 55 | 2.49 | 2.42 | -1 | yes |
| 27 | `goodware_cnet_08.zip` | 30 | 3.79 | 3.77 | -1 | yes |
| 28 | `goodware_cnet_09.zip` | 115 | 3.43 | 3.39 | -1 | yes |
| 29 | `goodware_cnet_10.zip` | 79 | 3.79 | 3.74 | -1 | yes |
| 30 | `goodware_cnet_11.zip` | 60 | 3.72 | 3.70 | -1 | yes |
| 31 | `goodware_cnet_12.zip` | 21 | 0.36 | 0.35 | -1 | yes |
| 32 | `goodware_softonic_01.zip` | 5 | 0.05 | 0.05 | -1 | yes |
| 33 | `goodware_softonic_02.zip` | 4 | 3.79 | 3.79 | -1 | yes |
| 34 | `goodware_softonic_03.zip` | 75 | 3.28 | 3.25 | -1 | yes |
| 35 | `goodware_softonic_04.zip` | 133 | 3.69 | 3.63 | -1 | yes |
| 36 | `goodware_softonic_05.zip` | 85 | 3.70 | 3.67 | -1 | yes |
| 37 | `goodware_softonic_06.zip` | 51 | 3.65 | 3.64 | -1 | yes |
| 38 | `goodware_softonic_07.zip` | 88 | 3.59 | 3.56 | -1 | yes |
| 39 | `goodware_softonic_08.zip` | 103 | 3.51 | 3.45 | -1 | yes |
| 40 | `goodware_softonic_09.zip` | 58 | 1.59 | 1.57 | -1 | yes |
| 41 | `goodware_softonic_10.zip` | 60 | 3.80 | 3.79 | -1 | yes |
| 42 | `goodware_softonic_11.zip` | 28 | 0.75 | 0.74 | -1 | yes |
| 43 | `goodware_softonic_12.zip` | 1 | 3.99 | 3.98 | -1 | yes |
| 44 | `goodware_softonic_13.zip` | 67 | 1.99 | 1.97 | -1 | yes |
| 45 | `goodware_sourceforge_01.zip` | 146 | 3.77 | 3.74 | -1 | yes |
| 46 | `goodware_sourceforge_02.zip` | 89 | 3.80 | 3.72 | -1 | yes |
| 47 | `goodware_sourceforge_03.zip` | 193 | 3.74 | 3.68 | -1 | yes |
| 48 | `goodware_sourceforge_04.zip` | 85 | 3.31 | 3.26 | -1 | yes |
| 49 | `goodware_sourceforge_05.zip` | 62 | 3.74 | 3.73 | -1 | yes |
| 50 | `goodware_sourceforge_06.zip` | 58 | 2.94 | 2.92 | -1 | yes |
| 51 | `goodware_sourceforge_07.zip` | 96 | 3.78 | 3.73 | -1 | yes |
| 52 | `goodware_sourceforge_08.zip` | 125 | 3.79 | 3.76 | -1 | yes |
| 53 | `goodware_sourceforge_09.zip` | 70 | 3.71 | 3.67 | -1 | yes |
| 54 | `goodware_sourceforge_10.zip` | 90 | 3.70 | 3.64 | -1 | yes |
| 55 | `goodware_sourceforge_11.zip` | 46 | 2.08 | 2.01 | -1 | yes |
| 56 | `goodware_ucsb_01.zip` | 2,643 | 3.80 | 3.32 | -6 | yes |
| 57 | `goodware_ucsb_02.zip` | 2,644 | 3.80 | 3.36 | -6 | yes |
| 58 | `goodware_ucsb_03.zip` | 2,594 | 3.80 | 3.29 | -6 | yes |
| 59 | `goodware_ucsb_04.zip` | 2,534 | 3.80 | 3.38 | -6 | yes |
| 60 | `goodware_ucsb_05.zip` | 2,553 | 3.80 | 3.36 | -6 | yes |
| 61 | `goodware_ucsb_06.zip` | 2,061 | 2.95 | 2.62 | -6 | yes |
| 62 | `malware_families_01.zip` | 1,080 | 3.80 | 3.22 | -6 | yes |
| 63 | `malware_families_02.zip` | 1,457 | 3.80 | 2.62 | -6 | yes |
| 64 | `malware_families_03.zip` | 1,264 | 3.79 | 2.43 | -6 | yes |
| 65 | `malware_families_04.zip` | 1,099 | 3.79 | 3.11 | -6 | yes |
| 66 | `malware_families_05.zip` | 246 | 3.78 | 3.61 | -6 | yes |
| 67 | `malware_families_06.zip` | 1,204 | 3.78 | 2.86 | -6 | yes |
| 68 | `malware_families_07.zip` | 661 | 3.80 | 1.94 | -6 | yes |
| 69 | `malware_families_08.zip` | 1,984 | 3.80 | 2.45 | -6 | yes |
| 70 | `malware_families_09.zip` | 1,600 | 3.76 | 2.73 | -6 | yes |
| 71 | `malware_families_10.zip` | 467 | 3.75 | 1.92 | -6 | yes |
| 72 | `malware_families_11.zip` | 910 | 3.80 | 2.65 | -6 | yes |
| 73 | `malware_families_12.zip` | 1,396 | 3.73 | 2.80 | -6 | yes |
| 74 | `malware_families_13.zip` | 634 | 3.80 | 1.95 | -6 | yes |
| 75 | `malware_families_14.zip` | 398 | 3.77 | 2.58 | -6 | yes |
| 76 | `malware_families_15.zip` | 940 | 3.79 | 2.89 | -6 | yes |
| 77 | `malware_families_16.zip` | 1,542 | 3.80 | 2.49 | -6 | yes |
| 78 | `malware_families_17.zip` | 1,136 | 2.68 | 1.82 | -6 | yes |
| 79 | `malware_unlabelled_bb_04.zip` | 775 | 3.80 | 0.69 | -6 | yes |
| 80 | `malware_unlabelled_bb_05.zip` | 1,425 | 3.78 | 1.23 | -6 | yes |
| 81 | `malware_unlabelled_bb_06.zip` | 1,564 | 3.80 | 1.61 | -6 | yes |
| 82 | `malware_unlabelled_bb_07.zip` | 1,038 | 3.80 | 0.92 | -6 | yes |
| 83 | `malware_unlabelled_bb_08.zip` | 1,106 | 3.48 | 1.06 | -6 | yes |
| 84 | `malware_unlabelled_bb_09.zip` | 1,597 | 3.80 | 1.48 | -6 | yes |
| 85 | `malware_unlabelled_bb_10.zip` | 826 | 3.43 | 0.78 | -6 | yes |
| 86 | `malware_unlabelled_bb_11.zip` | 936 | 3.66 | 0.92 | -6 | yes |
| 87 | `malware_unlabelled_bb_12.zip` | 1,147 | 3.80 | 1.15 | -6 | yes |
| 88 | `malware_unlabelled_bb_13.zip` | 977 | 3.80 | 0.97 | -6 | yes |
| 89 | `malware_unlabelled_bb_14.zip` | 883 | 3.75 | 0.86 | -6 | yes |
| 90 | `malware_unlabelled_bb_15.zip` | 801 | 3.50 | 0.81 | -6 | yes |
| 91 | `malware_unlabelled_bb_16.zip` | 936 | 3.80 | 0.97 | -6 | yes |
| 92 | `malware_unlabelled_bb_17.zip` | 1,403 | 3.60 | 1.30 | -6 | yes |
| 93 | `malware_unlabelled_bb_18.zip` | 889 | 3.80 | 0.94 | -6 | yes |
| 94 | `malware_unlabelled_bb_19.zip` | 1,080 | 3.80 | 1.08 | -6 | yes |
| 95 | `malware_unlabelled_bb_20.zip` | 1,049 | 3.80 | 1.20 | -6 | yes |
| 96 | `malware_unlabelled_bb_21.zip` | 889 | 3.69 | 0.78 | -6 | yes |
| 97 | `malware_unlabelled_bb_22.zip` | 1,522 | 3.80 | 1.53 | -6 | yes |
| 98 | `malware_unlabelled_bb_23.zip` | 1,428 | 3.79 | 1.46 | -6 | yes |
| 99 | `malware_unlabelled_bb_24.zip` | 1,240 | 3.73 | 1.24 | -6 | yes |
| 100 | `malware_unlabelled_bb_25.zip` | 1,027 | 3.35 | 1.06 | -6 | yes |
| 101 | `malware_unlabelled_bb_26.zip` | 458 | 3.30 | 0.44 | -6 | yes |
| 102 | `malware_unlabelled_bb_27.zip` | 826 | 3.79 | 0.90 | -6 | yes |
| 103 | `malware_unlabelled_bb_28.zip` | 1,089 | 3.78 | 1.07 | -6 | yes |
| 104 | `malware_unlabelled_bb_29.zip` | 1,120 | 3.80 | 1.02 | -6 | yes |
| 105 | `malware_unlabelled_bb_30.zip` | 1,080 | 3.78 | 0.99 | -6 | yes |
| 106 | `malware_unlabelled_stefano_01.zip` | 1,811 | 3.80 | 0.00 (pending) | -6 | yes |
| 107 | `malware_unlabelled_stefano_02.zip` | 1,792 | 3.80 | 0.00 (pending) | -6 | yes |
| 108 | `malware_unlabelled_stefano_03.zip` | 1,973 | 3.79 | 0.00 (pending) | -6 | yes |
| 109 | `malware_unlabelled_stefano_04.zip` | 116 | 0.25 | 0.17 | -6 | yes |
| 110 | `malware_unlabelled_ucsb_01.zip` | 6,520 | 3.80 | 0.00 (pending) | -6 | yes |
| 111 | `malware_unlabelled_ucsb_02.zip` | 5,708 | 3.80 | 0.00 (pending) | -6 | yes |
| 112 | `malware_unlabelled_ucsb_03.zip` | 1,112 | 0.75 | 0.54 | -6 | yes |

The archive name prefix gives the folder: `malware_families_*` → `malware/<family>/`; `malware_unlabelled_<c>_*` → `malware/_unlabelled/<c>/`; `goodware_<s>_*` → `goodware/<s>/`; `metadata.zip` → `metadata/`. `lists/<archive>.lst` lists every member; `dataset_structure.json` holds the same data in machine-readable form.

## 6. `metadata/sherlock_manifest.csv` columns

| Column(s) | Meaning |
|---|---|
| `sha256, md5, sha1, tlsh` | Content hashes (TLSH empty where it can't be computed) |
| `dataset_path` | Path relative to the dataset root, e.g. `malware/agenttesla/<sha256>.bin` |
| `folder, folder_basis` | Containing folder and why it was chosen (§3) |
| `pool` | `malware` or `goodware` as recorded in the manifest DB |
| `kind` | `pe`, `dotnet`, `elf`, `archive`, `other`; `uninventoried` = oversized file hashed at build time |
| `size` | Bytes |
| `mb_family, mb_family_raw` | MalwareBazaar signature family (normalized / as published). Tier X |
| `mb_first_seen, mb_label_source` | MalwareBazaar first-seen timestamp (the only real first-seen date available) and label source |
| `motif_family, motif_family_raw, motif_tier` | MOTIF label (Tier A) where the exact hash is in MOTIF |
| `die_packed, die_packer` | Detect-It-Easy packer verdict and packer name |
| `origins, n_paths` | Every collection the bytes were found in, and the number of original paths |
| `flags` | `any_softonic`, `pool_conflict`, `archive_member`, `selfpacked_child`, `oversized_uninventoried` |
| `parent_sha256` | Archive the file was extracted from, or the unpacked parent of a UPX child |
| `v1_crosscheck` | For oversized files: `match` = hash equals V1's `corpus_manifest.csv` |

Flag counts: `archive_member` 13,760, `any_softonic` 788, `selfpacked_child` 100, `oversized_uninventoried` 85, `pool_conflict` 17.

`metadata/build/original_paths.csv` maps every sample to every path it had on the old cluster, for provenance; those paths are dead on the new cluster. `project_state/ISB-Corpus-Update/data/manifest.sqlite` is the full manifest DB (PE/ELF metadata, packer tags, labels, alias graph, rule joins). Its `file_paths` table still holds old-cluster absolute paths, so join on `sha256` instead.

## 7. Setting up on the new cluster

1. **Before transfer, on the old cluster:** confirm all archives finished:
   ```bash
   cd ISB-Sherlock-Dataset-zips && ls *.zip.sha256 | wc -l   # expect 113
   ls *.tmp 2>/dev/null                                      # expect nothing
   ```
2. **Transfer the whole `ISB-Sherlock-Dataset-zips/` directory:** `*.zip`, `*.zip.sha256`, `plan.json`, `lists/`, `verify_names.py`, `verify_destination.sh`, this file, `family_index.csv`, `dataset_structure.json`, `README_MIGRATION.md`. For example: `rsync -a --partial --info=progress2 ISB-Sherlock-Dataset-zips/ newhost:/path/ISB-Sherlock-Dataset-zips/`.
3. **Make sure no on-access scanner deletes files** in the destination directory before extraction (that is why the archives are encrypted). Confirm any institutional malware-handling approval for the new system.
4. **Verify and extract** (needs only `bash`, `sha256sum`, `unzip` and `python3`; no third-party packages):
   ```bash
   bash verify_destination.sh /path/ISB-Sherlock-Dataset-zips /path/ISB-Sherlock-Dataset
   ```
   This checks every archive's sha256, extracts each archive, checks member counts against `lists/`, and confirms that every sample's sha256 equals its name. Wait for **`DESTINATION VERIFIED`**.
5. **Make the sample tree read-only** on the new cluster (independent copies, so this is safe there):
   `chmod -R a-w,o-rwx /path/ISB-Sherlock-Dataset/malware /path/ISB-Sherlock-Dataset/goodware`
6. **Only then** decommission or delete the old copy. Keep the zips until the dataset has a backup on the new system.
7. **Point code at the new root.** Every path in `sherlock_manifest.csv` is relative (`dataset_path`), so code needs only a dataset-root setting. Join to `manifest.sqlite` on `sha256`.

## 8. Not included (decide before decommissioning)

- Goodware package cache (641 files, 7.3 GB). Re-downloadable; hashes are pinned in `collection_state.json`.
- `ISB-Current-Corpus/malware.zip` (57 GB), the old raw copy of the vault.
- V1 experiment artifacts (`~/YaraGen-FinalExperiments/e2e-experiment/artifacts`: splits, extraction cache, CNN checkpoint, indexes) and the YaraGen code package (`~/pipeline/LLM-Playground/YaraGen`, including `Data/Crawled` rules).
- `ISB/V1-Legacy` and `ISB/Sherlock` code. These are small; copy them with the code repos.
- Pinned public sources (`ISB-Corpus-Update/data/scratch/sources`: NSRL ~182 GB, MOTIF metadata, rule repos, DIE/UPX tools).
- Claude's memory notes about this project (`~/.claude/projects/-home-soumya-corpus/memory/`).
