# ISB-Sherlock

Sherlock is **ISB vN**, the Intelligent Selection Block rebuilt from scratch. Given a
malware family's older samples, it picks the indicators (strings, byte patterns,
PE and .NET metadata) for a short YARA rule that still fires on the family's newer
samples and never on goodware. It will replace the frozen legacy ISB inside the
YARAikiba agent, and it is the subject of a standalone paper.

> **Live malware.** The dataset this code reads is real malware. Static analysis
> only: nothing in this repo executes, emulates or loads a sample as code. Samples,
> archives, hash lists and digests never go to GitHub or any online service.

## Status (2026-11-23)

| | |
|---|---|
| Phase | P0, set-up on the new cluster. **G0** (package skeleton) approved 23 Nov; W1 and W3 plans in [`Sherlock/docs/plans/`](Sherlock/docs/plans/) awaiting approval. G0 note: [`Sherlock/docs/gates/G0.md`](Sherlock/docs/gates/G0.md) |
| Dataset | Migrated and verified: 117,999 samples (95,718 malware, 22,281 goodware), every file hashed against its name, 0 mismatches. Reconciled with manifest run 278 in [`Sherlock/docs/migration/ACCEPTANCE.md`](Sherlock/docs/migration/ACCEPTANCE.md) |
| Code | `Sherlock/sherlock/`: `core.ir`, `core.records`, `data.roots`, `data.manifest` (G0); the other sub-packages are placeholders. V1's 12 ISB modules are in `Sherlock/legacy/V1/`, kept to run V1 as an after-the-fact baseline; Sherlock is written from scratch and not influenced by V1 (only its style and lessons are kept) |
| Tests | `pytest`: 328 passed, 4 skipped (180 legacy + 148 unit and lessons; skips: 4 `needs_data`). `pytest -m needs_data` with `ISB_DATA` set: 4 passed |
| Enrichment | W1–W9 not started (TLSH/sdhash collapse, alias review, source dates, rule hits, goodware, packers, labels) |

The plan (phases, gates, decisions, risks) is a private dashboard. Its latest export
is `SHERLOCKED.md` at the git root (local, gitignored; 23 Nov 2026), which supersedes
the committed snapshot
[`Sherlock/docs/canonical/2026-11-22/DASHBOARD_SNAPSHOT.md`](Sherlock/docs/canonical/2026-11-22/DASHBOARD_SNAPSHOT.md);
use that snapshot only on a clone without `SHERLOCKED.md`. The two canonical documents
split the ground: `SHERLOCKED.md` wins on the plan and this README wins on layout, and
each points to the other for the rest. A change to one that touches the other's
subject is made in both in the same change.

## Directory structure

This section is the layout reference: it wins on where things live (it replaced
`DIRECTORY_MAP.md` on 23 Nov 2026), and it is updated in the same change whenever a
root, a top-level folder or a new kind of artifact is added.

**Terms.** The *repo root* and the *git root* are the same folder: the one that
holds `README.md`, `setup.sh` and `Sherlock/`. `Sherlock/` is the *code folder*
(`ISB_HOME`): `pyproject.toml`, the `sherlock` package and `tests/` live there, so
`pytest`, `ruff`, `mypy` and `python -m sherlock.cli.<name>` run from `Sherlock/`.

The git repository holds code and docs only. On a cluster, the data, work and
scratch roots sit beside `Sherlock/` and are excluded by `.gitignore`; their absolute
paths live only in `Sherlock/config/roots.yaml` (never committed).

```
ISB-Sherlock/                      git root (github.com/xoumyax/ISB-Sherlock)
├── README.md                      this file
├── setup.sh                       conda env, roots.yaml, health check
├── download.sh                    fetch and verify the dataset archives
├── .gitignore                     keeps every data root and sample type out of git
├── SHERLOCKED.md                  canonical plan, latest dashboard export (local, gitignored)
├── HANDOFF.md                     session-to-session state on this cluster (local, gitignored)
│
├── Sherlock/                      the code repo (ISB_HOME)
│   ├── CLAUDE.md                  working rules for Claude Code (local, gitignored)
│   ├── STARTER_PROMPT.md          prompt for the next Claude Code session (local, gitignored)
│   ├── pyproject.toml             pytest, ruff and mypy settings
│   ├── environment.yml            conda spec (unpinned)
│   ├── environment.lock.yml       exact env from the first solve; setup.sh uses it
│   ├── config/
│   │   ├── roots.example.yaml     template
│   │   └── roots.yaml             this cluster's roots (gitignored; written by setup.sh)
│   ├── sherlock/                  the new package (from G0): core/ data/ extract/
│   │                              grammar/ stats/ learn/ select/ cond/ gate/ eval/ cli/
│   ├── legacy/V1/YaraGen/ISB/     V1's 12 modules, read-only; runs the V1 baseline
│   ├── tests/
│   │   ├── conftest.py            Sherlock/ on sys.path; writable roots → tmp_path
│   │   ├── legacy/                V1's own suites (pytest -m legacy)
│   │   ├── unit/ lessons/         per-module tests; V1's lessons L1–L12 (from G0)
│   │   └── integration/ parity/   needs_data tests; V1 baseline comparison
│   ├── scripts/
│   │   ├── migration/             acceptance and reconciliation scripts, verify_names.py,
│   │   │                          verify_destination.sh
│   │   └── slurm/                 sbatch files (submitted by hand)
│   ├── third_party/sdhash/        jc_sdhash wrapper + sdhash 3.4 binary (see PROVENANCE.md)
│   └── docs/
│       ├── canonical/<date>/      dashboard snapshot (read-only)
│       ├── dataset/               DATASET_STRUCTURE.md
│       ├── migration/             ACCEPTANCE.md
│       ├── gates/  sessions/      gate notes (G0…G6), end-of-session notes
│       ├── plans/                 one-page work plans (W1, W3, …) for brownie's approval
│       └── history/               notes from the old cluster
│
├── ISB-Sherlock-Data/             ISB_DATA, the dataset: read-only, NOT in git
│   ├── malware/<family>/<sha256>.bin          355 family folders, 18,018 files
│   ├── malware/_unlabelled/<collection>/      12 vault collections, 77,683 files
│   ├── malware/_pool_conflicts/               17 files
│   ├── goodware/<source>/                     12 sources, 22,281 files
│   └── metadata/
│       ├── sherlock_manifest.csv              one row per sample; sha256 → dataset_path
│       ├── source_metadata/<bazaar_run>/      MalwareBazaar exports (first-seen dates)
│       ├── build/                             organiser script, summary, old paths
│       └── project_state/                     checkpoint manifest.sqlite, reports,
│                                              dataset kit, V1 corpus manifest
├── ISB-Sherlock-Work/             ISB_WORK, every derived artifact, keyed by sha256, no
│   │                              absolute paths inside (H7): NOT in git
│   ├── manifest/                  working manifest.sqlite (+ enrichment tables, W1–W9)
│   │                              and CHECKPOINT.sha256 of the untouched original
│   ├── enrich/W1/ … W9/           each workstream's raw outputs before they load (P1)
│   ├── splits/                    malware_split.json, goodware_split.json,
│   │                              drift_windows.json, each with a .sha256 (G1)
│   ├── cache/extract/             extraction cache, sharded by sha256[:2] (P3)
│   ├── indexes/                   goodware DF and span indexes, cross-family index (P3)
│   ├── supervision/               persistence labels, aligned rule hits (P4)
│   ├── models/                    scorer/<v>/, cond_adapter/<v>/, bytecnn/ (P3–P5)
│   ├── parity/                    V1 baseline inputs and outputs (never read by Sherlock's pipeline)
│   ├── runs/<experiment>/<arm>/<run_id>/
│   │                              one folder per run: run.json (commit, config, root
│   │                              sources; no absolute paths), candidates, selection,
│   │                              rules, scan JSONL, summary.json, slurm-%j.out (P3 on)
│   └── reports/                   machine-written reports; reports/migration/ holds the
│                                  verify log, archive checksums and migration records
├── ISB-Sherlock-Scratch/          ISB_SCRATCH, temporary; safe to wipe: NOT in git
├── ISB-V1-RAW.zip                 V1's artifacts from the old cluster (splits, exp2
│                                  outputs, indexes, code): untrusted, read-only, verified;
│                                  used only for the V1 baseline: NOT in git
└── experiments/                   baselines run beside Sherlock, never read by its pipeline
    └── ISB-v1-Legacy/             V1 reproduction: docs and code tracked; inputs/, runs/,
                                   v1_raw/ NOT in git (see its README.md)
```

The roots can live anywhere (another filesystem, a scratch volume); `beside the
repo` is just the layout used on the first cluster. If you put them inside the git
tree under other names, add those names to `.gitignore` first.

### Where is…?

| Looking for | Go to |
|---|---|
| A phase, gate, date, decision, risk or approval | `SHERLOCKED.md` (offline: `Sherlock/docs/canonical/<latest>/`) |
| Where things stand on this cluster | `HANDOFF.md`, then `Sherlock/docs/sessions/<latest>.md` |
| A sample's file | `ISB_DATA/<dataset_path>` from `metadata/sherlock_manifest.csv`, keyed by `sha256` |
| Its family label | `mb_family` (Tier X, never an evaluation label); `motif_family`, `motif_tier` (Tier A) |
| Its first-seen date | `mb_first_seen`; raw exports in `metadata/source_metadata/` |
| Its TLSH digest / packer | `tlsh` (empty where it can't be computed); `die_packed`, `die_packer` |
| Its parent (UPX child, archive member) | `parent_sha256`, with `selfpacked_child` / `archive_member` in `flags` |
| Softonic files (barred from paper splits) | `any_softonic` in `flags` |
| PE/ELF metadata, alias graph, rule joins | `ISB_WORK/manifest/manifest.sqlite`, joined on `sha256` (never read `file_paths.path`: dead old-cluster paths) |
| Family sizes | count `folder` in the manifest; the migration copy of `family_index.csv` is in `ISB_WORK/reports/migration/source/` |
| Alias review, pool conflicts, dataset kit, V1 corpus manifest | `ISB_DATA/metadata/project_state/` (`ISB-Corpus-Update/reports/`, `…/yaragen-dataset-kit/`, `ISB-Current-Corpus/_manifest/`) |
| Migration evidence (verify log, checksums, reconciliation) | `ISB_WORK/reports/migration/`; the write-up is `Sherlock/docs/migration/ACCEPTANCE.md` |
| V1 code and tests | `Sherlock/legacy/V1/YaraGen/ISB/`, `Sherlock/tests/legacy/` |
| sdhash | `Sherlock/third_party/sdhash/` (bulk mode in `PROVENANCE.md`) |

**Not on this cluster** (needed later): V1's experiment artifacts (`malware_split.json`,
`goodware_split.json`, exp2 detection outputs, goodware indexes) for running V1 as a
baseline (not used by Sherlock); V1's `YaraGen/StaticFeatures/`, `Detection/`, `RuleSynth/template.py`
and `Pipelines/BinaryToRule.py` for rerunning V1; the rule repositories (W4), MOTIF
metadata (W9), DIE and UPX (W8). The dataset archives were deleted after verification,
so on ramius `ISB_DATA` is the only copy (see `HANDOFF.md`).

## Setup

### Requirements

- Linux x86-64 with `conda` (Anaconda or Miniforge) and `g++` (`py-tlsh` is built
  from source by pip).
- `bash`, `sha256sum`, `unzip`, `rsync`; `python3` for the verify scripts.
- About **350 GB** for the dataset and **235 GB** more while the archives are on
  disk. A cluster with SLURM is assumed for the long steps but not required.
- Permission to hold live malware on the machine, and no on-access antivirus
  scanning the archive or dataset folders (it would delete samples mid-extraction).

### 1. Clone

```bash
git clone git@github.com:xoumyax/ISB-Sherlock.git
cd ISB-Sherlock
```

### 2. Environment and roots: `setup.sh`

```bash
./setup.sh                                                 # first run in a terminal: asks where the roots go
./setup.sh --beside-repo                                   # roots next to Sherlock/
# or choose each root yourself:
./setup.sh --data /big/ISB-Sherlock-Data --work /big/ISB-Sherlock-Work --scratch /tmp/me/isb
                                                           # later re-runs reuse roots.yaml
```

It creates (or reuses) the `sherlock` conda env from `environment.lock.yml`, writes
`Sherlock/config/roots.yaml`, and creates the directory skeleton a fresh clone
lacks: the three roots (the dataset root stays empty for `download.sh`), the work
tree (`manifest/`, `enrich/W1…W9/`, `splits/`, `cache/extract/`, `indexes/`,
`supervision/`, `models/`, `parity/`, `runs/`, `reports/`) and the empty repo
folders (`docs/gates/`, `docs/sessions/`, `tests/unit|lessons|integration|parity/`).
Then it runs `pytest -m legacy` (expect 180 passed). Re-running is safe:
with no arguments it reuses the roots in `roots.yaml`, and `mkdir -p` never touches
what exists. A root inside the git tree that `.gitignore` doesn't cover is refused. There are no default paths:
pass the roots or opt in to `--beside-repo`. Other flags: `--env-only`,
`--update-env`, `--force` (overwrite `roots.yaml`), `--no-tests`.

### 3. Dataset: `download.sh`

The dataset travels as 113 encrypted zip archives (password `infected`; under
4 GiB each, no ZIP64), with `.sha256` files, `plan.json`, `lists/` and two verify
scripts. Fetch them into a new directory outside `Sherlock/`:

```bash
./download.sh gdrive <GDRIVE_FOLDER_ID>            --zips /big/ISB-Sherlock-Dataset-zips
./download.sh server user@host:/path/to/zips       --zips /big/ISB-Sherlock-Dataset-zips
./download.sh verify                               --zips /big/ISB-Sherlock-Dataset-zips
```

The source is a placeholder for now: pass it on the command line or fill in
`GDRIVE_FOLDER_ID` / `SERVER_SOURCE` at the top of `download.sh`. The script refuses
a `--zips` folder that git could stage, checks that all 113 archives arrived and
verifies every archive's sha256. Google Drive applies download quotas; if `gdown`
stops partway, rerun later or use `server`.

### 4. Build and verify the dataset

Extraction plus verification reads and writes several hundred GB and takes about
1.5 hours on NFS. On a cluster, submit the sbatch line `download.sh` prints:

```bash
export ISB_ZIPS=/big/ISB-Sherlock-Dataset-zips ISB_DATA=... ISB_WORK=...
mkdir -p "$ISB_WORK/reports/migration"
sbatch --export=ALL --output="$ISB_WORK/reports/migration/verify_destination-%j.out" \
    Sherlock/scripts/slurm/verify_destination.sbatch
```

or run `./download.sh verify --zips DIR --extract` on a machine where hours of I/O
are fine. Either way it unzips every archive into the dataset root, checks member
counts against `plan.json`, and hashes every sample against its file name. Wait for
the last line **`DESTINATION VERIFIED`**, then make the samples read-only:

```bash
chmod -R a-w,o-rwx "$ISB_DATA/malware" "$ISB_DATA/goodware"
```

Keep the archives until the dataset has a backup.

### 5. Check

```bash
conda activate sherlock
cd Sherlock
pytest -m legacy                                   # V1's suites: 180 passed
ISB_DATA=/big/ISB-Sherlock-Data pytest -m needs_data   # read-only dataset tests (from G0)
python -I scripts/migration/verify_names.py "$ISB_DATA" <list.lst>   # spot-check hashes
```

## Working rules (short version)

- **sha256 is the key.** Resolve a sample through `dataset_path` in
  `metadata/sherlock_manifest.csv`. The `file_paths` table in `manifest.sqlite`
  holds dead old-cluster paths: join on `sha256`, never read those paths.
- **Never write under the dataset root.** Derived artifacts go to `ISB_WORK`,
  temporary files to `ISB_SCRATCH`; tests redirect both to `tmp_path`.
- **No absolute paths** in code or artifacts; roots come from `ISB_DATA`,
  `ISB_WORK`, `ISB_SCRATCH`, then `config/roots.yaml`.
- **Labels:** MalwareBazaar `signature` (Tier X) is never an evaluation label;
  Softonic goodware (`any_softonic`) is barred from paper splits.
- **Nothing but code and docs on GitHub.** No samples, archives, `.sha256` lists,
  similarity digests, databases or `roots.yaml`.
- Work proceeds in gates (G0…G6); each passes when its note in `Sherlock/docs/gates/`
  is approved.

More: [`Sherlock/docs/dataset/DATASET_STRUCTURE.md`](Sherlock/docs/dataset/DATASET_STRUCTURE.md)
(dataset columns and folders), [`Sherlock/third_party/sdhash/PROVENANCE.md`](Sherlock/third_party/sdhash/PROVENANCE.md)
(sdhash in bulk mode).

# ISB-Sherlock
Indicator selection for binary-to-YARA rule generation: rules that survive family drift with near-zero FP.
