# experiments/ISB-v1-Legacy: V1 baseline reproduction

This folder holds the work to reproduce **V1's** (the legacy ISB system's)
reported Experiment-2 results on this cluster. Sherlock uses V1 only as an
**after-the-fact baseline**. The work is kept separate from Sherlock:
Sherlock's pipeline never reads, imports or calibrates against anything in this
folder. There are no V1 outputs, splits or parity targets in Sherlock.

Status (24 Nov 2026):

- **Stage 0 is done.** All 107 checks against report numbers pass (plus 1 derived and 1 internal check): R1, R2, R4 and R7 were
  recomputed from V1's stored per-unit results. See `RESULTS.md`.
- **The Stage 1 driver is built and its dry run is clean.** All 10,996 targets
  resolve and pass the stat check. The compile counts are 84/108, 12/12 and
  1,734/1,956, and the compile-error ids equal V1's.
- **Stage 1 has not run yet.** The scan is waiting for brownie to submit
  `slurm/stage1.sbatch` from the git root.
- Stage 2 and later stages haven't started. The decisions are in
  `DECISIONS.md`.

How to run each step, from the git root:

| Step | Command |
|---|---|
| Stage 0 | `python -I experiments/ISB-v1-Legacy/drivers/stage0_aggregate.py` |
| Stage 1 dry run | `PYTHONHASHSEED=0 ISB_DATA=... python -P -s experiments/ISB-v1-Legacy/drivers/stage1_rescore.py --dry-run` |
| Stage 1 scan (job) | `sbatch experiments/ISB-v1-Legacy/slurm/stage1.sbatch` (brownie only) |
| Acceptance | `python -I experiments/ISB-v1-Legacy/drivers/acceptance.py --run-dir experiments/ISB-v1-Legacy/runs/stage1/<run_id>` |
| Tests (fakes only) | `python -m pytest experiments/ISB-v1-Legacy/tests -q` |

Stage 1 uses `-P -s` rather than `-I` because `-I` ignores `PYTHONHASHSEED`.
`-P` still keeps the script's folder and the cwd off `sys.path`.

## Layout

| Path | What | Git |
|---|---|---|
| `README.md` | this file | tracked |
| `REPRO_PLAN.md` | the results to reproduce, inputs, gaps, stages, tolerance | tracked |
| `v1_raw/` | small text members extracted from the untrusted V1 zip, with the long prefix stripped: docs, driver `.py`/`.sbatch`, logs, `run_summary.json`, `*.meta.json`, `detection.json` (under 5 MB), `exp2__m4/presence.json`, split JSONs, `artifacts/reports/`, small vault JSONs (temporal, agreement, promiscuity) | ignored |
| `DECISIONS.md`, `RESULTS.md` | brownie's decisions; aggregate results | tracked |
| `inputs/` | the Stage 1 inputs from the zip (prefix stripped): 23 `rules.json` (template + 22 generator tags), 22 + 1 `run_summary.json`, 12 yarGen `.yar`, the split JSONs with their `.sha256` files, and V1's three reference `detection.json` files. Hashed in `inputs/INPUTS.sha256`, read-only | ignored |
| `tools/extract_inputs.py` | streams the allow-listed members out of the zip (`python -I`) | tracked |
| `v1repro/` | library: target resolution by sha256, unit builders, scan wrapper over `legacy/V1`'s harness, Stage 0 aggregation, the acceptance comparator | tracked |
| `drivers/` | `stage0_aggregate.py`, `stage1_rescore.py`, `acceptance.py` | tracked |
| `tests/` | pytest, synthetic files only | tracked |
| `slurm/stage1.sbatch` | the Stage 1 job (16 CPU, 192 GB, 2 h) | tracked |
| `runs/<stage>/<run_id>/` | run outputs and `run.json` (status, code and input sha256, git state, yara and Python versions, SLURM job id). The SLURM log stays in `runs/stage1/slurm-<job id>.out` (DECISIONS 8); the job id in `run.json` finds it. Never written into `v1_raw/` or `inputs/` | ignored |

Not extracted (they stay in the zip until Stage 2 needs them): the extraction
cache (5.2 GB), the `candidates_*` and `supervision_table` JSONs, the stored
`selections.json` and `presence.json`, the yarGen DBs, the classifier, and every
`.pkl` and `.pt` file.

Note on git: the root `.gitignore` tracks the `.md`, `.py` and `.sbatch` files
in this folder (code must hold no sample hashes and no absolute paths). It
ignores `inputs/`, `runs/` and `v1_raw/` (including its V1 `.md` docs, which
contain absolute paths), and every other file type.

## Safety rules

1. **The zip is untrusted.** Read members by streaming them with Python
   `zipfile`, from a script kept outside the extracted folders (`tools/`),
   under `python -I`.
2. **Never import or run any `.py` from the zip** (`v1_raw/*.py`). Those files
   are reference text. Runnable drivers must be re-authored, or reviewed and
   promoted by brownie (`REPRO_PLAN.md` §c).
3. **Never load a `.pkl` or `.pt` file** from the zip.
4. **The samples are read-only.** Never execute or open a sample outside the
   static scanners (yara, pefile). Never write under ISB_DATA (the dataset) or
   under `Sherlock/`. V1 code in `Sherlock/legacy/` is read-only.
5. **No sbatch from agents.** brownie submits every job. Login-node work is
   limited to light reads and aggregation.
6. **F_dev only.** F_test stays untouched, as in V1.
7. **In tracked `.md` files:** no absolute paths (write `<git root>`, ISB_DATA,
   ISB_WORK, ISB_V1_CORPUS) and no sample hashes (aggregate numbers only).
