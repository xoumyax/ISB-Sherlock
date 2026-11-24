# V1 reproduction decisions (brownie)

Answers to `REPRO_PLAN.md` §(h), recorded as they are given.

| # | Question | Decision | Date |
|---|---|---|---|
| 1 | Drivers | Thin new drivers in this folder, calling `legacy/V1`'s harness with explicit output folders; built, then reviewed. V1's own drivers (zip) are read as a spec only, never run | 24 Nov 2026 |
| 2 | Goodware DF index | Rebuilt from V1's extraction cache by our thin driver, in memory or as JSON; never load `goodware_df.pkl`. Accepted only on an exact match: 868,903 values over 3,595 docs | 24 Nov 2026 |
| 3 | Inputs | Extracted once into `inputs/` here (gitignored, long prefix stripped), every file hashed in `inputs/INPUTS.sha256`, then made read-only. Stage 1: rules only; Stage 2 adds selections, presence and the cache | 24 Nov 2026 |
| 4 | Generator-grid FP/1k | Acceptance uses V1's definition, the mean of the 12 per-arm cell means (`compare_generators.py`; lfm2 193.27). The pooled per-unit mean (lfm2 209.90) and raw benign-hit counts are reported beside it | 24 Nov 2026 |
| 5 | Job that wrote `exp2__m4/rules.json` | Unknown. Stage 1 re-scores the stored rules and doesn't need it; Stage 2's regeneration is judged by output equality alone | 24 Nov 2026 |
| 6 | V1 code version behind jobs 95852–95929 | Unknown. Any difference from `legacy/V1` would surface as a Stage 2 mismatch, traced per module | 24 Nov 2026 |
| 7 | LightGBM / YARA version | Answered from V1's notes: yaramod 4.5.0, yara-python 4.5.4, lightgbm 4.6, sklearn 1.7.2 (Python 3.12 in V1, 3.11 here) | 24 Nov 2026 |
| 8 | Outputs | `runs/<stage>/<run_id>/` here (run.json, results, SLURM log; gitignored). Summaries go in a tracked `RESULTS.md`, aggregate numbers only | 24 Nov 2026 |
| 9 | yarGen 0.25.0 and its DB | Found: brownie's local clone (`~/yarGen`, Neo23x0/yarGen at commit 34c1464, `__version__` 0.25.0, the version V1 used). Both of V1's DBs are in the zip: stock (44 files, 805 MB) and G_stats (4 files, 167 MB), gzipped JSON, not pickle. So R4 can be regenerated, not only re-scored, with no download (`--update`) and no DB build. The DB-build path in yarGen's README (`-c -g <goodware>`) stays available as a cross-check of V1's G_stats DB. yarGen is an untrusted tool: copied into its own folder here, run with `-I`, its DBs extracted read-only; it reads samples statically. Runs as a job for brownie, after Stage 1. Proposed as Stage 3 | 24 Nov 2026 |
| 10 | `.gitignore` | Done by brownie: `.md` files here are tracked; `v1_raw/` and all non-`.md` outputs are ignored | 24 Nov 2026 |
| 11 | yarGen's dependencies (lief, lxml) | A separate conda env `yargen` (python, lief, lxml, pefile), created by brownie: `conda create -n yargen -c conda-forge python=3.12 lief lxml pefile`. A package goes into `sherlock` only if ISB-Sherlock itself needs it | 24 Nov 2026 |
| 12 | Track the reproduction code? | Yes: `*.py` and `*.sbatch` under `experiments/` are tracked (they hold no sample hashes or absolute paths, checked); `inputs/`, `runs/` and `v1_raw/` stay ignored | 24 Nov 2026 |
