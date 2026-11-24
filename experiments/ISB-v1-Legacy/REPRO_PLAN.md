# V1 reproduction plan (Experiment 2, F_dev)

Scope: reproduce the numbers in V1's `EXP2_REPORT` on this cluster. Every
number is **F_dev, oracle-label condition**. F_test is not run. `v1/` below
means `v1_raw/` (members extracted from the zip, prefix stripped), and
`zip:` means a member that is still only in the zip.

## (a) Results to reproduce

| # | Result | Arm / config | Split / denominators | Source |
|---|---|---|---|---|
| R1 | Arm ladder, template generator: 14 rows of TPR, FP/1k, Win8 FP/1k, cross-fam. Headlines: `classifier__prevalence_k` 0.337 / **0.12**; `union__prevalence_k` 0.351 / 0.64; `classifier__all` 0.567 / 333.32; `union__learned` 0.180 / 0.27; `static__random_k` 0.054 / 0.00 | 3 sources x 6 arms, k=8, verify pool 40, seed 20260809, `ISB_DIR=isb__m4` | 6 F_dev families: 522 held PE, 527 gen PE, 9,947 G_eval | report tab:ladder; `v1/artifacts/exp2__m4/run_summary.json` and `detection.json`; log of job 95876 |
| R2 | 24 units cannot be rendered (over 10,000 strings; largest 412,124). 84 of 108 units compile | `static`/`union` x `all`/`lint` | same | report §res:ladder; `exp2__m4/run_summary.json` |
| R3 | Per-family TPR (quasarrat 0.632 ... gcleaner 0.000; best budgeted macro 0.354) | `classifier__prevalence_k` and the best budgeted arm | 87 held per family | report tab:perfamily; `exp2__m4/detection.json` per_unit |
| R4 | yarGen 0.25.0: stock 0.747 / 253.85 (Win8 72.26); G_stats DB 0.634 / 107.27 (Win8 59.12); about 146 rules per family | yarGen, 2 DB variants | same | report tab:yargen; `v1/artifacts/yargen/run_summary.json` and `detection.json` |
| R5 | Verify gate: 1,655 distinct pooled candidates, 679 (41%) found in goodware; per-arm rejection rates | `verify` stage, G_stats byte presence | 10,620 G_stats | report tab:verify; `exp2__m4/presence.meta.json` (976 absent) |
| R6 | Learned scorer PR-AUC 0.17133 against a prevalence baseline of 0.03789 | LightGBM salience, 6 held-out F_train families | supervision table: 511,663 rows | `isb__m4/run_summary.json` (`train`) |
| R7 | Generator grid, budgeted planformat (72 units each): TPR and FP/1k per generator, for example `lfm2` 0.430 / 193.27, `bart_scooper` 0.231 / 0.20, template 0.230 / 0.23 | 11 checkpoints x 2 prompt styles | same | report tab:gen; `v1/artifacts/exp2_all/detection.json` (scoreall job 95929) |
| R8 | Generator fidelity, hallucination and modifier fidelity (for example `llama_taskmix` 99.8% / 0.2%) | `fidelity.py`, template rules as ground truth | text only | report tab:gen, tab:genclass. Report-only today, but recomputable |
| R9 | Classifier gate: vault-out AUC 0.94148, family top-1 0.56709 (epoch 5); vault-in 0.92667 | byte CNN, 256 KB windows | F_dev classifier eval (n=395 family) | report tab:clf; `zip:artifacts/classifier/*/report.json` |
| R10 | Vault studies: `classifier__all` matches 19,748 PEs per rule on average; temporal 0.3–1.2%; corroboration null (0.393–0.521 against a 0.438 base rate) | `vault_studies.py` | 60,188 vault PE | report §res:vault; `v1/artifacts/vault/*.json` |

Notes:
- `run_summary.json` is rewritten on each invocation and holds only the last
  stages run (`exp2__m4` holds `score` only, `vault` holds `agreement` only).
  Use `detection.json`, the `*.meta.json` files and the logs as well.
- Report counts include non-PE samples. F_dev gen 528 becomes 527 PE and
  F_train held 1,967 becomes 1,965 PE; F_dev held is 522 either way. This is not
  a discrepancy.
- **Preflight check (done, login node):** `exp2__m4` and `yargen` grids equal R1
  and R4. Re-aggregating `exp2_all/detection.json` reproduces every R7 TPR and
  FP/1k exactly, provided FP/1k is taken the way `compare_generators.py` takes
  it: the mean of the 12 budgeted (source x arm) cell means. A per-unit mean
  does not match (for `lfm2`, 209.9 against 193.27). Record this definition.
- Not yet checked against stored artifacts: R9 (classifier `report.json`,
  still in the zip). R3 and R10 were verified by the independent review.

## (b) Inputs per result

| # | Producer (V1) | Inputs | Present? |
|---|---|---|---|
| R1–R3 rescore | `run_exp2.py STAGE=score` (`rescore_verified.sbatch`) | `zip:exp2__m4/rules.json` (220 MB), splits, F_dev + G_eval samples | rules and splits: zip. Samples: ISB_DATA |
| R1–R3 rerun | `run_exp2.py STAGE=select,verify,generate,score` | `isb__m4/{candidates_static,supervision_table,analyst_terms}.json` (`select` **re-fits** the salience LightGBM from the table; it does not load `salience.txt`), `goodware_spans.json`, **`goodware/goodware_df.pkl`**, G_stats samples (verify) | all in the zip; DF index is a **pickle** (rebuild it, §c) |
| R4 | `yargen_baseline.py` `STAGE=score` (rescore) or `prep,db,stock,generate,score` | `zip:yargen/rules/{stock,gstats}/*.yar`; for a rerun, yarGen 0.25.0 and its stock DB | rules and the built DBs: zip. yarGen itself: **missing** |
| R5 | `run_exp2.py STAGE=verify` | pooled candidates (`selections.json`), G_stats samples | zip, ISB_DATA |
| R6 | `run_isb.py STAGE=train` (fits on the stored table); `supervise` rebuilds the table | `isb__m4/supervision_table.json` (train). For supervise: `candidates_static.json`, the cache, the DF index, `goodware_spans.json` | train: zip. Supervise: DF pickle (rebuild) |
| R7 | `score_all.py` | 22 `zip:exp2__<gen>_<style>/rules.json` and `exp2__m4/rules.json` | zip (stored LLM outputs; no checkpoints needed) |
| R8 | `fidelity.py` | the same `rules.json` files (text only) | zip |
| R9 | `train_classifier.py`, `retrain_*.sbatch` | cache, vault screen, GPU | retraining needed; `.pt` files are off-limits |
| R10 | `vault_studies.py` | `zip:vault/vault_index.json`, `exp2__m4` rules, 60,188 vault PE; agreement also needs `best.pt` | vault PEs all in the Sherlock manifest; `.pt` off-limits |
| new rules from scratch | `run_isb.py STAGE=candidates,attribute,...` | cache, `best.pt` (attribution), `YaraGen/Data/Crawled` (analyst corpus, pickles) | `.pt` off-limits; Crawled **missing** |

Coverage check (stat only, no reads): all 27,373 split paths resolve through
sha256 to `dataset_path` in the Sherlock manifest. Only 50 resolve with V1's
own relative path. All 60,188 vault PEs and all 20,567 goodware are in the
manifest.

## (c) Gaps

| Gap | Blocks | Remedy |
|---|---|---|
| **The drivers exist only in the zip** (`run_exp2.py`, `score_all.py`, `fidelity.py`, `yargen_baseline.py`, `run_isb.py`), and zip `.py` must never be run | every stage | brownie reviews and promotes them to a trusted copy, or we re-author thin drivers here over `Sherlock/legacy/V1` modules |
| **The DF index is a pickle** (`goodware_df.pkl`, `pickle.load` in `dfindex.load_df_index`) | R1 rerun, R6 | rebuild it from the JSONL cache (`build_extraction_cache SCOPE=df`, 26 s in V1; per-source cap 2000, seed 20260809). Do **not** run `build_extraction_cache SCOPE=df`: it calls `save_df_index`, which writes `goodware_df.pkl`. Our own thin driver calls the in-memory builder and keeps the index in memory, or serialises it as JSON; never as a pickle. Accept the rebuild if it gives 868,903 values and 3,595 docs |
| **The classifier needs `best.pt`** (attribution, R9, vault agreement) | R10 agreement, new attribution | out of scope; Stage 2 uses the stored `candidates_union.json` |
| Missing legacy packages: `YaraGen.Inference` (lazy import in `RuleSynth/llm.py`), the scooper `IOCExtractor` (`llm.py` config); `YaraDiff` and `Inference.constrained_decoding` are imported only by the zip's `windowexample.py` (RQ8 harness, not used by Exp 2) | LLM generation only | out of scope; R7/R8 use the stored rules. `fidelity.py` needs none of them |
| `YaraGen/Data/Crawled` (305,697 crawled rules, `.pkl`) | `mine` stage | use the stored `analyst_terms.json` |
| yarGen 0.25.0 is absent (V1 used `<V1 home>/yarGen` and a separate `yargen` env with lief) | R4 rerun only | rescoring the stored `.yar` files needs only yara-python. There is no `yara` CLI on PATH, and none is needed |
| LLM checkpoints (`ISB_V1_MODELS`: RQ7/RQ8/RQ9 trees) | R7 regeneration | out of scope |
| Code provenance: `legacy/V1` was edited after V1 ran (env-var shims); there are no code hashes for the runs | exactness claims | ask brownie for V1's code hash, or accept the risk |

Python deps (checked, nothing installed). V1's run env is documented in
`v1_raw/HANDOFF.md` (Setup Required): `cu13_V4Train` with yaramod 4.5.0,
yara-python 4.5.4, lightgbm 4.6, sklearn 1.7.2. YARA 4.5.4 is the same on both
sides. Python is 3.12 in V1 and 3.11 here.

| Package | `sherlock` env | `cu13_V4Train` (V1's env) |
|---|---|---|
| yara-python / libyara | 4.5.4 | 4.5.4 |
| pefile | 2024.8.26 | 2024.8.26 |
| lightgbm | 4.7.0 | 4.6.0 (4.6 per HANDOFF) |
| torch | missing | 2.11.0+cpu |
| scikit-learn | 1.9.1 | 1.7.2 per HANDOFF |
| lief | missing | missing |
| transformers | missing | 4.57.0 |

Stages 0–2 need only yara, pefile, lightgbm and numpy, which the `sherlock`
env has.

## (d) Path rewiring

| Hard-coded in the zip | Where | Map to |
|---|---|---|
| `<V1 home>/corpus` (`corpus_root`, `CORPUS`) | `run_exp2.py`, `score_all.py`, `run_isb.py`, `yargen_baseline.py`, `vault_studies.py`, `build_extraction_cache.py`, `phase0_corpus_splits.py` | a **sha256 resolver** over `ISB_DATA/metadata/sherlock_manifest.csv`, giving `ISB_DATA/<dataset_path>`. A `corpus_root` swap is not enough because the layouts differ. Do not edit the frozen splits; build `ScanTarget` paths in the driver |
| `<V1 home>/corpus/_manifest/{corpus_manifest,cross_label_collisions}.csv` | `phase0`, `build_extraction_cache`, `build_vault_screen`, `vault_studies` | `ISB_V1_CORPUS/_manifest/...` (V1's manifest sits under ISB_DATA's project_state; latin-1) |
| `<V1 home>/yarGen`, `<V1 home>/.conda/envs/yargen/bin/python` | `yargen_baseline.py` and `.sbatch` | env vars `YARGEN_DIR` and `YARGEN_PY`, needed only for a rerun |
| `HERE/artifacts/...` (every input and output is relative to the script) | all drivers | inputs: read-only, streamed from the zip or from an `ISB_V1_ARTIFACTS` root; outputs: `runs/<stage>/` in this folder (ignored by git), or ISB_WORK if brownie prefers. **Never** the same directory as the inputs: drivers overwrite `run_summary.json`, `detection.json` and so on |
| `ROOT = dirname(dirname(HERE))` added to `sys.path` | all drivers | put `<git root>/Sherlock/legacy/V1` on `sys.path` |
| `conda activate cu13_V4Train` | `*.sbatch` | the `sherlock` env, which is enough for Stages 0–2 |
| absolute `out_dir` and `paths` in `run_summary.json` (`finalExperimets`) | provenance only | ignore |

## (e) Staged order

| Stage | What | Compute | Basis | Job? |
|---|---|---|---|---|
| **0** (Stage 1 preflight) | Re-aggregate the stored `detection.json` files (`exp2__m4`, `yargen`, `exp2_all`) into R1–R4 and R7 (R1, R4 and R7 already confirmed). Recompute R8 fidelity from the stored `rules.json` (text) | login node, under 1 min, under 2 GB RAM (streams the 220 MB `rules.json`) | arithmetic only | no |
| **1** | **Three scans, as V1 ran them**, with the legacy `Detection.harness` against F_dev held (522) + gen (527) + G_eval (9,947). They are not pooled, because the 30 s timeout applies per file across all compiled rules. (1a) template: 108 units (`exp2__m4`, as job 95876). (1b) yarGen: 12 units, one per variant x family, each family's whole `.yar` set (as job 95891). (1c) generators: the 23 pinned `TAGS` (22 generator x style tags at 84 units each + `m4` at 108, total **1,956 = 1,848 + 108**; the template is inside the 1,956), smoke runs excluded (as job 95929). See "Stage 1 fidelity" below. Inputs are streamed from the zip | 16 CPU; memory 128–192 GB is V1's `--mem` request, not a measured MaxRSS; **about 10 min per scan** (2 h wall limit) | jobs 95891, 95929, 95876: 453–485 s per full scan (job 95863 took 8,342 s because it compiled the 24 over-limit units before the cap existed) | **yes**: CPU job from brownie |
| **2** | ISB rerun from the stored `isb__m4` candidates: rebuild the DF index from the cache; then `select`, `verify` and `generate`; diff against the stored `selections.json`, `presence.json` and `rules.json`; then score. Optionally re-fit the salience model (R6) | 16 CPU, 192 GB (V1's setting; 0.9–1.2 GB JSONs), **about 25 min** (2 h wall limit) | select 538 s, generate 81 s, verify 536 s (`presence.meta`), score about 480 s, train 9 s, df 26 s | **yes** |
| 3 | Full re-extraction: `build_extraction_cache` (pass1 + vault), then `run_isb candidates,supervise,train` without attribution (static source only); diff against the zip's cache | 64 workers, about 30 min for the cache, 6 min for candidates and supervise | m1 reports: pass1 83 s, vault 1,222 s; `candidates` 272 s, `supervise` 199 s | yes |
| 3b | yarGen rerun (R4 from scratch), if brownie supplies yarGen | 16 CPU, 192 GB, about 1 h | `db` 1,454 s, `generate` 1,945 s | yes |
| 3c | Vault promiscuity and temporal studies (R10, no `.pt`) | 16 CPU, 128 GB, about 20 min | promiscuity 971–981 s | yes |
| out | Classifier retraining (R9), attribution, LLM generation (R7 regeneration), the analyst `mine` stage | GPU: about 2,750 s/epoch x 12 epochs | job 95807 | out of scope |

**Stage 1 fidelity** (copy V1 exactly):
- yarGen units: read the `.yar` as bytes, decode utf-8 with `errors="replace"`,
  replace each NUL byte with the 4-character text `\x00`, and skip empty sources. They carry no `n_strings`,
  so the harness counts strings by regex. Template and generator units pass
  `meta n_strings`, as `run_exp2.py` and `score_all.py` do.
- Pin the 23 `TAGS` explicitly; never glob (`smoke` was excluded in 95929).
- Expect yara "too many matches" RuntimeWarnings, as V1 had them; they are not failures.
- Set `PYTHONHASHSEED=0`. V1 did not set it. Stage 1 does not depend on it, but
  Stage 2 tie-breaks over sets or dicts might.
- Goodware `source` labels (`benign_by_source`, Win8 column) come from V1's
  `goodware_split.json`, not from the Sherlock manifest: 10 G_eval files sit
  under `malware/_pool_conflicts` there, and 14 are oversized or uninventoried.
  Only the file path comes from the manifest.
- Timeout risk: if storage here is slower than V1's, a file could pass the 30 s
  timeout and change a result. Any `failures` entry fails the stage; then rerun
  that scan, not raise the timeout.

## (f) Acceptance tolerance

| Stage | "Reproduced" means |
|---|---|
| 0 | every reported number equals the recomputed one at the report's printed precision. Any mismatch is explained in writing |
| 1 | the same bytes, the same yara (4.5.4), the same targets, so the result is **exact**: per unit, `tp`, `cross_match`, `benign_match`, `gen_match` and every `benign_by_source` count are equal integers. Template: 84 compiled, 24 unrenderable. yarGen: 0 compile errors. Generators: 1,956 units in, 1,734 compiled, 222 compile errors. No `failures` (timeout is 30 s per file; any timeout fails the check) |
| 2 | `selections.json` and `rules.json` are **byte-identical** for `prevalence_k`, `random_k` (seeded `Random(seed:family)`), `all` and `lint`; presence gives 976 of 1,655 absent. `learned` (salience LightGBM, re-fit in `select`) and `analyst` (PU-bagged LightGBM) depend on the LightGBM version (4.7.0 here, 4.6 in V1 per HANDOFF). Expected exact; if not, TPR within ±0.01 and FP/1k within ±0.05 per row, with the selection diff reported. R6 PR-AUC within ±0.005 |
| 3 | cache records are equal per sha on the fields consumed; static candidate rows equal the stored pre-attribution count. The 7,607,160-row and 511,663-row figures include classifier spans: they are reachable only if the stored spans are spliced in |

## (g) Safety notes

- V1 scanning is static. `harness.py` uses `yara.match(filepath=..., timeout=30)`.
  Extraction uses pefile and byte reads. Nothing executes a sample.
- **Where V1 writes.** Driver defaults are under `HERE/artifacts` (the
  script's own directory), but writes can be redirected:
  - by environment variables: `OUT` in `score_all.py:168` and
    `build_vault_screen.py:161` (which also writes a `_prev.json` copy), and
    `OUT_DIR` in `build_extraction_cache.py:97`;
  - by library functions, which write wherever their caller passes `out_dir`:
    `dfindex.py:134` (`pickle.dump`), `spanindex.py:215`, `mining.py:209`,
    `salience.py:291,301`, `cache.py:137` (append), `model_a.py:296` (pickle),
    `train.py:358` (`torch.save`).
- `yargen_baseline.py` builds **symlink farms** to samples (`samples/`,
  `goodware_gstats/`), deletes files in `work/*/dbs` with `os.remove`, and runs
  yarGen as a subprocess that reads the linked samples. Anything that followed
  those links in write mode would reach the dataset.
- **Rule for us:** every run sets an explicit output directory outside
  `v1_raw/`, and no output is ever written to a folder that holds reference
  files (the zip cache, `v1_raw/`, ISB_DATA).
- `phase0_corpus_splits.py` re-freezes the splits and renames earlier versions:
  **never run it**.
- `StaticFeatureExtractor/common.py:_try_floss` writes sample bytes to a temp
  file and runs `floss`, which emulates code. It runs only with `use_floss=True`;
  V1's YaraGen does not call it.
- `vault_studies` and `build_vault_screen` read V1's manifest only, and write
  under `artifacts/`.
- No V1 code writes next to samples or into the dataset root, as long as
  outputs are redirected as in §d.

## (h) For brownie

1. Approve one of these: re-authored thin drivers here, or promotion of the
   reviewed zip drivers (`run_exp2.py`, `score_all.py`, `fidelity.py`).
2. Approve rebuilding the DF index from the cache in memory (or as JSON, by our
   own driver), instead of loading `goodware_df.pkl`.
3. Approve extracting the Stage 1 inputs, and say where they go
   (`ISB_V1_ARTIFACTS`), or approve streaming them from the zip: `exp2__m4/rules.json`, the 22 generator `rules.json`
   files, `yargen/rules/*.yar`. Stage 2 adds `isb__m4/*`, `exp2__m4/{selections,presence}.json`
   and the cache.
4. Confirm the R7 FP/1k definition: the mean of the cell means, as in `compare_generators.py`.
5. No log in the zip covers the final `verify` + `generate` run that wrote
   `exp2__m4/rules.json` (job 95863 predates verify; 95876 is score only).
   Which job was it?
6. The V1 code version (commit or hashes) behind jobs 95852–95929, and how it
   differs from `legacy/V1`.
7. Confirm that 4.6.0 (in `cu13_V4Train` today, 4.6 per HANDOFF) is the exact LightGBM build V1 ran.
8. Where should run outputs go: `runs/` here, or ISB_WORK?
9. Is yarGen 0.25.0 plus its 805 MB stock DB available, if R4 is rerun?
10. ~~Fix `.gitignore` so that these `.md` files are tracked.~~ Done.
11. Submit the Stage 1 and Stage 2 jobs when they are ready.
