# Memory export: YaraGen, YARAikiba, and how ISB connects them

Exported 2026-11-22 from Claude's project memory (`~/.claude/projects/-home-soumya-pipeline-LLM-Playground/memory/`).
I checked the ISB paths against the disk on the export date. Everything else is copied from memory as it was written, so dates show when each fact was recorded.
Old memories still say `finalExperimets/`. That folder was renamed to `finalexperiments/` on 2026-10-09.

---

## 1. The picture in one diagram

```
                 YaraGen/  (research package, shared code, in git)
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ Data/ Training/ TrainingAST/ Inference/(RuleGenerator, frozen API)        │
 │ Complexity/ YaraDiff/ Merger/ Mutator/ Describer/ Classifier/ Humanizer/  │
 │                                                                          │
 │ Exp-2 binary track (built Aug 2026, "all reusable logic = YaraGen modules")│
 │   StaticFeatures/ ──> SampleClassifier/ ──> ISB/ ──> RuleSynth/ ──> Detection/
 │   (extract, DF index,   (MalConv attribution,  (select IOCs,   (template /   (TPR, FP/1k
 │    span/presence index)  HEX_SPAN emitter)     plan condition)  LM render)    harness)
 │                         facade: Pipelines/BinaryToRule.py                  │
 └───────────────────────────────┬──────────────────────────────────────────┘
                                 │ copied in, never imported across
                                 ▼
                 YARAikiba/  (standalone co-analyst agent + A/B study platform)
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ yaraikiba/vendor/YaraGen/{ISB,StaticFeatures,...}  (verbatim, HEAD 8b1822a5)│
 │ data/isb/  pinned Exp-2 "m4" artifacts (goodware_df.pkl, goodware_spans.json,│
 │            salience.txt, goodware_gstats_files.json), frozen                │
 │ tools/isb.py: isb_candidates → isb_select → isb_plan → isb_render_template │
 │                                                    └→ isb_render_taskmix   │
 │ WF10 "binary → readable rule"; the candidate IR and grammar are also used  │
 │ by the report path (filter_iocs, format_ioc_prompt, normalize_nl_request,  │
 │ multisample, rule naming); insights/risk.py = FP-risk view                 │
 └──────────────────────────────────────────────────────────────────────────┘
```

**In short:** ISB is a YaraGen module that came out of the paper's Exp-2 detection study. YARAikiba carries a vendored, frozen copy of it (the "legacy ISB"). That copy powers WF10, the readable-rule path from binaries. Its candidate IR and grammar are also reused across the report-to-rule tools. A new ISB version, "vN", is being built to replace the legacy copy in the agent. Its integration is pending.

---

## 2. ISB, the bridge module

### 2.1 What it is
- The name stands for **Intelligent Selection Block**. The YARAikiba docs call it "indicator selection for binaries". The question it answers is **which IOCs go into a rule**.
- It was born in **RQ4-v2** (spec `finalexperiments/e2e-experiment/RQ4v2_SPEC.md`), which replaced RQ4 and RQ4b. In the RQ4-v2 framing, detection (TPR and FP per 1k goodware) is the endpoint and parse validity is only a gate.
- Code lives in `YaraGen/ISB/`: `candidate.py` (frozen Candidate IR, a unified type space, value normalisation), `grammar.py` (YARA expressibility), `goodware.py` (GoodwareOracle: hex values go to the span index, everything else to the string DF index; it returns `index="none"`, never a fake clean 0), `stoplist.py`, `salience.py` (ISB-A LightGBM scorer, with PriorScorer as fallback), `supervision.py`, `budget.py` (type_cover, k=8, hashes free), `condition.py` (ISB-B ConditionBrain), `pooling.py`, `mining.py` (analyst arm), `isb.py` (orchestrator).
- The modules it depends on are also in YaraGen: `StaticFeatures/` (extract, dfindex, spanindex, `presence.py` byte-substring verify), `SampleClassifier/` (window-MalConv, `emit_spans.py`), `RuleSynth/` (`template.py` is the deterministic renderer, `llm.py` holds the LM generators), `Detection/harness.py`, and the facade `Pipelines/BinaryToRule.py`.
- brownie's architecture rule: all reusable pipeline logic lives in YaraGen modules, and experiment scripts stay thin drivers. The facades exist so that an agent can call the end-to-end pipelines in one shot. That is exactly how YARAikiba uses BinaryToRule.

### 2.2 How it evolved (research side)
| When | Milestone |
|---|---|
| 08-07 | First ISB, 34 tests, P1 report pipeline. Added the curated stoplist, the smart threshold condition `(hash) or (any of $strong) or (N of $weak)`, and single-rule-first generation with merge only as a fallback |
| 08-09 | **Full wipe and restart.** Exp 1 (report→rule, fidelity and extraction bottleneck) was decoupled from Exp 2 (binary→rule detection). Track A lesson: `budget_exclude_types` |
| 08-10 | Milestones M0 and M1 approved. M2 classifier: vault-OUT window-MalConv chosen, F_dev AUC 0.941 |
| 08-20 | M3: the supervision tautology was fixed (support is now measured on held samples; PR-AUC 0.171 vs a 0.038 baseline, 4.5x). Mining: crawled rule names are anonymised, so the analyst arm cannot attribute families |
| 08-20 | M4 run: FP of 197–541 per 1k. Root cause: the string DF index cannot see byte substrings. **`presence.py` verify-then-budget brought FP down 300–800x to <1 per 1k** |
| 08-21 | yarGen baseline: about 2x our TPR at about 400x our FP. LM grid with an IOC-fidelity metric: **llama_taskmix + planformat 99.5% fidelity**, Ministral 62.7%, the BARTs 31–38% (they hallucinate IOCs). Lesson: TPR/FP alone cannot evaluate LM rule generation |

Headline operating points, from the 6 F_dev families and 9,947 G_eval files:
- `union__prevalence_k` scored 0.351 TPR at 0.64 FP/1k.
- `classifier__prevalence_k` scored 0.337 TPR at 0.12 FP/1k.
- The `learned` arm (0.180 TPR) still does not beat the prevalence heuristic. That is a negative result.

Known caveats:
- **Date-stamped strings.** The goodware is from 2012–2016 and the malware from 2026. Strings with dates look specific only because the goodware is older, so the reported FP is optimistic.
- **Runtime gap.** Few VB6, .NET, or packed files are in the goodware. The stoplist is a patch, and collecting more goodware of those kinds is the real fix.

### 2.3 How YARAikiba uses it (verified in `YARAikiba/docs/modules/yaragen-isb.md` and `docs/tools/isb.md`)
- **Vendored verbatim** into `yaraikiba/vendor/YaraGen/{ISB,StaticFeatures}/`. Provenance is in `vendor/VENDORED_FROM.txt`: block P2a covers the report pipeline (candidate and grammar), block P4c covers WF10 (all files).
- **Engine** = `BinaryToRule(strict=True, classifier_path=None, device="cpu")`. With no classifier it runs on static candidates only (the Exp-2 `static` arm). It refuses to run without a goodware index.
- **Pinned data** in `data/isb/`: the Exp-2 `m4` operating point, copied 2026-10-14 and provenanced by sha256. Lookup order: `YARAIKIBA_ISB_DIR`, then `[tools.isb].dir`, then `[data].isb_dir`, then `data/isb`. The folder is gitignored.
- **WF10 pipeline:** quarantine_file → isb_candidates → isb_select (grammar, stoplist, goodware, ISB-A, k=8) → isb_plan (ISB-B) → isb_render_template (the default) or isb_render_taskmix (Llama-3.1-8B-TaskMix on vLLM, behind the IOC-fidelity guard, with the template rule as fallback) → validate_rule → scan_rule. A test pins the staged path to give exactly the same rule as `BinaryToRule.generate`.
- **Why template is the default:** Exp 2 measured Ministral at only 62.7% IOC fidelity on ISB prompts. That decision was taken 2026-10-13, and task 3 was brought back into scope.
- **Report path:** it uses only the candidate IR and grammar, with no goodware data (`pipelines/report_to_iocs.py`, `normalizer/ir.py`, `tools/multisample.py`, `naming.py`).
- **FP-risk view:** `insights/risk.py` loads the DF and span indexes.
- Training-side modules (mining, supervision, SalienceScorer training) are vendored but YARAikiba does not use them.
- Safety: static analysis only (pefile and byte reads). Samples are live malware and are never executed.

### 2.4 ISB vN, the pending replacement
- The legacy ISB in YARAikiba is frozen. **Don't touch the ISB data in the agent until the new ISB lands.**
- The handover note is `ISB_V2_HANDOVER.md`. Its old home `YARAikiba/build_log/` was archived to `~/archive/yaraikiba_cleanup_20261121.tar.zst` on 2026-11-21.
- vN should close the gaps logged in the roadmap: corpus conflicts (G1, G2), hard-coded paths (G3–G6), the task-3 gold rebuild (G7), and the missing reindex source (G8).
- Corpus: `~/corpus/ISB-Current-Corpus` plus `~/corpus/ISB-Corpus-Update`, or the Update folder alone, to be decided at integration. The corpus is growing and has no splits yet. Refresh policy is manual and pinned.
- **New on disk, not yet in memory:** `~/corpus/ISB/` (`Sherlock/`, `V1-Legacy/`, an enrichment spec, `ISB_DATASET_REVIEW_2026-11-22.md`) and `~/corpus/ISB-Sherlock-Dataset/{goodware,malware,metadata}`. This looks like the vN dataset build ("Sherlock"). I have not read it.

---

## 3. YaraGen memory (research package)

**Standing rules**
- Never change the `RuleGenerator` API without asking. It is shared by RQ7, RQ8, RQ9, and the e2e work. Fix the caller instead.
- For shared library code (`YaraGen/Training/*`), explain the change and its blast radius first, and edit only after approval.
- `tokenization_num_proc=None`, always. A pickled YaraAST tokenizer corrupts silently in map workers, so pre-tokenize offline.
- `yaramod` must be imported before `evaluate`/TF.
- In tests, never write to real data paths: redirect every path global into a tmpdir.
- Data-gen house style: a configurable class plus `executer(data_dir, output_dir)` that returns a summary dict.
- brownie submits all sbatch jobs. The login node has no SLURM binaries. brownie also does every git commit and push.
- Never execute malware samples.
- transformers 5.x needs `low_cpu_mem_usage=True` for 8B models.

**Model lines and results**
- **Curriculum:** seq2seq → rltraining (KL consistency) → module_grounding pass 3 v2. Humanization pass 3 covers the CanonicalSlots vocab gotcha.
- **YaraAST tokenizer:**
  - Warm-start bugs, now fixed: `warm_start_embeddings` never ran, and the lm_head was clobbered on resume. Both hit every earlier YaraAST model.
  - Decode spacing fixes, V7 `_join_parts` bugs.
  - AST-T5 curriculum (S1/S2/S3 prep verified, bundle for the H100 cluster).
  - Downstream G1–G4/P1 built on 11-10.
  - Multi-model order: BART → codet5p → t5gemma → Ministral 3B/8B. Slot canonicalisation is on everywhere. Tukey shuts down 12-14.
- **RQ6:** the Pass-2 winner is `RQ6-Pass2-Synth-Low-2p55M-0p50xR-YaraAST`. Pass 3 is a failure-mode feedback fine-tune.
- **RQ7:** task generalisation (generation, patching, humanized). Stage3-TaskGen matches the patching specialist, and the PatchV1 scooper adds +18 points on patching.
- **RQ8:** seq2seq beats causal, and BART leads when paired with a scooper.
- **RQ9:** 12 runs, Llama-3.1-8B and Ministral-3-8B × Gen/Patch/Mix × base/YaraAST tokenizer. Leaderboard figure shipped. The LLMScooper IOC-NER LoRA adapters beat the BiLSTM scooper.
- **Scoopers:** the V8 BiLSTM IOC-NER rebuild, and PatchV1 for patching.
- **ReportScooper (PDF IOC NER):** concluded. Champion `sweep_v13/M/ft/best.pt` at 0.8935 micro / 0.9246 macro. Public API: `ReportScooperInference`.
- **Data:** the canonical crawled-rule set is `Agent/Data/yara_malware_dataset_v2`, 73.7k rules (v1 deleted after A1). Other data work: CrawledAugmentation, 16 augmentation generators, and the failure-feedback oversampling pipeline.
- **Paper:** USENIX Sec27 cycle 1 was rejected. The resubmission plan is the security track with 3 pillars plus a survey. Gates: G1 (rerun bart_scooper Exp2), G2 (strict-equivalence re-tally).

**E2E experiments that feed ISB**
- **Exp 1** (report→rule): the extraction-bottleneck study. The `exp1/` harness folder is gone, and `ReportScooper/experiments/rq5_testset_export` (47 reports + gold) replaces it.
- **Exp 2** (binary→rule): the ISB study in §2.2. Corpus: `~/corpus/_manifest/corpus_manifest.csv`, split by family, temporally, F_train 22 / F_dev 6 / F_test 9. The bazaar Run IV kit grew the corpus to 6,806 samples.
- **bart_scooper:** kept as a separate model key, never a flag on `bart`. The 24/84 fault came from BART's max_position 1024 vs the 4096 input length. The fix: fatal device errors now abort the run instead of degrading it.

---

## 4. YARAikiba memory (agent + study platform)

**What it is.** A standalone co-analyst agent plus an A/B expert-study platform, in `YARAikiba/`. It copies code in and never imports across. The entry point is `YARAikiba/README.md` plus `docs/`, consolidated 11-21. PLAN, DEPLOY, and build_log were archived.

**Key decisions (brownie, 10-13 to 10-20)**
- The orchestrator is Ministral-3-8B-Instruct and writes prose. The generators write rules.
- Gen specialist = Ministral-8B (BaseTok). Patch specialist = LLaMA-8B (BaseTok). Both are served by vLLM 0.26.
- The scoopers are LoRA adapters plus token-classification heads, which vLLM cannot serve, so they run in a **PyTorch aux sidecar**.
- `VLLMRuleClient` mirrors RuleGenerator's Base/ALL/Parse modes and repairs, behind a parity gate. Patching runs with `postprocess=False`, and the default gen mode is Parse.
- **Task 3 (binary→readable rule) = ISB (WF10)**, with the template renderer as default and taskmix as an option.
- Workflow manager: a YAML catalog (WF1–WF17 today) plus a tool-trace panel. Expand clicks are logged as verification-behaviour data.
- Access: a login-protected proxy, per-analyst revocable access codes, a session limiter of 1–2 concurrent users, its own SQLite library.
- History is protected: protected principals are skipped by every purge, and backups are taken first. Protected ids are config-only, under `[study] protected_participants` in the gitignored config.toml.

**Study.** The design is in `docs/study-design.md` (4 tasks × 3 levels). It ran 2026-11-03 to 11-05 with 24 tasks. OFF = YARA docs only, ON = everything through the agent.

**Operational gotchas**
- **vLLM and Ministral:** vLLM uses attention scale 1.277 where HF uses 1.0, and the llama_4_scaling dict is missing. Fix both with `--hf-overrides` (the full rope dict, plus `apply_yarn_scaling: false`). Always run a logit check of vLLM against HF.
- **Live code:** the live 8443 server and aux sidecar lazily import from the working tree. Serve from a frozen snapshot while a build is running.
- **Scratch copies:** they keep the live config paths and ports. Every agent brief must demand redirected paths, dead ports (591xx), and `-m "not services"`.
- **Deploys:** brownie runs prod deploys (the 8443 window and the 8444 instance scripts). Claude prepares everything, hands over the `!` commands, then runs the health checks in `docs/deploy.md` §7.
- **Roles:** this session orchestrates build and review subagents. An approved review unlocks the next phase, and nothing gets built without a grant.
- **Failures:** on a fatal failure, write `YARAikiba/FATAL.md`, stop, and wait. No email.
- **Usage limit:** near 95% usage, start no new agents, park the running ones, and write the resume state.

**Release path.** V1 Beta (agent) → V1 Final.4 deployed (late October) → the study ran → roadmap items. The ISB-related roadmap items are ISB vN, rule-corpus quality, and the legacy Agent ingest path.

---

## 5. Where memory may be stale
- Status lines from August (the GPU runs "pending" in RQ4-v2) predate the wipe and restart. The ISB numbers in §2.2 are post-restart and were current as of 08-21.
- Today, ISB vN / "Sherlock" is the most active thread on disk, and memory has nothing on it beyond "the handover exists". If you walk me through the Sherlock build, I'll add a memory entry.
