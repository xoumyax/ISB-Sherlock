# Baselines Sherlock is compared with (recorded 24 Nov 2026)

Baselines are measured beside Sherlock and never feed it (D11, amended 23 Nov). They
are compared at E1/P6 (gate G5: each baseline reproduces its documented behaviour).
Each runs in its own folder under `experiments/<tool>/`, as an untrusted tool: its own
env, run with `python -I` (or its own runtime), static reads of samples only, outputs
and data gitignored, docs and our driver code tracked.

| Baseline | Source | Version | Runtime | Status |
|---|---|---|---|---|
| V1 ISB (legacy) | `Sherlock/legacy/V1` + `ISB-V1-RAW.zip` | V1's final runs | `sherlock` env | Reproduction under way: `experiments/ISB-v1-Legacy/` (Stage 0 passed; Stage 1 job 58349) |
| yarGen | local clone of Neo23x0/yarGen | 0.25.0, commit 34c1464 | separate `yargen` env (lief, lxml, pefile) | V1's stock and G_stats DBs are in the zip; regeneration proposed as V1 Stage 3 |
| yarGen-Go | local clone of Neo23x0/yarGen-Go | commit 2efb973 (8 Feb 2026) | Go toolchain (not checked yet) | New baseline (brownie, 24 Nov) |
| AutoYara | local clone of FutureComputing4AI/AutoYara | 1.0-SNAPSHOT, commit c38be04 | Java/Maven (not checked yet) | Planned (E1) |
| AutoPYara | local clone of Botacin-s-Lab/AutoPYaraPyPI (brownie's own work, ACSAC 2026) | 0.1.3, commit dc08f3f | Python, own env | Planned (E1; E3's hex-only arm) |
| Frontier LLM | — | — | — | Planned (E1); prompts and samples' strings only, never samples or hashes sent out without brownie's approval (A4-style) |

Open, for when E1 is designed:
- the same splits for every tool (Sherlock's G1 split), with each tool's documented
  training input (yarGen: goodware DBs; AutoYara: its benign/malicious sets);
- the FP measure (per 1,000 goodware files on G_eval) and operating points;
- whether yarGen-Go reproduces yarGen 0.25.0 on the same input (a sanity check
  before it is used as a separate baseline).
