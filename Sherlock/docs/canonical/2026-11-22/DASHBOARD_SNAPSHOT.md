# Dashboard snapshot, 2026-11-22

Read-only export of the canonical dashboard, **ISB and Sherlock: canonical project reference**
(https://claude.ai/artifact/FqLX93SwNaU43KhH9Yxa2Q). The dashboard is a private claude.ai page that Claude Code can't open; this file is
how a session on the cluster reads it. If this file and the dashboard disagree, the dashboard
wins: ask brownie for a fresh snapshot. Questions about where files live go to `DIRECTORY_MAP.md`.

Generated from the dashboard's datasets (the JSON files beside this one) and the page's own
text. Dataset figures come from the ISB dataset library review (manifest run 278, 25 Oct 2026).
Phases, experiments and decisions are proposals unless marked Decided. Dates were set before
the cluster move and may shift.

## Status at the checkpoint

| | |
|---|---|
| Unique files in the manifest | 117,944 (95,701 malware, 22,243 goodware) |
| Tier A families with ≥10 samples | 4 (v0 needs 40) |
| Tier X families with ≥20 executables | 315 (an upper bound until W1's TLSH recount) |
| Usable .NET goodware | 569 (the freeze needs 3,000) |
| G1 split freeze | 2026-12-13 (fallback 2026-12-20); 7 of 7 gating criteria open |

## 1. Data readiness

### Manifest pools

| id | pool | unique_files | executables | pe | dotnet | elf | non_exe | packed_pct |
|---|---|---|---|---|---|---|---|---|
| malware | Malware | 95,701 | 78,054 | 69,780 | 8,259 | 15 | 17,647 | 27.2 |
| goodware | Goodware | 22,243 | 22,234 | 20,189 | 575 | 1,470 | 9 | 45.1 |

### Label regimes

| id | regime | short | label | samples | families | ge10 | ge20 | ge40 | ge80 | eval_allowed |
|---|---|---|---|---|---|---|---|---|---|---|
| A | A | Tier A | Tier A: MOTIF exact hash + report provenance | 155 | 54 | 4 | 1 | 0 | 0 | Yes |
| X | X | Tier X | Tier X: MalwareBazaar signature, runs I–V (executables) | 17,845 | 315 | 315 | 315 | 301 | 38 | No (kit rule 8) |
| B | B | Tier B | Tier B: multi-engine consensus | 0 | 0 | 0 | 0 | 0 | 0 | Yes, as sensitivity |

### Targets

| id | target | min_samples | families | tier_a_families |
|---|---|---|---|---|
| v0 | v0 | 10 | 80 | 40 |
| v1 | v1 | 20 | 300 | 100 |

### Format balance

| id | format | malware_exes | usable_goodware | gap_1to1 |
|---|---|---|---|---|
| pe | PE (native) | 69,780 | 19,318 | 50,445 |
| dotnet | .NET | 8,259 | 569 | 7,690 |

### Routes to evaluation-grade labels

| Route | Tier | Blocked by | Unlocks | Status |
|---|---|---|---|---|
| Static config-extractor confirmation (CAPE parsers, MWCP, malduck) over the Tier X pool | A (confirmed) | A3: run extractors in a no-network container; count only full structured parses | A confirmed subset inside existing Tier X families, many of them .NET RATs and stealers | Week 1 (W9) |
| MOTIF disarmed archive (~1.47 GB) | A | Your approval (A2) | Report-derived families; header fields need re-arming | Awaiting approval |
| 33-file MalwareBazaar acquisition of MOTIF-matched hashes | A | Your approval (A2) | At most one more family above 10 samples | Awaiting approval |
| Malpedia sample-membership export | A | Request A4 (register.md #2) | Analyst-curated families; packed, unpacked and dumped triples | Request this week |
| VirusTotal academic, then ClarAVy/AVClass consensus | B | Request A4 (register.md #1) | Tier B labels, goodware vetting and real first-seen dates | Request this week |
| BODMAS / EMBER2024 label-only export | B | Request A4 to the maintainers; EMBER archives hold no label-only members | Tier B labels for hash-joined samples | Request this week |
| Analyst-report IOC appendices | A candidate | Manual review effort | Report-linked samples | Not started |
| Propagate Tier A labels through tight TLSH clusters, flagged | Propagated (training only) | W1 clusters: TLSH ≤ 30 with SDhash agreement | Training labels around the seed families; never an evaluation label | After W1 |

### Malware pool by origin

| Origin | Unique files | Label source | Tier A |
|---|---|---|---|
| vault_bb | 46,451 | None | 0 |
| vault_ucsb | 13,367 | None | 16 |
| bazaar_run5 (Run V) | 11,082 | MB signature (Tier X) | 18 |
| vault_ucsb_jp | 6,521 | None | 33 |
| vault_stefano | 5,698 | None | 5 |
| vault_codexgiga | 5,395 | None | 57 |
| bazaar_run4 | 4,549 | MB signature (Tier X) | 8 |
| bazaar_run1 | 1,903 | MB signature (Tier X) | 0 |
| bazaar_run2 (near-duplicate of run 1) | 1,903 | MB signature (Tier X) | 0 |
| vault_mlsec19/20/21, apts, evasive_it | 811 | None | 13 |
| bazaar_run3 | 304 | MB signature (Tier X) | 0 |
| bazaar_report_linked | 42 | MB signature + report link | 4 |

### Goodware pool by origin

| Origin | Executables | Vendor evidence | Paper use | Note |
|---|---|---|---|---|
| ucsb_goodware | 15,029 | 96.4 | Keep | V1 G_stats/G_eval backbone; re-split by vendor |
| windows_8_6.2.9200 | 2,868 | 99.5 | Keep | Newest OS image held; split by OS build |
| sourceforge | 1,062 | 42.7 | Keep | Weakest vendor evidence |
| cnet | 836 | 89.4 | Keep | — |
| softonic | 777 | 92.7 | Exclude | Barred from paper splits (kit rule 7); V1 used it |
| Ubuntu 26.04/26.10, Debian 13 | 1,470 | 0 | Out of scope | Unique ELF; no Windows benefit |
| winget expansion + pilot | 151 | 100 | Keep | Current Windows apps; 66 packages skipped at the 8 GiB cap |
| selfpacked_upx | 100 | 83 | Packer ablation | UPX children; excluded from the balanced view |

### Analyst rule sources

| Source | Rules | Rule names | Distinct hashes | SHA-256 in pool | Family metadata | Use |
|---|---|---|---|---|---|---|
| Elastic protections-artifacts | 3,069 | Kept | 5,640 | 12 | Every row | Family-matched supervision; review Elastic License 2.0 before releasing derived rules |
| Neo23x0 signature-base | 4,581 | Kept | 6,510 | 103 | 41 rows | Supervision; family parsed from rule names |
| YARA-Forge | 12,452 | Kept | 21,540 | 180 | 534 rows | Deduplicate first: 6,478 of signature-base's 6,510 hashes recur here |
| V1 crawled corpus (59 repos) | 305,697 | Stripped | — | — | None | V1 baseline for the analyst arm only |

## 2. Dataset enrichment

### Workstreams

| ID | Workstream | Improves the module by | Outputs | Done when | Start | End | Gates G1 | Needs |
|---|---|---|---|---|---|---|---|---|
| W1 | Near-duplicate collapse and family recount | Prevalence counts clusters, not near-duplicate variants; gives the real family sizes behind the 315-family upper bound | near_dup_clusters for every executable; families at TLSH 20, 30 and 50; cross-family conflict list | Every Tier X executable has a TLSH digest or a recorded reason, and the recount is published | 2026-11-23 | 2026-12-02 | Yes | Compute only |
| W2 | Alias adjudication and pool conflicts | Family-disjoint splits rest on correct alias groups, so cross-family features neither leak nor drag families together | alias_adjudications: decision, evidence, reviewer and date per component | The top 28 components and every W1 conflict have a decision; the other 229 are flagged provisional | 2026-11-30 | 2026-12-10 | Yes | W1 conflicts; your review |
| W3 | First-seen dates for drift | gen/held and the drift replay (E7) run on source dates, not inventory time; goodware dated by release | sample_dates; splits/drift_windows.json | 100% of Tier X has a source date; the windows file lists samples and families per window | 2026-11-23 | 2026-11-25 | Yes | Compute only |
| W4 | Analyst-rule string hits for supervision | Family-matched, offset-aligned positives for the scorer, replacing V1's name-stripped join | rule_meta; rule_string_hits; per-family coverage report; rule–label agreement for the circularity probe | The coverage report has a row for every Tier X family | 2026-11-24 | 2026-12-06 | Yes | Compute only |
| W5 | Windows OS goodware | The goodware index sees modern system and .NET Framework strings that malware borrows | Win10 22H2 and Win11 23H2 to G_stats; Win11 24H2 line and Server 2025 to G_eval; per-build counts, signers, overlap matrix | Each build counted (PE and .NET) with signer coverage and a cross-build overlap matrix | 2026-11-30 | 2026-12-09 | Yes | A1, A7 (A5 for update snapshots) |
| W6 | Linux goodware: PE and .NET in Linux packages | .NET runtime and SDK, PowerShell, Mono, Wine and signed EFI images add PE vendors with exact package provenance | goodware_provenance rows per package; Fedora 45 ELF in the separate ELF pool | PE and .NET yield counted per source; Fedora 45 ELF inventoried | 2026-12-01 | 2026-12-08 | Yes | A1, A8 |
| W7 | Third-party Windows and .NET goodware | Third-party apps carry most false-positive risk and the vendor diversity the split needs | winget plan finished and extended past 450 packages; NuGet top 2,000 with owner, signature and repository; installers to G_ood | winget complete at the raised cap; NuGet ingested; W5–W7 together pass the .NET target | 2026-11-30 | 2026-12-12 | Yes | A1 |
| W8 | UPX unpacking and the self-packed set | Packed samples yield payload candidates; known-packer goodware for the packer ablation (E5) | unpack_pairs; selfpack over UPX (two configs), MPRESS, Petite, kkrunchy, one protector and ConfuserEx | Every UPX-tagged file has an unpack status; three native packers and ConfuserEx reach 1,000 validated children | 2026-12-01 | 2026-12-12 | Yes | A5, A6 |
| W9 | Labels: config extraction, MOTIF, requests, propagation | A confirmed subset evaluation can defend; propagated labels feed training only | config_extractions; label_evidence; VirusTotal, Malpedia and EMBER/BODMAS requests | Config pass over Tier X and the vault; confirmed counts per family; three requests sent; MOTIF ingested if approved | 2026-11-23 | 2026-12-13 | No | A2, A3, A4 |

### Dates

| id | marker | date | kind | basis |
|---|---|---|---|---|
| m_req | Label requests sent | 2026-11-24 | Task | VirusTotal academic, Malpedia and BODMAS/EMBER2024 (A4) |
| m_tg | Thanksgiving (US) | 2026-11-26 | Holiday | Unattended compute (W1, W3, W4) fills this week |
| m_g1 | G1 split freeze | 2026-12-13 | Target | Freeze when every gating stop criterion passes |
| m_g1b | Fallback freeze | 2026-12-20 | Fallback | If a gating row is short, freeze a week later rather than lower a target; build phases shift by the same week |

### Stop criteria for the freeze

| Metric | Today | Target at the freeze | Gates G1 | From | Status |
|---|---|---|---|---|---|
| Tier X families with ≥10 independent samples (TLSH-30 clusters) | 315 before collapse, an upper bound | ≥80 (v0) | Yes | W1 | Open |
| Families with ≥20 independent samples | 315 before collapse | Reported; v1 targets 300 | No | W1 | Open |
| High-impact alias components adjudicated | 0 of 28 | 28 of 28, plus every W1 conflict | Yes | W2 | Open |
| Tier X executables with a source date | None loaded | 100% | Yes | W3 | Open |
| Analyst-rule coverage report | 626-row pilot | A row for every Tier X family | Yes | W4 | Open |
| G_stats goodware, vendor- and build-split, no Softonic | V1 had 10,620, including Softonic | ≥25,000 (v0) | Yes | W5–W7 | Open |
| Usable .NET goodware, all splits | 569 | ≥3,000; at zero FP that bounds .NET FP below 1 per 1,000 | Yes | W5–W7 | Open |
| G_eval goodware, vendor- and build-split | Not split yet | ≥30,000 (v0); can grow after the freeze with new vendors | No | W5–W7 | Open |
| Self-packed children per claimed packer | 100, UPX only | ≥1,000 each for three native packers and ConfuserEx | Yes | W8 | Open |
| UPX-tagged files with an unpack status | 0 | 100% | No | W8 | Open |
| Confirmed-subset families with ≥10 samples | 4 (Tier A) | Measured and reported | No | W9 | Open |
| External label requests sent | 0 of 3 | 3 of 3 | No | W9 | Open |

### Approvals needed from brownie

| ID | Approval | Recommendation | Needed by | Blocks | Status |
|---|---|---|---|---|---|
| A1 | Download cap (was D4) | Raise from 8 GiB to about 100 GiB, budgeted per source: Windows images ~20 GB, winget ~40 GB, NuGet and Linux packages the rest. Re-budget after the first 10% of each pull | Week 1 | W5, W6, W7 | Awaiting you |
| A2 | MOTIF archive and the 33-file acquisition (was D3) | Approve both | Week 1 | W9 | Awaiting you |
| A3 | Run third-party config extractors over malware | Approve, inside a no-network container with CPU, memory and time limits | Week 1 | W9 | Awaiting you |
| A4 | Send the VirusTotal, Malpedia and EMBER/BODMAS requests | Send under your name this week; nothing waits on the replies | Week 1 | W9 | Awaiting you |
| A5 | A Windows VM with no network | Provision one for Windows-only packers, ConfuserEx and image servicing | Week 2 | W8; W5 update snapshots | Awaiting you |
| A6 | Commercial protector for the packer ablation | Pick one (Themida, VMProtect, Enigma or Obsidium) after reading its trial EULA | Week 2 | W8 | Awaiting you |
| A7 | Source for Windows 10 22H2 and Windows 11 23H2 images | The university's Microsoft software portal or an existing licensed image | Week 2 | W5 | Awaiting you |
| A8 | ELF scope (was D8) | Keep ELF goodware as a separate pool, out of the paper's denominators | Week 2 | W6 | Awaiting you |

### Ground rules for every workstream

- Static only. No sample is executed. Parsers, unpackers and config extractors run in a container with no network and with CPU, memory and time limits.
- The manifest is the record. Every new fact is a row in manifest.sqlite, keyed by sha256, with a run id in the run log. Paths resolve through dataset_path in sherlock_manifest.csv and never appear in derived artifacts.
- Provenance on every label and goodware row: source, tool and version, and a tier (A, B, X or propagated). A propagated label never counts as an evaluation label.
- Dates come from sources, not inventory. first_seen_local is never a sample date (H6).
- Hashes only in anything released. Microsoft and third-party binaries stay on the cluster.
- Measure before collecting more. No new MalwareBazaar run until W1 reports real family counts.

## 3. V1 baseline

### Setup

| id | dev_families | held_samples | g_eval_files | scorer_pr_auc | prevalence_baseline | f_train_families | f_dev_families | f_test_families | labelled_samples |
|---|---|---|---|---|---|---|---|---|---|
| v1 | 6 | 522 | 9,947 | 0.171 | 0.038 | 23 | 6 | 9 | 6,806 |

### Results

| System | Arm | TPR | FP/1k |
|---|---|---|---|
| ISB V1 | union · prevalence_k | 0.351 | 0.64 |
| ISB V1 | classifier · prevalence_k | 0.337 | 0.12 |
| ISB V1 | classifier · learned | 0.303 | 0.15 |
| ISB V1 | classifier · analyst | 0.299 | 0.07 |
| ISB V1 | static · prevalence_k | 0.249 | 0.64 |
| ISB V1 | static · learned | 0.138 | 0.17 |
| yarGen | yarGen 0.25.0, G_stats DB | 0.634 | 107.3 |
| yarGen | yarGen, stock DB | 0.747 | 253.8 |

### What V1 hands to Sherlock

| Artifact | Contents | Verdict | Action |
|---|---|---|---|
| ISB/ (V1-Legacy, 12 modules) | 3,474 lines: IR, grammar, stoplist, pooling, goodware oracle, supervision, salience, mining, budget, conditions, arms | Reference | Style source and G2 parity oracle; its lessons become named tests (D11) |
| splits/malware_split.json | 38 families, 6,806 samples, family→split, gen/held | Partly | Keep the family→split assignment (EXTEND, D2), re-checked against W1 clusters and W2 decisions; drop path fields; labels are Tier X |
| splits/goodware_split.json | 20,567 files in G_stats/G_eval | Rebuild | Re-split from the manifest by vendor, without Softonic |
| cache/extract/ (4.9 GB) | Extraction for 6,806 labelled, 60,190 vault, 10,620 G_stats | Partly | Reuse by sha256; extract Run V (11,076), new goodware and .NET heaps |
| goodware/goodware_df.pkl | 868,903 values over 3,595 docs | Rebuild | Rebuild after G1: G_stats only, no Softonic, capped per source |
| isb__m4/goodware_spans.json | 5,849 spans | Rebuild | Rebuild after G1 from the new candidate set |
| classifier/…/best.pt | Byte-CNN, binary + family heads (AUC 0.941) | Partly | Binary head as-is; retrain the family head on the new F_train |
| isb__m4/analyst_terms.json | 287,372 terms from 305,697 rules, names stripped | Reference | V1 baseline only; named-rule sources replace it |
| isb__m4/supervision_table.json + salience | 511,663 rows, 3,497 positive; LightGBM, 12 features | Reference | Compare against; do not reuse |
| yargen/ | yarGen baseline outputs | Rebuild | Symlinks are dead; re-run with the G_stats DB and the stock DB |
| run_isb.py, run_exp2.py, phase0_corpus_splits.py … | V1 drivers | Reference | Not ported: Sherlock's cli/ replaces them with config roots (D11) |
| vault/ | Vault index, promiscuity and temporal studies | Reference | Background FP and promiscuity only |

## 4. Code: Sherlock from scratch

### What the fresh take changes

- The rule is the unit, not the candidate. Selection picks the set expected to cover the most held samples under the string cap (D12, proposed). V1 ranked candidates one at a time and forced breadth with a type round-robin.
- Persistence is what the scorer learns: will this candidate still be in newer samples? Support is counted over TLSH clusters (W1) and ordered by source dates (W3).
- Two independent supervision sources. Held persistence, which has real negatives, and family-matched analyst string hits (W4) stay separate arms, so agreement between them means something.
- Goodware is a constraint first. A strong string needs verified zero hits on G_stats; per-source rates feed the scorer second.
- Every occurrence keeps its origin: sha256, section and offset, so rule hits, spans and strings align.
- Data only through the manifest. No paths in code or artifacts, and leakage guards raise.

### How V1 is used

- Parity oracle at G2. On V1's 38-family split and goodware, Sherlock's all, lint and prevalence_k arms reproduce V1's F_dev numbers within tolerance before any new arm is compared.
- Lessons as tests. Each failure V1 measured becomes a named test, written before the module that could repeat it.
- Style source. The conventions below apply to every Sherlock module.
- Left behind. V1's drivers, hard-coded paths and supervision table.

### Module map

| Module | Does | V1 counterpart | What is new | Phase | Kind |
|---|---|---|---|---|---|
| core/ir.py | Candidate IR and type space; render form vs match form | candidate.py (411 lines) | Each occurrence keeps sha256, section and offset, so W4 hits align by offset; CType stays plain strings | P3 | Rewrite |
| core/records.py | Typed run records: selections, drop reasons, summaries; JSONL I/O | isb.py (Selection) | One record schema for every stage, written to runs/<experiment>/<arm>/ | P3 | Rewrite |
| data/manifest.py | sha256 → dataset_path from sherlock_manifest.csv; manifest.sqlite joined on sha256; split, cluster, date and label lookups | Drivers with hard-coded roots | No paths in artifacts (H7); manifest.sqlite's file_paths are dead old-cluster paths; guards raise when training code touches F_dev or F_test | P3 | New |
| extract/pe.py | Strings by section, imports, exports, rich header, resources, VersionInfo | V1 extraction cache | Reads V1's cache by sha256; strings keep section and offset | P3 | Rewrite |
| extract/dotnet.py | CLR metadata via dnfile: #Strings, #US, type and member refs, assembly info | — | Closes the .NET gap (D9) | P3 | New |
| extract/packing.py | DIE tag, section entropy, stub detection, unpacked-child links | — | Packer features for the scorer and E5, from W8's tables | P3 | New |
| extract/spans.py | Byte-CNN attribution spans | Classifier source | Family head retrained on the frozen F_train (D10) | P3 | Rewrite |
| grammar/express.py | Expressibility, escaping, modifier legality, rendering | grammar.py (476 lines) | Same rules, each test tied to a section of the YARA docs | P3 | Rewrite |
| grammar/hygiene.py | Curated stoplist and trivial-hex checks | stoplist.py (431 lines) | Active in every arm; type-aware | P3 | Rewrite |
| stats/support.py | Family pooling and support statistics | pooling.py (406 lines) | Support counted over TLSH-30 clusters (W1), not files; rates only | P3 | Rewrite |
| stats/goodware.py | Type-routed goodware oracle: string DF and span presence | goodware.py (105 lines) | Per-source caps from goodware_provenance; evidence kept per origin | P3 | Rewrite |
| learn/labels.py | Persistence labels: does a gen candidate survive into newer samples? | supervision.py (291 lines) | Time-ordered support from W3 dates; F_train only, guarded | P4 | Rewrite |
| learn/hits.py | Family-matched analyst evidence from rule string hits | mining.py (329 lines) | Offset-aligned W4 hits with real rule families replace the name-stripped term index | P4 | Rewrite |
| learn/scorer.py | GBDT persistence scorer with a prior fallback | salience.py (303 lines) | Grouped family holdout; tuned on F_dev only | P4 | Rewrite |
| select/cover.py | Pick the candidate set with the highest expected held coverage under the string cap | budget.py (159 lines) | Replaces pointwise ranking plus type round-robin (D12, proposed) | P4 | New |
| select/arms.py | The arm ladder: all, lint, prevalence_k, random_k, learned, analyst, oracle | isb.py (249 lines) | Same ordering rules; adds the coverage arm | P4 | Rewrite |
| cond/template.py | Strong and weak strings, N-of group, module terms | condition.py (198 lines) | Verified-absence rule kept | P5 | Rewrite |
| cond/adapter.py | Grammar-constrained condition adapter: pe, math, filesize, counts, .NET | — | Learns the condition shape; tuned on F_dev | P5 | New |
| gate/fp.py | FP gate on G_stats: repair or reject | — | Operating points 0, 0.1 and 1 FP/1k | P5 | New |
| eval/ | Namespaced compile, single-pass scan, bootstrap, paired tests, Holm | V1 drivers | Self-match excluded from TP by construction | P6 | New |
| cli/ | Drivers: extract, label, train, select, render, gate, scan | run_isb.py, run_exp2.py … | Config roots and run ids only; drivers log, library code returns records | P3–P6 | Rewrite |

### Code style carried over from V1

| Area | Convention | In V1 | Sherlock | Note |
|---|---|---|---|---|
| Module docstrings | One-line purpose, then the why: failure modes, measured numbers with their dates, and the spec section | supervision.py records the label tautology it measured (agreement 1.000000) | Keep | Cite RQ4v2 and enrichment-spec sections |
| Imports and exports | from __future__ import annotations; an explicit __all__ in every module; the package __init__ re-exports, grouped by module | __init__.py | Keep | — |
| Configuration | Frozen dataclass *Config with defaults; a #: comment on each knob saying why; a module-level DEFAULT_CONFIG | BudgetConfig.free_min_prevalence | Keep | YAML loads into the same dataclasses |
| Results | Small dataclasses with summary(), to_dict() and from_dict(); verdict objects are truthy | Expressibility, GoodwareVerdict | Keep | — |
| Type constants | Plain string constants on a class, not Enum, so JSONL round-trips need no conversion | CType | Keep | — |
| Errors | ValueError naming the fix for misuse; NotImplementedError instead of a silent fallback; leakage guards raise, never warn | random_k without size_match; analyst arm without a scorer | Keep | — |
| Unknown input | Degrade with a recorded reason rather than crash a run | canonical_ctype → unknown_type; dropped[reason] | Keep | — |
| Determinism | Fixed seed; per-family RNG Random(f"{seed}:{family}"); stable sorts tie-broken on candidate.key() | isb.py | Keep | — |
| Heavy dependencies | numpy and lightgbm imported inside functions; never yaramod at module scope (import-order clash with HF evaluate and TensorFlow) | salience.py, grammar.py | Keep | — |
| Typing | Full hints; abstract inputs (Sequence, Mapping), concrete returns (list, dict); X \| None | Every module | Keep | Add mypy on core/ and select/ |
| Layout | # -- section -- separators; private _helpers; about 88 columns | isb.py | Keep | Enforce with ruff |
| Logging | None in library code; records carry stats and drop reasons | No logging or print in any V1 module | Add | Module loggers in data/ and cli/ only; the library stays silent |
| Paths | Drivers hard-code corpus roots | run_isb.py, phase0_corpus_splits.py | Change | Config roots and manifest sha256 lookups only |
| Tests | Docstrings say "a test pins that"; tests were not in the archive | supervision.py | Add | pytest per module; each V1 lesson as a named test; parity fixtures |

### Lessons V1 paid for, carried in as tests

| ID | Lesson | What V1 measured | V1 module | Sherlock test |
|---|---|---|---|---|
| L1 | Render form and match form stay separate | Rendering the case-folded form writes rules that cannot match the sample | candidate.py | test_render_never_uses_norm |
| L2 | Hex spans go to the span index | The string index scores every span as absent from goodware, the very verdict that promotes it | goodware.py | test_hex_span_routed_to_span_index |
| L3 | Labels must not be computable from features | Support on the feature samples made the label equal prevalence ≥ 0.20 and no goodware: agreement 1.000000, PR-AUC 1.0 | supervision.py | test_label_support_from_held_side |
| L4 | Rates only, never raw support counts | n_containing out-ranked prevalence 2,292 to 199 by keying on family size | pooling.py | test_features_are_rates |
| L5 | Budget-exempt hashes need prevalence | guloader got 8 ranked candidates and 59 hash terms | budget.py | test_free_types_prevalence_gated |
| L6 | No plain top-k cut | 853 FP per 1,000 goodware: top candidates cluster in one type | budget.py | No top_k in the library; negative control only |
| L7 | Never any of them; strong strings need verified absence | One generic string made a gold rule match 5 of 5 goodware | condition.py | test_strong_requires_scored_absence |
| L8 | The stoplist runs in every arm | Generic section names are shorter than the DF index minimum, so DF never sees them | stoplist.py | test_stoplist_section_names |
| L9 | random_k is post-lint and matched on the budgeted count | A control drawn from another pool or size answers a different question | isb.py | test_random_k_matches_learned_budget |
| L10 | No silent fallbacks; peeking arms are flagged | An analyst arm that mirrored learned would fake independent agreement | isb.py | test_analyst_arm_requires_scorer |
| L11 | Scorer holdout grouped by family, with a minimum of positives | Row holdouts report memorisation; under 30 positives the prior scorer is used | salience.py | test_holdout_grouped_by_family |
| L12 | Leakage guards raise | A guard that defaults off is an accidental off-switch | pooling.py, supervision.py | test_eval_family_cannot_label |

### Layout (D6)

```
Sherlock/                 the repo (ISB_HOME): code, tests, docs; brownie commits
  sherlock/               core/ data/ extract/ grammar/ stats/ learn/ select/ cond/ gate/ eval/ cli/
  tests/                  legacy/ (V1 suites)  unit/  lessons/ (L1–L12)  parity/  integration/
  legacy/V1/              V1 ISB code, read-only: style source and parity oracle
  config/                 roots.example.yaml → roots.yaml (gitignored)
  docs/                   canonical/<date>/ (dashboard snapshot), gates/, sessions/, migration/, history/
  third_party/sdhash/     sdhash 3.4 with the jc_sdhash wrapper
ISB-Sherlock-Dataset/     the dataset (ISB_DATA), read-only: malware/ goodware/ metadata/
sherlock-work/            every derived artifact (ISB_WORK)
  manifest/               working copy of manifest.sqlite plus the enrichment tables
  enrich/W1 … W9/         workstream outputs before they load into the manifest
  splits/  cache/extract/  indexes/  supervision/  models/  parity/
  runs/<experiment>/<arm>/   reports/
```

## 5. Build plan

### Pipeline

1. **Front end:** PE and .NET parse: strings by section with offsets, imports, exports, rich header, resources, CLR heaps; packer features; byte-CNN spans
2. **Candidates:** Typed records with provenance per occurrence: sha256, section, offset (the RQ4v2 Candidate IR)
3. **Filter:** Expressibility and lint; every drop logged by type and reason
4. **Score:** GBDT persistence: will the candidate still be in newer samples? Cluster support, goodware rate, cross-family and packer features; analyst string hits as a second arm
5. **Select:** The set with the highest expected held coverage under a hard string cap (D12, proposed); type_cover kept as an arm
6. **Conditions:** Template, or a grammar-constrained adapter: strings with modifiers, pe, math, filesize, counts
7. **FP gate:** Scan G_stats; repair or reject any rule that fires
8. **Rule:** At a calibrated operating point, with per-string provenance

### Phases

| Phase | Name | Start | End | Deliverables | Gate | Gate date |
|---|---|---|---|---|---|---|
| P0 | Decide and set up | 2026-11-23 | 2026-12-04 | Migration acceptance on the new cluster (counts, hashes, permissions, working manifest copy); approvals A1–A8; D1–D12 recorded; sherlock env from environment.yml plus a lock file; Sherlock repo skeleton (package, config roots, ruff, mypy, pytest); V1 parity fixtures, if V1's artifacts were brought over | G0: on the new cluster, the skeleton resolves samples by sha256 through sherlock_manifest.csv and round-trips Candidate records; the legacy suite is green; V1 parity fixtures frozen | 2026-12-04 |
| P1 | Enrichment and split freeze | 2026-11-23 | 2026-12-13 | W1–W9: TLSH/SDhash collapse and recount; alias decisions; source dates and drift windows; analyst-rule string hits; Windows, Linux-shipped PE/.NET, winget and NuGet goodware; UPX unpacking and the self-packed set; config-extraction labels. Then the family-disjoint split (extending V1's 38) and the vendor- and build-disjoint goodware split without Softonic | G1: every gating stop criterion passes; splits frozen and hashed; no alias group, vendor, OS build or TLSH cluster straddles a split. Fallback date 20 Dec | 2026-12-13 |
| P2 | Post-freeze growth | 2026-12-14 | 2027-03-05 | Confirmed labels on already-placed samples (MOTIF, Malpedia, VirusTotal/ClarAVy, BODMAS/EMBER); G_eval and G_ood from new vendors; monthly cumulative-update snapshots (stretch); UPX header repair | Data cut: labels, G_eval and G_ood fixed for the experiment runs | 2027-03-05 |
| P3 | Core and front end | 2026-12-01 | 2027-01-22 | Sherlock core, data, extract (PE, .NET CLR, packing, spans), grammar and stats packages written fresh; V1 lessons as named tests; extraction cache reused by sha256; DF and span indexes on the frozen G_stats; byte-CNN retrain on the frozen F_train (GPU) | G2 parity: on V1's 38-family split, Sherlock's all, lint and prevalence_k arms reproduce V1's F_dev numbers within tolerance, every gap explained; then rerun on the new split | 2027-01-22 |
| P4 | Selection | 2027-01-11 | 2027-02-19 | Logged expressibility and lint; persistence labels on time-ordered support; family-matched analyst hits (W4); GBDT scorer; set-coverage selection (D12) beside type_cover; analyst arm with real rule families; packer-aware variant | G3 go/no-go: learned beats prevalence_k on F_dev TPR at matched FP/1k | 2027-02-19 |
| P5 | Conditions and FP gate | 2027-02-01 | 2027-03-12 | Template generator; grammar-constrained condition adapter (strings with modifiers, pe, math, filesize, counts, .NET); FP gate on G_stats with repair or reject; operating points; string caps | G4: every rule compiles; 0 FP on G_stats at the default point; no rule over the string cap | 2027-03-12 |
| P6 | Harness and baselines | 2027-02-15 | 2027-03-19 | Namespaced compile and single-pass scan; family-clustered bootstrap, paired tests, Holm; yarGen (G_stats DB and stock), AutoPYara, AutoYara, frontier-LLM baseline | G5: self-match excluded from TP; each baseline reproduces its documented behaviour | 2027-03-19 |
| P7 | Experiments | 2027-03-15 | 2027-05-14 | E1–E11 runs, drift replay, robustness subsets, figures | G6: every headline cell has a CI; confirmed-subset deltas computed | 2027-05-14 |
| P8 | Paper and artifact | 2027-04-26 | 2027-06-03 | Draft; anonymous artifact (hash lists, splits, rules, code); Open Science and ethics appendices | Submit to S&P 2028 Cycle 1 (est.); fallback USENIX Security '28 Cycle 1 (est.) | 2027-06-03 |

### Venue deadlines (projected)

| id | milestone | date | kind | basis |
|---|---|---|---|---|
| agent_ndss | Agent paper, NDSS 2028 (est.) | 2027-05-05 | Competing | Agent roadmap; NDSS 2027's summer cycle closed 6 May 2026 |
| sp28_c1 | S&P 2028 Cycle 1 (est.) | 2027-06-03 | Target | S&P 2026's Cycle 1 closed 5 Jun 2025 |
| sec28_c1 | USENIX Sec '28 Cycle 1 (est.) | 2027-08-24 | Fallback | USENIX Security '27 Cycle 1 closed 25 Aug 2026 |

## 6. Experiments

### Claims

| Claim | Statement | Evidence | Holds if | If it fails |
|---|---|---|---|---|
| C1 | ISB detects more held malware than existing rule generators at the same low false-positive budget | E1 | Higher family-macro TPR than every baseline at FP/1k ≤ 0.1; paired family-bootstrap CI excludes 0 | Report the TPR–FP frontier and where ISB dominates it |
| C2 | Learned selection adds detection beyond filtering and shorter rules | E2, E10 | Learned beats size-matched random-k and prevalence_k on F_test, CI excludes 0 | Reframe as prevalence-ranked selection plus grammar plus gate (V1's learned arm lost to prevalence_k) |
| C3 | Using the full YARA grammar beats hex-only and strings-only rules | E3, E4 | Higher TPR at equal FP/1k without more slow-rule warnings | Keep only the feature groups that add detection; report the rest as null results |
| C4 | Packer-aware selection removes false positives on packed goodware | E5 | Lower FP/1k on natural-packed and self-packed goodware at equal TPR | Report per packer; claim only where it holds |
| C5 | The gains are not an artifact of YARA-derived labels | E6 | C1–C2 deltas keep their sign within CI on the confirmed subset; circularity probe shows no concentration on rule-matched samples | Present Tier X results as an upper bound and say so in the abstract |
| C6 | A repair ladder keeps ISB near its starting quality for less than full retraining | E7 | TPR stays within the starting CI at FP/1k ≤ 0.1 across windows, at fewer GPU-hours than full retraining | Report the drift rate and the retraining point only |

### Experiment catalogue

| ID | Question group | Question | Arms | Metrics | Paper output | Priority | Can start |
|---|---|---|---|---|---|---|---|
| E1 | RQ1 Effectiveness | Does ISB reach higher TPR than existing generators at the same FP budget? | ISB at its default point vs yarGen (G_stats DB and stock DB), AutoPYara, AutoYara, frontier LLM given the same candidates, template (no LM) | Family-macro TPR on held; FP/1k on G_eval and G_ood; cross-family FP; TPR at FP/1k ≤ 0.1 | Main table; TPR–FP curves | Must | After G5 |
| E2 | RQ2 Attribution | Which stage earns the gain: filtering, shortening, ranking, conditions or the gate? | all (capped) → lint → random-k (post-lint, size-matched) → learned, pointwise + type_cover (V1) → learned, set coverage (D12) → + conditions → + FP gate; oracle-sel as ceiling | Δ TPR and Δ FP/1k per step; paired family bootstrap; Holm | Ablation ladder table | Must | After G5 |
| E3 | RQ3 Grammar | What does the full YARA grammar add over hex-only and strings-only rules? | Hex only (AutoPYara-style) vs strings vs + pe module vs + math, filesize, counts vs + .NET metadata | TPR at fixed FP/1k; strings per rule; slow-rule warnings; scan time | Gain per feature group | Should | After G5 |
| E4 | RQ3 Sources | Which candidate source carries detection: static strings, byte-CNN spans or both? | Static / classifier / union / analyst-endorsed; byte-CNN binary head vs retrained family head | TPR and FP/1k per source (V1: classifier spans beat static) | Source table | Should | After G5 |
| E5 | RQ4 Packing | Does packer-aware selection cut FP on packed goodware without losing TPR on packed malware? | Packer-aware vs packer-unaware ISB | FP/1k on natural-packed and self-packed goodware, per packer; TPR on packed vs unpacked malware | Per-packer FP figure | Must | After G5 |
| E6 | RQ5 Label robustness | Do the E1–E2 gains survive labels that are not YARA-derived? | Same deltas on Tier X, the confirmed subset, Tier B and label-free cluster-held evaluation; circularity probe | Sign and CI of each delta per regime; delta on held samples that public rules for F match vs those they miss | Robustness table | Must | After G5 and the data cut (P2) |
| E7 | RQ6 Drift | How fast does ISB degrade, and which repair rung restores it most cheaply? | Never / periodic / repair ladder (recalibrate → scorer → PEFT → full) / full at each trigger / oracle each window | TPR and FP/1k per quarterly window of source dates (W3), 2020–2026; FP drift on dated goodware builds; GPU-hours; retrains; forgetting on old families | Drift curves; cost table | Must | After G4 |
| E8 | RQ7 Operating points | Do calibrated FP budgets hold out of sample? | Calibrate FP/1k at 0, 0.1 and 1 on tune; test on G_eval and G_ood | Realized vs target FP/1k; TPR at each point | Calibration figure | Should | After G5 |
| E9 | RQ8 Cost | Is ISB cheap enough to run on a CPU-only laptop? | ISB stages vs yarGen vs LLM baseline | p50/p95 latency per sample; peak memory; rules per hour; rule scan cost | Cost table | Should | After G5 |
| E10 | Diagnostic | What does the scorer learn? | Feature importance; PU class-prior sweep; pointwise vs set-coverage selection at matched k | PR-AUC vs prevalence baseline (V1: 0.171 vs 0.038); gain importances | Feature-importance figure | Could | After G3 |
| E11 | Optional | Would analysts deploy the rules? | Blind review of a sample of rules per arm by several analysts | Would-deploy rate; edits needed; inter-rater agreement | Small user-study table | Could | After G6 |

### Dependencies

| ID | Experiment | Frozen split (G1) | Rule string hits (W4) | Source dates (W3) | Goodware (W5–W7) | Self-packed set (W8) | Confirmed labels (P2 cut) | .NET extractor (P3) | Scorer (P4) | Conditions + gate (P5) | Baselines (P6) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| E1 | Effectiveness | ● |  |  | ● |  |  | ● | ● | ● | ● |
| E2 | Attribution | ● | ● |  | ● |  |  | ● | ● | ● |  |
| E3 | Grammar | ● |  |  | ● |  |  | ● | ● | ● | ● |
| E4 | Sources | ● | ● |  | ● |  |  |  | ● | ● |  |
| E5 | Packing | ● |  |  | ● | ● |  |  | ● | ● |  |
| E6 | Label robustness | ● | ● |  | ● |  | ● | ● | ● | ● | ● |
| E7 | Drift | ● |  | ● | ● |  |  |  | ● | ● |  |
| E8 | Operating points | ● |  |  | ● |  |  |  | ● | ● |  |
| E9 | Cost |  |  |  |  |  |  |  | ● | ● | ● |
| E10 | Scorer diagnostic | ● | ● |  |  |  |  |  | ● |  |  |
| E11 | Analyst review | ● |  |  |  |  |  |  | ● | ● | ● |

### Evaluation protocol

- The family is the unit: macro-average over families, with the per-family table in the appendix.
- TPR is measured on held samples only; a rule matching its own source never counts.
- False positives per 1,000 files on G_eval and G_ood, with corpus sizes fixed across arms and raw counts beside the rates. Cross-family matches are reported separately.
- Family-clustered bootstrap CIs and paired tests on every headline cell, Holm–Bonferroni within each metric family.
- Every threshold, k, checkpoint and operating point is set on the tune split, never on the reported scope.
- Tier X results are labelled AV/YARA-derived, and every claim is re-run on the confirmed subset.

## 7. Decisions and risks

### Decisions

| ID | Decision | Recommendation | Unblocks | When | Status |
|---|---|---|---|---|---|
| D11 | Sherlock from scratch | Rewrite in V1's style. V1 stays runnable as the parity oracle for G2 and as the record of every lesson it paid for | P0, P3 | 22 Nov | Decided |
| D1 | Label regime for training vs evaluation | Hybrid. Train and tune on Tier X; report Tier X headlines as AV/YARA-derived upper bounds; every claim must hold on the confirmed subset. Don't wait for labels to start the build | P1 splits; E1, E2, E6 | This week | Recommended |
| D3 | MOTIF archive and the 33-file acquisition (A2) | Approve both: the cheapest Tier A gain. Re-arm or drop pe.machine and pe.subsystem for the disarmed files | W9; E6 confirmed subset | This week | Recommended |
| D4 | Download cap and Windows image source (A1, A7) | Raise to about 100 GiB, budgeted per source; Windows 10/11 from the university portal, the 24H2 line and Server 2025 from the Evaluation Center | W5–W7 | This week | Recommended |
| D7 | Which environment Sherlock runs in | Clone yaraikiba into a sherlock env; add tlsh, python-magic and dnfile | P0, P3 | This week | Recommended |
| D8 | Linux/ELF scope (A8) | ELF out of the paper (15 malware files). ELF goodware is a separate pool, out of FP denominators; Linux-shipped PE and .NET files join the Windows pools | W6 | By G0 | Recommended |
| D2 | Keep V1's 38-family assignment or re-split | EXTEND: freeze V1's 38 assignments so its F_test stays unseen; assign the other families by median source date, 60/16/24, over alias groups after W1–W2 | G1 splits; G2 parity | By G0 | Recommended |
| D6 | Sherlock data layout | sha256-keyed and manifest-driven; no paths in artifacts; one run folder per experiment and arm (layout in the Code section) | P0, P3 | By G0 | Recommended |
| D9 | .NET handling | A CLR metadata extractor (#Strings, #US, type and member refs, assembly info); report .NET separately | P3; E3, E6 | By G0 | Recommended |
| D5 | Alias components and pool conflicts (W2) | Do the 28 high-impact components and every W1 conflict before the freeze; keep the 17 pool conflicts excluded unless signer evidence is unambiguous | G1 alias groups | Before G1 | Recommended |
| D10 | HEX_SPAN (byte-CNN) arm | Keep it: V1's classifier spans beat static strings on TPR and FP. Binary head now; retrain both heads on the frozen F_train in P3 | P3; E4 | Before G1 | Recommended |
| D12 | Selection objective | Choose the set of candidates that maximizes expected held coverage under the string cap, using the scorer's persistence probabilities; keep type_cover and prevalence_k as arms and pick at G3 on F_dev | P4; E2, E10 | Before P4 | Proposed |

### Risks

| ID | Risk | Evidence | Mitigation |
|---|---|---|---|
| R1 | Too few independent labels | 4 Tier A families have ≥10 samples; v0 needs 40 | W9 config extraction now; MOTIF (A2); requests (A4); report Tier X as an upper bound |
| R2 | Learned scorer may not beat a prevalence heuristic | V1 TPR: learned 0.138 vs prevalence_k 0.249 (static); 0.303 vs 0.337 (classifier) | Persistence labels on cluster-level support; set-coverage selection (D12); go/no-go at G3; if it fails, reframe C2 |
| R3 | FP rates optimistic for .NET and packed software | 569 usable .NET goodware files vs 8,259 .NET malware | W5–W7 to ≥3,000 .NET files before the freeze; W8 self-packed set; FP per format, PE subtype and packer |
| R4 | Tier X family sizes inflated | No TLSH collapse or alias review yet; 315 is an upper bound | W1–W2 recount before the freeze; a sixth MalwareBazaar run only for families below 10 clusters |
| R5 | Rule blow-up | V1 static all/lint rules never compiled (>10,000 strings) | Hard string caps; the all arm capped and labelled degenerate |
| R6 | Schedule clash with the agent paper | Agent paper targets NDSS (est. early May 2027), the same weeks as the experiments | Freeze ISB data at G1 (13 Dec); run the drift replay unattended on the cluster |
| R7 | Disarmed MOTIF binaries distort pe conditions | Zeroed machine and subsystem header fields | Re-arm from metadata or exclude those pe fields for MOTIF files |
| R8 | Collection outruns the freeze | Nine workstreams in three weeks, with Thanksgiving in week 1 | Gate on the seven gating rows only; fallback freeze 20 Dec; G_eval and labels grow afterwards |
| R9 | Agent sandbox can't reach the network or submit SLURM jobs | DNS failures in runs 268 and 274 | Run pulls and sbatch from your own shell; agents prepare scripts and verify outputs |
| R10 | OS and NuGet files swamp the goodware index | Microsoft strings would dominate the DF statistics | Cap each source in the index; report FP per origin and per PE subtype |
| R11 | Circular confirmed labels | Some extractors run only after a YARA hit | Count only full structured parses; circularity probe in E6 |
| R12 | The rewrite slips the build | 3,474 lines of V1 to redo, from scratch | Port V1's lessons as tests first; G2 parity on V1's split before anything new; V1 stays runnable |
| R13 | The move delays enrichment or strands V1's artifacts | V1's experiment artifacts, YaraGen/StaticFeatures and the corpus project's memory notes were not in the migration set (DATASET_STRUCTURE.md §8) | Copy V1's split files, exp2 outputs and goodware indexes before decommissioning; start W1 and W3 from metadata.zip, which needs no sample extraction |

## 8. Documents and plan changes

### Documents

| Document | Role | Holds | Where |
|---|---|---|---|
| This dashboard | Canonical | Plan, dates, gates, decisions, risks and status. Wins on any conflict about the plan | Here |
| DIRECTORY_MAP.md | Canonical | Where everything lives on the new cluster: roots, repo, dataset and work tree. Wins on any conflict about layout | Sherlock repo root |
| CLAUDE.md | Supporting | Guidebook for Claude Code: working rules, safety, style, tests and inherited lessons | Sherlock repo root |
| DATASET_STRUCTURE.md | Source | The migrated dataset: folders, counts, manifest columns and setup steps | Archive folder; copy in docs/dataset/ |
| ISB dataset enrichment spec | Supporting | Procedures, commands and manifest tables for W1–W9 | Claude Doc |
| RQ4v2_SPEC.md | Supporting | Evaluation protocol, Candidate IR, split definitions, type-and-shape prior | YARA-LLM project docs |
| ISB_DATASET_PLAN.md | Supporting | v0 and v1 sizes, rule of three, packer list; its schedule is superseded here | YARA-LLM project docs |
| ISB dataset library review, 22 Nov 2026 | Source | Every "today" figure (manifest run 278) | metadata/project_state/ in the dataset |
| V1-Legacy ISB package | Reference | 12 modules, 3,474 lines: the style source and G2's parity oracle | legacy/V1 in the Sherlock repo |
| Agent chapter roadmap | Related | The next paper and the open-source release; shares schedule risk R6 | Claude Doc |

### Plan changes

| Date | Change | Why | Affects |
|---|---|---|---|
| 2026-11-22 | G1 split freeze moves from 8 Jan 2027 to 13 Dec 2026, with 20 Dec as fallback | Enrichment W1–W9 replaces the P1 data foundation and fits in three weeks | P1, P2, R6 |
| 2026-11-22 | Windows, Linux-shipped PE/.NET and NuGet goodware, and the self-packed set, land before the freeze | Anything that feeds G_stats must be in before the split; afterwards only new-vendor G_eval/G_ood and labels may grow | P2, E5, stop criteria |
| 2026-11-22 | Sherlock is written from scratch in V1's style; V1 becomes the parity oracle | Your decision (D11) | G0, G2, P3, Code section |
| 2026-11-22 | The scorer gains family-matched analyst string hits; set-coverage selection proposed | V1's learned arm lost to prevalence_k; named rule sources make family matching possible | P4, D12, E2, E10 |
| 2026-11-22 | Source dates (W3) replace inventory time; drift windows are cut before the freeze | E7 and gen/held need real dates (finding H6) | E7, dependencies |
| 2026-11-22 | Approvals A1–A8 carry D3, D4 and D8 and add five more | They gate the enrichment workstreams | Decisions |
| 2026-11-22 | The project moves to a new cluster from the 22 Nov checkpoint, before enrichment; Sherlock starts there from an empty package | Your decision. The dataset travels as 113 verified archives with relative paths; old-cluster paths are dead | P0, P1 dates, R13 |
| 2026-11-22 | The D6 layout splits into a code repo and separate data and work roots, mapped in DIRECTORY_MAP.md | The repo stays small and versioned; derived artifacts go where the space is | D6, Code section |

## Definitions

- **Tier A:** A family label from a mechanism independent of signatures: MOTIF report hashes, Malpedia, or a structured config parse. Allowed for evaluation.
- **Tier B:** Multi-engine AV consensus (ClarAVy or AVClass). Allowed as a sensitivity regime.
- **Tier X:** MalwareBazaar signature, often derived from YARA hits. Barred from evaluation by kit rule 8.
- **Confirmed subset:** Tier X samples whose family a Tier A or Tier B source agrees with.
- **F_train / F_dev / F_test:** Family-disjoint splits over alias groups.
- **gen / held:** Older and newer halves within a family: rules are built from gen and scored on held.
- **G_stats / G_eval / G_ood:** Goodware for statistics and the FP gate, for measuring FP, and out-of-distribution software such as installers and packed commercial apps. Split by vendor and OS build.
- **FP/1k:** Benign files a rule set matches, per 1,000 benign files scanned.
- **prevalence_k:** V1's prevalence-ranked top-k selection arm.
- **random-k:** A random draw from the post-lint pool, the same size as the learned selection for that family.
- **oracle-sel:** Candidates a human rule for the family matches; an upper bound on selection.
- **TLSH-30 cluster:** Samples linked at TLSH distance ≤ 30, taken as connected components within a family; family size counts clusters, not files.
- **Propagated label:** A label copied from a Tier A or config-confirmed seed to a near neighbour. Training only, never an evaluation label.
- **G1 freeze rule:** After G1, labels on placed samples and new-vendor goodware in G_eval and G_ood may still be added; family membership, gen/held, alias groups and G_stats may not change.
- **Persistence:** Whether a candidate seen in a family's older samples is still present in its newer ones: what Sherlock's scorer predicts.
- **Set coverage:** Selecting the candidate set whose union is expected to match the most held samples, instead of ranking candidates one by one (D12).
- **Parity oracle:** V1 run on its own split; Sherlock must reproduce its numbers at G2 before any new arm is compared.
- **Circularity probe:** The learned-vs-reference delta, split by whether public rules for the family match each held sample.
