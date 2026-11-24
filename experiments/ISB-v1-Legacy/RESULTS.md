# V1 reproduction: results

Aggregate numbers only. Run records are in `runs/` (gitignored). All numbers
are F_dev, oracle-label condition, the same as V1's report.

## Stage 0: re-aggregation of V1's stored results (run `20261124T033112Z`)

**109 of 109 checks pass.** Every number was recomputed from the per-unit
integers in V1's stored `detection.json` files (`tp`, `n_held_family`,
`benign_match`, `benign_by_source`, `cross_match`). We didn't copy V1's stored
`grid`; we used it only as a cross-check, and it agrees for all 14 ladder rows.
A number passes when it equals the report at the report's printed precision.
The inputs come from `inputs/` (decision 3), and each one is checked against
`inputs/INPUTS.sha256`.

### R1: arm ladder, template generator (report tab:ladder)

Denominators: 522 held, 9,947 G_eval (2,867 Win8); 6 units per row.

| Source | Arm | TPR | FP/1k | Win8 FP/1k | Cross-fam | Result |
|---|---|---|---|---|---|---|
| classifier | all | 0.567 | 333.32 | 333.39 | 891 | pass |
| union | prevalence_k | 0.351 | 0.64 | 1.45 | 49 | pass |
| classifier | lint | 0.337 | 0.12 | 0.06 | 24 | pass |
| classifier | prevalence_k | 0.337 | 0.12 | 0.06 | 24 | pass |
| classifier | random_k | 0.337 | 0.17 | 0.00 | 24 | pass |
| classifier | learned | 0.303 | 0.15 | 0.00 | 24 | pass |
| classifier | analyst | 0.299 | 0.07 | 0.06 | 23 | pass |
| union | analyst | 0.261 | 0.37 | 0.41 | 40 | pass |
| static | prevalence_k | 0.249 | 0.64 | 1.51 | 47 | pass |
| static | analyst | 0.201 | 0.17 | 0.29 | 29 | pass |
| union | learned | 0.180 | 0.27 | 0.23 | 28 | pass |
| static | learned | 0.138 | 0.17 | 0.23 | 23 | pass |
| static | random_k | 0.054 | 0.00 | 0.00 | 17 | pass |
| union | random_k | 0.050 | 0.00 | 0.00 | 17 | pass |

### R2: renderability

There are 108 units in all. 84 of them compile and 24 can't be rendered; the
largest has 412,124 strings. All four numbers pass.

### R4: yarGen 0.25.0 (report tab:yargen)

| System | TPR | FP/1k | Win8 FP/1k | Result |
|---|---|---|---|---|
| yargen_stock | 0.747 | 253.85 | 72.26 | pass |
| yargen_gstats | 0.634 | 107.27 | 59.12 | pass |

The report text also passes:

- 1,755 yarGen rules across 12 sets, which is about 146 per family;
- 2.13 times the TPR of `union__prevalence_k`;
- 399 times its FP/1k;
- 2,164 times the FP/1k of `classifier__prevalence_k`.

### R7: generator grid, budgeted arms (report tab:gen)

All rows are planformat except the template, which V1 ran as describer (tag
`m4`). There are 72 budgeted units per generator: 4 arms times 3 sources times 6
families. **FP/1k (V1)** is V1's definition, the mean of the per-cell means
over the (source x arm) cells that compiled; decision 4 fixes it as the
acceptance number. The pooled per-unit mean and the raw benign-hit count sit
beside it for information. Only lfm2's pooled value (209.90) is a checked
number.

| Generator | TPR | FP/1k (V1) | Cmp. err | Result | FP/1k pooled | Benign hits |
|---|---|---|---|---|---|---|
| llama_taskmix | 0.236 | 0.23 | 0 | pass | 0.23 | 164 |
| ministral | 0.234 | 0.24 | 7 | pass | 0.23 | 147 |
| bart_scooper | 0.231 | 0.20 | 5 | pass | 0.20 | 132 |
| t5gemma_humanized | 0.227 | 0.23 | 0 | pass | 0.23 | 167 |
| lfm2_consistency | 0.430 | 193.27 | 10 | pass | 209.90 (pass) | 129,446 |
| bart | 0.239 | 0.31 | 1 | pass | 0.32 | 223 |
| bart_taskmix_base | 0.225 | 0.58 | 2 | pass | 0.53 | 366 |
| codet5p_consistency | 0.208 | 0.26 | 3 | pass | 0.26 | 178 |
| bart_taskmix_human | 0.207 | 0.78 | 8 | pass | 0.51 | 325 |
| bart_humanized | 0.241 | 11.46 | 5 | pass | 12.31 | 8,205 |
| llama1b_consistency | 0.222 | 0.09 | 32 | pass | 0.08 | 32 |
| template | 0.230 | 0.23 | 0 | pass | 0.23 | 164 |

llama1b's footnote also passes: 40 of its units were scanned. It has 11 cells,
because one cell lost every unit to compile errors.

R3, R5, R6, R8, R9 and R10 aren't part of Stage 0 here. R8 (fidelity) is in the
plan's Stage 0 but wasn't built in this round.

## Stage 1: re-score with V1's harness (not yet run)

On the login node, the dry run (`20261124T034042Z`) ran a stat-only target
check and compiled the rules. It scanned nothing.

| Corpus | Selected from V1's split | Resolved through the manifest | Stat ok, size equals manifest |
|---|---|---|---|
| F_dev held | 522 | 522 | 522 |
| F_dev gen | 527 | 527 | 527 |
| G_eval | 9,947 | 9,947 | 9,947 |

| Scan | Units | Compiled | Over the string limit | Compile errors | Error ids equal V1's |
|---|---|---|---|---|---|
| template | 108 | 84 | 24 | 24 | yes |
| yarGen | 12 | 12 | 0 | 0 | yes |
| generators | 1,956 | 1,734 | 24 | 222 | yes |

The scan itself is a SLURM job for brownie (`slurm/stage1.sbatch`).
