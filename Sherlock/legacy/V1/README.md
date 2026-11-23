# legacy/V1: the V1 ISB package (reference only)

These are the 12 modules of V1's `YaraGen/ISB` package from the V1-Legacy
archive, unmodified. `YaraGen/__init__.py` is an import shim added so that
`YaraGen.ISB` resolves here; it is not V1 code.

Rules:

* Read-only. Sherlock never imports from here. Fix nothing here.
* It is the style source for Sherlock and the parity oracle for gate G2.
* `tests/legacy/` runs V1's own suites against this copy (`pytest -m legacy`).

Not included, and needed if V1 is to be rerun for G2 (see DIRECTORY_MAP.md §7):
`YaraGen/StaticFeatures/`, `YaraGen/Detection/`, `YaraGen/RuleSynth/template.py`,
`YaraGen/Pipelines/BinaryToRule.py`, and V1's experiment artifacts. Copy any of
them in beside `ISB/` under `legacy/V1/YaraGen/`.

| File | sha256 |
|---|---|
| `ISB/__init__.py` | `4bb21baba523479fec16b46e947c135201a00ab8c6e9860e4d3283cf352095b9` |
| `ISB/budget.py` | `874e4eb1b52f84bb47be5d6a66d2e5da5ea3d83c9cf2ed97b14200ca91b36715` |
| `ISB/candidate.py` | `74d8e03afbdc6a9d938ea7992a67024a0956e72f41bc40a9f96408b76db4327d` |
| `ISB/condition.py` | `bb6f0a2f743ec3a1563ab0286d22c4e115ffeb761995c90fa8cd81a9ee0c8f2b` |
| `ISB/goodware.py` | `205ef5e3ff3a366d59e3bbe479c6790e5e625c7c2abf88f8d35d2316556f2f90` |
| `ISB/grammar.py` | `89f98b469f9be920663633ee5ba3599667cbe440f5cae87e428236f2990c37f6` |
| `ISB/isb.py` | `6a85435fe451d6761fed6d9f1d707cd8d0304178a16b7419e839ddf2f9667bdd` |
| `ISB/mining.py` | `3a1e8414640b1a0a8defcc2c943ccc7668d05efe50cc96a78bd5fd97bb56aa47` |
| `ISB/pooling.py` | `1ab92a1944a1156b0afc57570ab2fd2d2322cc275cc61a03c8a2768983a80ffc` |
| `ISB/salience.py` | `82aa4b209a7022769549fa75daef111121070e934290d75288b0914fe51bfed7` |
| `ISB/stoplist.py` | `f5a18cb31988e72321765777904e71a58646d035b15d41e64f1dac7452f6edb7` |
| `ISB/supervision.py` | `41eced270d78102a07c745a7268f2f3d8221b491fd63b30121d40c0e304077a1` |
