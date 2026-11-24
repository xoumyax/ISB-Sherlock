# YaraGen.StaticFeatures

One static extraction pass over each sample, cached by SHA-256. For every file
the package records its strings (ASCII and UTF-16LE), PE imports, exports,
sections, original file name, version metadata and imphash. It then turns the
record into ISB `Candidate` objects and builds the goodware indexes that ISB
uses to judge how generic a value is.

**Safety.** The samples are live malware. Everything here is a static read:
`open(path, "rb")` plus `pefile` on an in-memory buffer. Nothing runs, unpacks or
changes the permissions of a sample. Keep it that way.

## What is in this folder

| File | Role |
|---|---|
| `extract.py` | `extract_record(path)` and `ExtractConfig`. Never raises. |
| `strings.py` | `extract_strings`, `extract_ascii_strings`, `extract_wide_strings`, `MIN_STRING_LEN`. |
| `cache.py` | `ExtractionCache`: sharded, resumable JSONL cache (256 shards by the first two hex characters of the sha256). |
| `runner.py` | `BatchExtractor`, `BatchConfig`, `WorkItem`, `cpu_default`: parallel, resumable extraction. |
| `emit.py` | `record_to_candidates`, `records_to_candidates`, `EmitConfig`: record to `Candidate` list. |
| `dfindex.py` | `build_df_index`, `save_df_index`, `load_df_index`, `record_values`: goodware document-frequency index. |
| `spanindex.py` | `build_span_df`, `save_span_df`, `load_span_df`, `SpanIndexConfig`: byte-span presence over goodware, for hex spans. |
| `presence.py` | `build_presence_index`, `PresenceConfig`: byte presence of any candidate in goodware, measured the way YARA matches. |

`YaraGen.StaticFeatures` re-exports every module except `spanindex` and
`presence`. Import those two by module path.

## Public API

```python
from YaraGen.StaticFeatures import (
    extract_record, ExtractConfig, ExtractionCache,
    BatchExtractor, BatchConfig, WorkItem,
    record_to_candidates, EmitConfig,
    build_df_index, save_df_index, load_df_index,
)
```

| Call | Returns |
|---|---|
| `extract_record(path, config=None, expected_sha256=None)` | A `dict` with the keys `sha256`, `size`, `is_pe`, `strings_ascii`, `strings_wide`, `strings_truncated`, `imports`, `import_functions`, `exports`, `sections`, `pe_original_filename`, `pe_metadata`, `imphash`, `path`, `error`. `record_schema_keys()` returns this list. A broken file gives a partial record with `error` set. |
| `ExtractConfig(min_string_len=6, max_strings=20000, max_size_bytes=256 MiB, timeout_seconds=120, import_functions=True, max_import_functions=4000, max_exports=4000)` | Extraction limits. |
| `ExtractionCache(root, compress=False, max_cached_shards=8)` | Methods: `write_many(records)`, `get(sha256)`, `has(sha256)`, `existing_shas()`, `iter_records()`, `len(cache)`. |
| `BatchExtractor(cache, extract_config=None, batch_config=None, log=None).run(items)` | A summary dict: `n_requested`, `n_skipped_cached`, `n_extracted`, `n_written`, `n_errors`, `n_pe`, `errors_by_kind`, `seconds`. |
| `BatchConfig(workers=32, flush_every=500, chunksize=4, max_tasks_per_child=200, resume=True, log_every=2000)` | Parallelism and resume settings. |
| `WorkItem(sha256, path, meta={})` | One sample to extract. |
| `record_to_candidates(rec, config=None)` | `list[Candidate]` with `source="static"`. `records_to_candidates` maps over many records. |
| `build_df_index(records, source_of=None, per_source_cap=600, min_df=2, seed=20260809)` | `(DFIndex, meta)`. |
| `save_df_index(index, meta, out_dir, basename="goodware_df")` / `load_df_index(pkl_path)` | Writes `<basename>.pkl` and `.meta.json`; loads `(DFIndex, meta)`. |
| `build_span_df(hex_bodies, paths, config=None, progress=None)` | `(DFIndex, meta)`. Counts, per hex body, the goodware files that contain it. Uses `yara-python`. |
| `build_presence_index(candidates, paths, config=None, progress=None)` | `(DFIndex, meta)` for any candidate type. |

## Example

```python
import hashlib
from YaraGen.StaticFeatures import (BatchExtractor, BatchConfig, ExtractionCache,
                                    WorkItem, record_to_candidates, build_df_index)

path = "<path/to/sample-or-file>"
sha = hashlib.sha256(open(path, "rb").read()).hexdigest()

cache = ExtractionCache("<path/to/cache_dir>")
summary = BatchExtractor(cache, batch_config=BatchConfig(workers=4)).run(
    [WorkItem(sha256=sha, path=path)])
# {'n_requested': 1, 'n_extracted': 1, 'n_written': 1, 'n_errors': 0, ...}

rec = cache.get(sha)
cands = record_to_candidates(rec)        # list[Candidate], ready for ISB pooling

df, meta = build_df_index(cache.iter_records())   # run on goodware records only
```

## Inputs, outputs and data

- The cache is a directory of `<sha256[:2]>.jsonl` shards (or `.jsonl.gz` with
  `compress=True`). Only the parent process writes to it.
- Build the DF index from the **goodware statistics split only**. An index that
  has seen the goodware evaluation split scores against its own data. The index
  keys are case-folded and independent of type.
- `per_source_cap` samples at most that many files per source, so that one large
  goodware source cannot define what "generic" means.
- The span and presence indexes scan the **whole** goodware side. They have no
  per-source cap, because dropping files can only invent false "absent" results.

## Gotchas

- Resume does not retry failed samples. A file that was missing or over the size
  cap is cached with an `error`, and `existing_shas()` counts it. Delete its
  record, or run with `resume=False`, to try again.
- `BatchExtractor` uses `fork` multiprocessing and recycles workers
  (`max_tasks_per_child`) because `pefile` leaks on hostile input. The default
  is 32 workers. Set `workers` for your machine (`cpu_default()` gives a guess).
- Strings are stored by value, without offsets.
- `extract_record` uses `SIGALRM` for its time limit. The limit does nothing off
  the main thread.
- The package avoids `yaramod`, `torch` and `evaluate`, so import order does not
  matter here.

## Related

- [`../ISB/README.md`](../ISB/README.md) consumes the candidates and indexes.
- [`../SampleClassifier/README.md`](../SampleClassifier/README.md) trains on the cache.
- [`../Detection/README.md`](../Detection/README.md) scans the rules built from them.
- [`../../StaticFeatureExtractor/README.md`](../../StaticFeatureExtractor/README.md)
  is a separate, broader static IOC extractor.
- [`../../ReportScooper/README.md`](../../ReportScooper/README.md) covers the report side.
