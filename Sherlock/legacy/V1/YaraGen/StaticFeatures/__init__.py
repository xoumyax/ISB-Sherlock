"""StaticFeatures — one static-extraction pass, cached per sha256.

SAFETY: the corpus is live malware. Everything here is a **static read**
(``open(rb)`` + ``pefile`` on an in-memory buffer). Nothing executes a sample.

Pipeline position::

    corpus ──► extract_record ──► ExtractionCache (sharded JSONL)
                                       │
                                       ├─► emit.record_to_candidates  (static arm)
                                       └─► dfindex.build_df_index     (G_stats only)

Modules:

* :mod:`extract` — ``extract_record(path)``, never raises.
* :mod:`strings` — ASCII / UTF-16LE byte-scan extraction.
* :mod:`cache` — sharded, resumable JSONL record cache.
* :mod:`runner` — ``BatchExtractor``, parallel and resumable.
* :mod:`emit` — record → ``Candidate`` list (the ``static`` candidate source).
* :mod:`dfindex` — goodware document-frequency index.

Like ``YaraGen/ISB``, this package imports no ``yaramod``/``torch``/``evaluate``,
so it is import-order-safe from anywhere.
"""

from .cache import ExtractionCache
from .dfindex import (
    build_df_index,
    load_df_index,
    record_values,
    save_df_index,
)
from .emit import EmitConfig, record_to_candidates, records_to_candidates
from .extract import ExtractConfig, extract_record, record_schema_keys
from .runner import BatchConfig, BatchExtractor, WorkItem, cpu_default
from .strings import (
    MIN_STRING_LEN,
    extract_ascii_strings,
    extract_strings,
    extract_wide_strings,
)

__all__ = [
    "ExtractConfig", "extract_record", "record_schema_keys",
    "MIN_STRING_LEN", "extract_strings", "extract_ascii_strings",
    "extract_wide_strings",
    "ExtractionCache",
    "BatchExtractor", "BatchConfig", "WorkItem", "cpu_default",
    "EmitConfig", "record_to_candidates", "records_to_candidates",
    "build_df_index", "save_df_index", "load_df_index", "record_values",
]
