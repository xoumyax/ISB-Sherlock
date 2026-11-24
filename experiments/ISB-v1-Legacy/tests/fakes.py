"""A complete fake inputs tree and fake dataset. Synthetic bytes only."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any

from v1repro import acceptance, units

FAMS = ["fa", "fb"]


def sha(c: str) -> str:
    return c * 64


def rule(name: str, text: str) -> str:
    return f'rule {name} {{ strings: $a = "{text}" condition: $a }}'


def _write(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)


def template_rules() -> dict[str, Any]:
    return {
        "static__prevalence_k__fa": {
            "family": "fa",
            "arm": "prevalence_k",
            "candidate_source": "static",
            "source_text": rule("r", "ALPHA"),
            "n_strings": 1,
        },
        "classifier__prevalence_k__fb": {
            "family": "fb",
            "arm": "prevalence_k",
            "candidate_source": "classifier",
            "source_text": rule("r", "BETA"),
            "n_strings": 1,
        },
        "static__all__fa": {
            "family": "fa",
            "arm": "all",
            "candidate_source": "static",
            "source_text": rule("r", "ALPHA"),
            "n_strings": 20_000,
            "over_string_limit": True,
        },
    }


def generator_rules(tag: str) -> dict[str, Any]:
    gen = tag.rsplit("_", 1)[0]
    return {
        f"static__prevalence_k__fa__{gen}": {
            "family": "fa",
            "arm": "prevalence_k",
            "candidate_source": "static",
            "source_text": rule("g", "ALPHA"),
            "generator": gen,
            "n_strings": 1,
        },
        f"static__random_k__fb__{gen}": {
            "family": "fb",
            "arm": "random_k",
            "candidate_source": "static",
            "source_text": "rule broken { condition: }",
            "generator": gen,
            "n_strings": 0,
        },
        "static__all__fa": {
            "family": "fa",
            "arm": "all",
            "candidate_source": "static",
            "source_text": "  ",
        },
    }


#: Fake samples: name -> (bytes, split record or None, goodware record or None).
SAMPLES: dict[str, tuple[bytes, dict[str, Any] | None, dict[str, Any] | None]] = {
    sha("a"): (b"..ALPHA..", {"split": "F_dev", "side": "held", "family": "fa"}, None),
    sha("b"): (b"..BETA..", {"split": "F_dev", "side": "held", "family": "fb"}, None),
    sha("c"): (b"ALPHA", {"split": "F_dev", "side": "gen", "family": "fa"}, None),
    sha("d"): (b"ALPHA", {"split": "F_test", "side": "held", "family": "ft"}, None),
    sha("e"): (b"benign ALPHA", None, {"side": "G_eval", "source": "Win8"}),
    sha("f"): (b"benign", None, {"side": "G_eval", "source": "UCSB"}),
    sha("1"): (b"stats", None, {"side": "G_stats", "source": "UCSB"}),
}


def build_dataset(root: Path, missing: tuple[str, ...] = ()) -> None:
    rows = []
    for s, (data, _m, _g) in SAMPLES.items():
        rel = f"pool/{s[:2]}/{s}.bin"
        if s not in missing:
            _write(root / rel, data)
        rows.append({"sha256": s, "dataset_path": rel, "size": str(len(data))})
    path = root / "metadata/sherlock_manifest.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["sha256", "dataset_path", "size"])
        w.writeheader()
        w.writerows(rows)


def build_inputs(inputs: Path) -> None:
    mal = {"samples": {}}
    good = {"samples": {}}
    for s, (_d, m, g) in SAMPLES.items():
        if m:
            mal["samples"][s] = {**m, "is_pe": True, "path": f"v1/{s}.bin"}
        if g:
            good["samples"][s] = {**g, "is_pe": True, "path": f"goodware/{s}.exe"}
    _write(inputs / "artifacts/splits/malware_split.json", json.dumps(mal))
    _write(inputs / "artifacts/splits/goodware_split.json", json.dumps(good))
    _write(inputs / units.rules_rel("m4"), json.dumps(template_rules()))
    for tag in units.GENERATOR_TAGS:
        if tag != "m4":
            _write(inputs / units.rules_rel(tag), json.dumps(generator_rules(tag)))
    for variant in units.YARGEN_VARIANTS:
        for fam in FAMS:
            _write(
                inputs / f"artifacts/yargen/rules/{variant}/{fam}.yar",
                b"/* \x00 */\n" + rule(f"{variant}_{fam}", "ALPHA").encode(),
            )
    for spec in acceptance.SCANS.values():
        _write(inputs / spec["ref"], "{}")
    write_index(inputs)


def write_index(inputs: Path) -> None:
    lines = []
    for p in sorted(inputs.rglob("*")):
        if p.is_file() and p.name != "INPUTS.sha256":
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            lines.append(f"{digest}  {p.relative_to(inputs).as_posix()}\n")
    (inputs / "INPUTS.sha256").write_text("".join(lines))
