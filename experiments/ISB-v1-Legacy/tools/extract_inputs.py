"""Extract the Stage 1 inputs from the untrusted V1 zip into ``inputs/``.

Decision 3 (DECISIONS.md): extract once, strip the long prefix, hash every
file into ``inputs/INPUTS.sha256``, then make the folder read-only (the chmod
is done by the caller: ``chmod -R a-w inputs/``).

Safety:
* an exact allow-list of members; no globbing (a glob would pull in
  ``exp2__smoke``), no ``extractall``;
* every member name in the zip is checked for absolute paths, ``..``,
  backslashes and symlink mode before anything is written;
* members are streamed with ``ZipFile.open``; files are created with ``x`` mode,
  so nothing is overwritten; the destination must be absent or empty;
* the split JSONs are checked against their ``.sha256`` companions.

Run as: ``python -I tools/extract_inputs.py --zip <zip> --dest inputs``.
"""

from __future__ import annotations

import argparse
import hashlib
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath

#: The zip stores V1's tree under a long home-folder prefix ending in this; the
#: full prefix is read from the zip, so no home path is written here.
PREFIX_TAIL = "finalexperimets/e2e-experiment/"

#: The 22 generator x prompt-style tags, as job 95929 scored them (smoke excluded).
GENERATOR_TAGS = [
    f"{model}_{style}"
    for model in (
        "bart",
        "bart_humanized",
        "bart_scooper",
        "bart_taskmix_base",
        "bart_taskmix_human",
        "codet5p_consistency",
        "lfm2_consistency",
        "llama1b_consistency_step25934",
        "llama_taskmix",
        "ministral",
        "t5gemma_humanized",
    )
    for style in ("describer", "planformat")
]
FAMILIES = ["amadey", "gcleaner", "guloader", "lummastealer", "njrat", "quasarrat"]
CHUNK = 1 << 20


def allow_list() -> list[str]:
    """Every member to extract, relative to the zip prefix."""
    members = [
        "artifacts/exp2__m4/rules.json",
        "artifacts/exp2__m4/run_summary.json",
        "artifacts/exp2__m4/detection.json",
        "artifacts/exp2_all/detection.json",
        "artifacts/yargen/detection.json",
        "artifacts/yargen/run_summary.json",
    ]
    for tag in GENERATOR_TAGS:
        members += [
            f"artifacts/exp2__{tag}/rules.json",
            f"artifacts/exp2__{tag}/run_summary.json",
        ]
    for variant in ("gstats", "stock"):
        members += [f"artifacts/yargen/rules/{variant}/{fam}.yar" for fam in FAMILIES]
    for split in ("goodware_split", "malware_split"):
        members += [
            f"artifacts/splits/{split}.json",
            f"artifacts/splits/{split}.sha256",
        ]
    return members


def unsafe_reason(info: zipfile.ZipInfo) -> str | None:
    """Why a member name or mode is unsafe to write, or None."""
    name = info.filename
    if "\\" in name or "\x00" in name:
        return "backslash or NUL in name"
    path = PurePosixPath(name)
    if path.is_absolute() or name.startswith("/"):
        return "absolute path"
    if any(part == ".." for part in path.parts):
        return "parent reference"
    mode = info.external_attr >> 16
    if mode and stat.S_ISLNK(mode):
        return "symlink member"
    return None


def find_prefix(zf: zipfile.ZipFile) -> str:
    """The one member-name prefix ending in ``PREFIX_TAIL``; else refuse."""
    found = {
        i.filename[: i.filename.index(PREFIX_TAIL) + len(PREFIX_TAIL)]
        for i in zf.infolist()
        if PREFIX_TAIL in i.filename
    }
    if len(found) != 1:
        raise RuntimeError(f"expected one V1 prefix in the zip, found {len(found)}")
    return found.pop()


def check_zip(
    zf: zipfile.ZipFile, wanted: list[str], prefix: str
) -> dict[str, zipfile.ZipInfo]:
    """Check every member; return the wanted ones. Raise on any problem."""
    bad = {i.filename: r for i in zf.infolist() if (r := unsafe_reason(i))}
    by_name = {i.filename: i for i in zf.infolist()}
    picked: dict[str, zipfile.ZipInfo] = {}
    for rel in wanted:
        full = prefix + rel
        if full in bad:
            raise RuntimeError(f"unsafe member {rel!r}: {bad[full]}")
        if full not in by_name:
            raise RuntimeError(f"member missing from zip: {rel!r}")
        if by_name[full].is_dir():
            raise RuntimeError(f"member is a directory: {rel!r}")
        picked[rel] = by_name[full]
    if bad:
        # Not extracted, but a zip with hostile names deserves a stop.
        raise RuntimeError(f"{len(bad)} unsafe member names in the zip; refusing")
    return picked


def safe_target(dest: Path, rel: str) -> Path:
    target = (dest / rel).resolve()
    if not target.is_relative_to(dest.resolve()):
        raise RuntimeError(f"member escapes destination: {rel!r}")
    return target


def extract_one(zf: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path) -> str:
    """Stream one member to ``target`` (new file only); return its sha256."""
    target.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with zf.open(info) as src, open(target, "xb") as out:
        while chunk := src.read(CHUNK):
            digest.update(chunk)
            out.write(chunk)
    if target.stat().st_size != info.file_size:
        raise RuntimeError(f"size mismatch for {info.filename!r}")
    return digest.hexdigest()


def check_split_hashes(dest: Path, hashes: dict[str, str]) -> None:
    for split in ("goodware_split", "malware_split"):
        rel = f"artifacts/splits/{split}"
        expected = (dest / f"{rel}.sha256").read_text().split()[0].strip()
        if hashes[f"{rel}.json"] != expected:
            raise RuntimeError(f"{split}.json does not match its .sha256")


def write_index(dest: Path, hashes: dict[str, str]) -> None:
    lines = [f"{hashes[rel]}  {rel}\n" for rel in sorted(hashes)]
    with open(dest / "INPUTS.sha256", "x") as fh:
        fh.writelines(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--zip", required=True, type=Path)
    ap.add_argument("--dest", required=True, type=Path)
    args = ap.parse_args(argv)
    dest: Path = args.dest
    if dest.exists() and any(dest.iterdir()):
        raise SystemExit(f"refusing: {dest} exists and is not empty")
    dest.mkdir(parents=True, exist_ok=True)
    wanted = allow_list()
    with zipfile.ZipFile(args.zip) as zf:
        picked = check_zip(zf, wanted, find_prefix(zf))
        hashes = {
            rel: extract_one(zf, info, safe_target(dest, rel))
            for rel, info in picked.items()
        }
    check_split_hashes(dest, hashes)
    write_index(dest, hashes)
    total = sum(i.file_size for i in picked.values())
    print(
        f"extracted {len(hashes)} files, {total / 1e6:.1f} MB; "
        f"split hashes verified; INPUTS.sha256 written"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
