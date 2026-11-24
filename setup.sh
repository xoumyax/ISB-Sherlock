#!/usr/bin/env bash
# Set up Sherlock for one user on one cluster, from a fresh clone or again later:
# the `sherlock` conda env, the three roots in Sherlock/config/roots.yaml, the
# directory skeleton (roots, work tree, empty repo folders) and a legacy-suite
# health check.
#
#   ./setup.sh --data DIR --work DIR --scratch DIR     # explicit roots
#   ./setup.sh --beside-repo                           # roots next to Sherlock/:
#                                                      #   ISB-Sherlock-{Data,Work,Scratch}
#   ./setup.sh                                         # re-run: reuse roots.yaml
# Options:
#   --env-only     build or update the env, write nothing else
#   --update-env   rebuild the env even if it already exists
#   --force        overwrite an existing config/roots.yaml
#   --no-tests     skip `pytest -m legacy`
#
# There are no default paths (CLAUDE.md §4): either pass the three roots or opt in
# to --beside-repo. The dataset itself is fetched by ./download.sh. This script
# never touches samples and never writes under the dataset root.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO="$HERE/Sherlock"
ENV_NAME=sherlock

die() { echo "setup.sh: $*" >&2; exit 1; }
say() { echo "==> $*"; }
usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }

DATA="${ISB_DATA:-}"; WORK="${ISB_WORK:-}"; SCRATCH="${ISB_SCRATCH:-}"
ENV_ONLY=0; UPDATE_ENV=0; FORCE=0; TESTS=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --data) DATA="$2"; shift 2 ;;
        --work) WORK="$2"; shift 2 ;;
        --scratch) SCRATCH="$2"; shift 2 ;;
        --beside-repo)
            DATA="$HERE/ISB-Sherlock-Data"; WORK="$HERE/ISB-Sherlock-Work"
            SCRATCH="$HERE/ISB-Sherlock-Scratch"; shift ;;
        --env-only) ENV_ONLY=1; shift ;;
        --update-env) UPDATE_ENV=1; shift ;;
        --force) FORCE=1; shift ;;
        --no-tests) TESTS=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
done

[[ -d "$REPO/sherlock" || -f "$REPO/pyproject.toml" ]] || die "run from the repo checkout ($REPO not found)"

# -- 1. conda env ---------------------------------------------------------------
command -v conda >/dev/null || die "conda not found: load your cluster's anaconda/miniforge module first"
command -v g++ >/dev/null || die "g++ not found: py-tlsh is built from source (pip); load a compiler module"

SPEC="$REPO/environment.lock.yml"
[[ -f "$SPEC" ]] || SPEC="$REPO/environment.yml"
if conda env list | awk '{print $1}' | grep -qx "$ENV_NAME"; then
    if [[ $UPDATE_ENV == 1 ]]; then
        say "updating env '$ENV_NAME' from $(basename "$SPEC")"
        conda env update -n "$ENV_NAME" -f "$SPEC" --prune
    else
        say "env '$ENV_NAME' exists (pass --update-env to rebuild it)"
    fi
else
    say "creating env '$ENV_NAME' from $(basename "$SPEC") (a few minutes)"
    conda env create -n "$ENV_NAME" -f "$SPEC"
fi
conda run -n "$ENV_NAME" python -I -c "import tlsh, dnfile, pefile, yara, yaml" \
    || die "env '$ENV_NAME' is missing a package; rerun with --update-env"
[[ $ENV_ONLY == 1 ]] && { say "env ready"; exit 0; }

# -- 2. roots -------------------------------------------------------------------
ROOTS="$REPO/config/roots.yaml"
yaml_key() { sed -n "s/^$1:[[:space:]]*\([^#[:space:]]*\).*/\1/p" "$ROOTS"; }

# Re-runs: with no roots given and a roots.yaml present, reuse what it says.
if [[ -z "$DATA$WORK$SCRATCH" && -f "$ROOTS" && $FORCE == 0 ]]; then
    DATA=$(yaml_key dataset_root); WORK=$(yaml_key work_root)
    SCRATCH=$(yaml_key scratch_root)
    say "using the roots in $ROOTS"
fi
# First run with no roots given: ask (in a terminal), or say exactly what to pass.
if [[ -z "$DATA" || -z "$WORK" || -z "$SCRATCH" ]]; then
    if [[ -t 0 ]]; then
        echo
        echo "No roots yet. Where do the dataset, work and scratch folders live?"
        echo "  1) beside this checkout: $HERE/ISB-Sherlock-{Data,Work,Scratch}"
        echo "     (new, empty folders: pick this if the dataset isn't on this machine yet)"
        echo "  2) somewhere else, e.g. an existing dataset from another checkout"
        read -r -p "Choose 1 or 2: " choice
        case "$choice" in
            1) DATA="$HERE/ISB-Sherlock-Data"; WORK="$HERE/ISB-Sherlock-Work"
               SCRATCH="$HERE/ISB-Sherlock-Scratch" ;;
            2) [[ -n "$DATA" ]] || read -r -e -p "  dataset root (ISB_DATA): " DATA
               [[ -n "$WORK" ]] || read -r -e -p "  work root    (ISB_WORK): " WORK
               [[ -n "$SCRATCH" ]] || read -r -e -p "  scratch root (ISB_SCRATCH): " SCRATCH ;;
            *) die "no choice made; nothing written" ;;
        esac
        DATA="${DATA/#\~/$HOME}"; WORK="${WORK/#\~/$HOME}"; SCRATCH="${SCRATCH/#\~/$HOME}"
    fi
fi
if [[ -z "$DATA" || -z "$WORK" || -z "$SCRATCH" ]]; then
    cat >&2 <<EOF
setup.sh: no roots given and no $ROOTS yet. There are no default paths; run one of:

  ./setup.sh --beside-repo        # new roots in $HERE/ISB-Sherlock-{Data,Work,Scratch}
  ./setup.sh --data /path/to/ISB-Sherlock-Data \\
             --work /path/to/ISB-Sherlock-Work \\
             --scratch /path/to/ISB-Sherlock-Scratch   # e.g. an existing dataset

(or set ISB_DATA, ISB_WORK and ISB_SCRATCH, or run it in a terminal to be asked)
EOF
    exit 1
fi
abspath() { realpath -m "$1"; }
DATA=$(abspath "$DATA"); WORK=$(abspath "$WORK"); SCRATCH=$(abspath "$SCRATCH")
for p in "$DATA" "$WORK" "$SCRATCH"; do
    case "$p/" in "$REPO"/*) die "$p is inside Sherlock/: roots live outside the code" ;; esac
done
# Roots inside the git tree must be ignored, or a `git add .` would stage samples.
if git -C "$HERE" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    for p in "$DATA" "$WORK" "$SCRATCH"; do
        case "$p/" in "$HERE"/*)
            git -C "$HERE" check-ignore -q "$p/" \
                || die "$p is inside the git tree and not in .gitignore; add it first" ;;
        esac
    done
fi

if [[ -f "$ROOTS" && $FORCE == 0 ]]; then
    if [[ "$(yaml_key dataset_root)" != "$DATA" || "$(yaml_key work_root)" != "$WORK" \
          || "$(yaml_key scratch_root)" != "$SCRATCH" ]]; then
        die "$ROOTS names other roots than the ones given; pass --force to overwrite it"
    fi
    say "keeping existing $ROOTS"
else
    say "writing $ROOTS"
    cat > "$ROOTS" <<EOF
# This cluster's roots, written by setup.sh on $(date -I) for $(whoami)@$(hostname -s).
# Gitignored: never commit. Environment variables override these keys:
#   ISB_DATA, ISB_WORK, ISB_SCRATCH (and ISB_ZIPS while archives are present)
# There are no defaults: a missing root is an error, never a guess.

dataset_root: $DATA     # ISB_DATA, read-only after verification
work_root: $WORK        # ISB_WORK, every derived artifact
scratch_root: $SCRATCH  # ISB_SCRATCH, temporary; safe to wipe

tools:                  # relative paths are relative to Sherlock/
  sdhash: third_party/sdhash/jc_sdhash/sdhash
  diec: null            # Detect It Easy CLI, needed for W8
  upx: null             # UPX, needed for W8 (static unpacking only)
EOF
fi

# -- 3. directories -------------------------------------------------------------
# A fresh clone has none of these: git does not carry the roots or empty folders.
# mkdir -p only: nothing that exists is touched, and nothing is created *inside*
# the dataset root (download.sh fills it).
say "creating directories"
mkdir -p "$DATA" "$SCRATCH"
# The work tree, as README.md's "Directory structure" lays it out.
mkdir -p "$WORK"/{manifest,splits,cache/extract,indexes,supervision,parity,runs} \
         "$WORK"/models/{scorer,cond_adapter,bytecnn} \
         "$WORK"/reports/migration \
         "$WORK"/enrich/W{1..9}
# Repo folders that start empty (gate and session notes, test packages).
mkdir -p "$REPO"/docs/{gates,sessions,migration} \
         "$REPO"/tests/{unit,lessons,integration,parity} \
         "$REPO"/scripts/slurm
echo "    dataset  $DATA"
echo "    work     $WORK"
echo "    scratch  $SCRATCH"

if [[ -d "$DATA/malware" ]]; then
    say "dataset found at $DATA"
else
    say "dataset root is empty: run ./download.sh next"
fi

# -- 4. health check ------------------------------------------------------------
if [[ $TESTS == 1 ]]; then
    say "pytest -m legacy (expect 172 passed, 8 skipped)"
    (cd "$REPO" && conda run -n "$ENV_NAME" python -m pytest -m legacy -q -p no:cacheprovider) \
        || die "legacy suite failed: see the output above"
fi

say "done. Activate with: conda activate $ENV_NAME; work from $REPO"
