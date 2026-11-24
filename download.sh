#!/usr/bin/env bash
# Fetch the ISB-Sherlock-Dataset archives, check them, and (optionally) build the
# dataset from them.
#
#   ./download.sh gdrive [FOLDER_ID]          --zips DIR [--extract]
#   ./download.sh server [USER@HOST:/PATH]    --zips DIR [--extract]
#   ./download.sh verify                      --zips DIR [--extract]
#
#   gdrive   Google Drive folder holding the archive folder (needs `gdown`, which
#            this script installs into the `sherlock` env if it is missing)
#   server   any rsync/ssh source holding the archive folder
#   verify   no download: check archives already in --zips
#   --zips   a NEW or empty directory for the archives (~232 GB), outside git
#   --extract  after the checksums pass, run verify_destination.sh to unzip into
#            dataset_root (from Sherlock/config/roots.yaml; run ./setup.sh first).
#            Hours of I/O: on a cluster, prefer the sbatch line printed at the end.
#
# The archive folder is the one built on the old cluster: 113 `*.zip` with their
# `*.zip.sha256`, `plan.json`, `lists/`, `verify_destination.sh`, `verify_names.py`.
#
# SAFETY. The sample archives hold LIVE MALWARE (password `infected`). This script
# only downloads, hashes and unzips; it never runs a sample. Make sure no on-access
# scanner watches --zips or the dataset root, and that your institution's
# malware-handling approval covers this machine. Never put either under git.
set -euo pipefail

# -- placeholders: fill in before first use --------------------------------------
GDRIVE_FOLDER_ID="<PLACEHOLDER_GDRIVE_FOLDER_ID>"
SERVER_SOURCE="<PLACEHOLDER_USER@HOST:/path/to/ISB-Sherlock-Dataset-zips>"
# ---------------------------------------------------------------------------------

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO="$HERE/Sherlock"
ROOTS="$REPO/config/roots.yaml"
ENV_NAME=sherlock
N_ARCHIVES=113

die() { echo "download.sh: $*" >&2; exit 1; }
say() { echo "==> $*"; }
usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }

MODE="${1:-}"; [[ -n "$MODE" ]] || { usage; exit 1; }
shift
SRC=""; ZIPS=""; EXTRACT=0
if [[ $# -gt 0 && "$1" != --* ]]; then SRC="$1"; shift; fi
while [[ $# -gt 0 ]]; do
    case "$1" in
        --zips) ZIPS="$2"; shift 2 ;;
        --extract) EXTRACT=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
done
[[ -n "$ZIPS" ]] || die "give --zips DIR (there is no default location)"
ZIPS=$(realpath -m "$ZIPS")

# -- the archive folder must never be stageable by git ----------------------------
case "$ZIPS/" in "$REPO"/*) die "--zips is inside Sherlock/; put it outside the code" ;; esac
if git -C "$HERE" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    case "$ZIPS/" in
        "$HERE"/*)
            git -C "$HERE" check-ignore -q "$ZIPS/" \
                || die "$ZIPS is inside the git tree and not ignored; add it to .gitignore or choose another path" ;;
    esac
fi

# -- download ---------------------------------------------------------------------
fresh_dir() {
    mkdir -p "$ZIPS"
    [[ -z "$(ls -A "$ZIPS")" ]] || die "$ZIPS is not empty; use a new directory, or '$0 verify --zips $ZIPS'"
}

case "$MODE" in
    gdrive)
        ID="${SRC:-$GDRIVE_FOLDER_ID}"
        [[ "$ID" != *PLACEHOLDER* ]] || die "no Google Drive folder id: pass one or set GDRIVE_FOLDER_ID in $0"
        fresh_dir
        conda run -n "$ENV_NAME" python -I -c "import gdown" 2>/dev/null \
            || { say "installing gdown into env '$ENV_NAME'"; conda run -n "$ENV_NAME" pip install -q gdown; }
        say "downloading Drive folder $ID into $ZIPS"
        # gdown keeps the folder's own structure; --remaining-ok lets it list >50 files
        (cd "$ZIPS" && conda run --no-capture-output -n "$ENV_NAME" \
            gdown --folder "$ID" --remaining-ok -O "$ZIPS")
        # if Drive wrapped everything in one sub-folder, flatten it
        if [[ ! -f "$ZIPS/plan.json" ]]; then
            sub=$(find "$ZIPS" -mindepth 2 -maxdepth 2 -name plan.json -printf '%h\n' | head -1)
            [[ -n "$sub" ]] && { shopt -s dotglob; mv "$sub"/* "$ZIPS"/; rmdir "$sub"; }
        fi
        ;;
    server)
        S="${SRC:-$SERVER_SOURCE}"
        [[ "$S" != *PLACEHOLDER* ]] || die "no server source: pass USER@HOST:/PATH or set SERVER_SOURCE in $0"
        fresh_dir
        say "rsync from $S into $ZIPS (resumable: rerun with 'verify' if it stops)"
        rsync -a --partial --info=progress2 "${S%/}/" "$ZIPS/"
        ;;
    verify) [[ -d "$ZIPS" ]] || die "$ZIPS does not exist" ;;
    *) die "mode must be gdrive, server or verify (see --help)" ;;
esac

# -- check what arrived -----------------------------------------------------------
cd "$ZIPS"
[[ -f plan.json && -d lists ]] || die "plan.json or lists/ missing from $ZIPS: the source must be the whole archive folder"
for s in verify_destination.sh verify_names.py; do
    [[ -f "$s" ]] || { say "$s missing; using the repo copy"; cp "$REPO/scripts/migration/$s" .; }
done
n_zip=$(find . -maxdepth 1 -name "*.zip" | wc -l)
n_sum=$(find . -maxdepth 1 -name "*.zip.sha256" | wc -l)
say "$n_zip archives, $n_sum checksum files (expect $N_ARCHIVES each)"
[[ "$n_zip" == "$N_ARCHIVES" && "$n_sum" == "$N_ARCHIVES" ]] || die "incomplete download: rerun the same command, or '$0 verify --zips $ZIPS' once complete"
say "checking archive sha256 (reads ~232 GB)"
cat ./*.zip.sha256 | sha256sum -c --quiet || die "checksum mismatch: re-download the failing archives"
say "all $N_ARCHIVES archive checksums OK"

# -- extract (optional) -----------------------------------------------------------
[[ -f "$ROOTS" ]] || die "no $ROOTS: run ./setup.sh first, then rerun with 'verify --extract'"
DATA=$(sed -n 's/^dataset_root:[[:space:]]*\([^#[:space:]]*\).*/\1/p' "$ROOTS")
WORK=$(sed -n 's/^work_root:[[:space:]]*\([^#[:space:]]*\).*/\1/p' "$ROOTS")
[[ -n "$DATA" && -n "$WORK" ]] || die "dataset_root or work_root missing from $ROOTS"

if [[ $EXTRACT == 1 ]]; then
    if [[ -d "$DATA" && -n "$(ls -A "$DATA")" ]]; then
        die "$DATA is not empty; extraction only goes into a new or empty dataset root"
    fi
    mkdir -p "$WORK/reports/migration"
    LOG="$WORK/reports/migration/verify_destination-$(date +%Y%m%dT%H%M%S).log"
    say "extracting into $DATA (log: $LOG)"
    bash "$ZIPS/verify_destination.sh" "$ZIPS" "$DATA" 2>&1 | tee "$LOG"
    tail -1 "$LOG" | grep -qx "DESTINATION VERIFIED" || die "verification failed: see $LOG"
    say "dataset verified. Now make it read-only:"
else
    say "archives ready. To build the dataset on a cluster node:"
    echo "    export ISB_ZIPS=$ZIPS ISB_DATA=$DATA ISB_WORK=$WORK"
    echo "    mkdir -p \"\$ISB_WORK/reports/migration\""
    echo "    sbatch --export=ALL --output=\"\$ISB_WORK/reports/migration/verify_destination-%j.out\" \\"
    echo "        $REPO/scripts/slurm/verify_destination.sbatch"
    echo "  or here: $0 verify --zips $ZIPS --extract"
    say "after DESTINATION VERIFIED, make it read-only:"
fi
echo "    chmod -R a-w,o-rwx $DATA/malware $DATA/goodware"
