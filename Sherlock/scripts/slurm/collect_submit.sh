#!/bin/bash
# Submit the fetch-only goodware pulls (DECISIONS C20). Run from the git root, on
# the login node, with ISB_DATA, ISB_WORK and ISB_SCRATCH exported.
#
#   bash Sherlock/scripts/slurm/collect_submit.sh smoke   # 3 packages per source, 1 GiB each
#   bash Sherlock/scripts/slurm/collect_submit.sh chain   # nuget -> pmc -> apt [-> winget]
#
# Both freeze the code first: a detached worktree of HEAD under
# $ISB_SCRATCH/collect-src/<commit>, so later edits cannot reach a running chain.
# HEAD must be clean (commit first). WINGET=1 adds winget to the chain.
# Budgets (GiB) are DECISIONS C13: nuget 18, pmc 5, apt 7, winget 20. Refuses to
# submit while any isb-collect-* job is queued (two jobs of one source must not
# overlap; the CLI also takes a per-source lock).
set -euo pipefail
mode="${1:-}"
case "$mode" in smoke|chain) ;; *) echo "usage: $0 smoke|chain"; exit 2;; esac
for v in ISB_DATA ISB_WORK ISB_SCRATCH; do
    [[ -n "${!v:-}" ]] || { echo "FATAL: export $v first"; exit 2; }
done
root="$(git rev-parse --show-toplevel)"
if [[ -n "$(git -C "$root" status --porcelain -- Sherlock/sherlock Sherlock/scripts)" ]]; then
    echo "FATAL: uncommitted changes under Sherlock/sherlock or Sherlock/scripts; commit first"
    exit 2
fi
commit="$(git -C "$root" rev-parse HEAD)"
export COLLECT_SRC="$ISB_SCRATCH/collect-src/$commit"
if [[ ! -d "$COLLECT_SRC" ]]; then
    mkdir -p "$ISB_SCRATCH/collect-src"
    git -C "$root" worktree add --detach "$COLLECT_SRC" "$commit"
fi
queued="$(squeue -h -u "$USER" -o '%j')" || { echo "FATAL: squeue failed"; exit 2; }
if grep -q '^isb-collect-' <<<"$queued"; then
    echo "FATAL: isb-collect-* jobs are still queued or running (squeue); wait for them"
    exit 2
fi
sb="$COLLECT_SRC/Sherlock/scripts/slurm/collect_fetch.sbatch"

submit() {  # submit <source> <budget_gib> [dependency]
    local dep=()
    [[ -n "${3:-}" ]] && dep=(--dependency="afterany:$3")
    mkdir -p "$ISB_WORK/runs/collect/$1"
    SOURCE="$1" BUDGET_GIB="$2" sbatch --parsable --export=ALL \
        --job-name="isb-collect-$1" \
        --output="$ISB_WORK/runs/collect/$1/slurm-%j.out" "${dep[@]}" "$sb"
}

if [[ "$mode" == smoke ]]; then
    export PLAN_LIMIT=3 MAX_ITEMS=3
    for s in nuget pmc apt ${WINGET:+winget}; do
        echo "$s: job $(submit "$s" 1)"
    done
else
    unset PLAN_LIMIT MAX_ITEMS SEED PY ATTEMPTS
    j1=$(submit nuget 18);        echo "nuget:  job $j1"
    j2=$(submit pmc 5 "$j1");     echo "pmc:    job $j2 (after $j1)"
    j3=$(submit apt 7 "$j2");     echo "apt:    job $j3 (after $j2)"
    if [[ -n "${WINGET:-}" ]]; then
        j4=$(submit winget 20 "$j3"); echo "winget: job $j4 (after $j3)"
    fi
fi
echo "logs: \$ISB_WORK/runs/collect/<source>/slurm-<job>.out   code: commit $commit"
