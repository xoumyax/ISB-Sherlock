#!/bin/bash
# Fetch-only goodware pull for ONE source (COLLECT.md; DECISIONS C12-C20).
#
# Plans the source's catalogue, then downloads the planned payloads into
# $ISB_WORK/intake/<source>/store/, each checked against its catalogue SHA-256 or
# SHA-512. Nothing is unpacked or executed. Resumable: re-submitting replays what is
# already stored without spending budget.
#
# Runs from a FROZEN checkout ($COLLECT_SRC, a detached git worktree of one commit),
# so edits to the live checkout cannot change a running chain. Submit through
# scripts/slurm/collect_submit.sh, which sets everything below; by hand:
#
#   export ISB_DATA=... ISB_WORK=... ISB_SCRATCH=... COLLECT_SRC=<worktree>
#   export SOURCE=nuget BUDGET_GIB=18          # optional: PLAN_LIMIT=3 MAX_ITEMS=3
#   sbatch --export=ALL --output="$ISB_WORK/runs/collect/$SOURCE/slurm-%j.out" \
#     scripts/slurm/collect_fetch.sbatch
#
# Exit 0 also when the pull stops at its budget (stats.stopped says why). A failed
# attempt (e.g. a host outage that outlasts the breaker) is retried up to
# ATTEMPTS times (default 3), 30 min apart; resume is safe (plan reused, receipts
# replay, nothing is charged twice). A held source lock (another job of the same
# source running) is not retried.
#SBATCH --job-name=isb-collect
#SBATCH --partition=def
#SBATCH --cpus-per-task=2
#SBATCH --mem=8G
#SBATCH --time=36:00:00
set -euo pipefail

for v in ISB_DATA ISB_WORK ISB_SCRATCH COLLECT_SRC SOURCE BUDGET_GIB; do
    [[ -n "${!v:-}" ]] || { echo "FATAL: $v is not set; export it before sbatch"; exit 2; }
done
case "$SOURCE" in nuget|apt|pmc|winget) ;; *) echo "FATAL: SOURCE=$SOURCE"; exit 2;; esac
[[ -d "$COLLECT_SRC/Sherlock/sherlock/collect" ]] \
    || { echo "FATAL: $COLLECT_SRC has no Sherlock/sherlock/collect"; exit 2; }
PY="${PY:-$HOME/.conda/envs/sherlock/bin/python}"

extra=()
[[ -n "${PLAN_LIMIT:-}" ]] && extra+=(--plan-limit "$PLAN_LIMIT")
[[ -n "${MAX_ITEMS:-}" ]] && extra+=(--max-items "$MAX_ITEMS")
[[ -n "${SEED:-}" ]] && extra+=(--seed "$SEED")

echo "host=$(hostname) job=${SLURM_JOB_ID:-none} source=$SOURCE budget_gib=$BUDGET_GIB start=$(date -Is)"
echo "src_commit=$(git -C "$COLLECT_SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
df -h --output=avail "$ISB_WORK" | tail -1 | sed 's/^/work_avail=/'

cd "$COLLECT_SRC/Sherlock"
attempts="${ATTEMPTS:-3}"
status=0
for ((i = 1; i <= attempts; i++)); do
    status=0
    echo "attempt $i/$attempts start=$(date -Is)"
    "$PY" -m sherlock.cli.collect run --source "$SOURCE" --budget-gib "$BUDGET_GIB" \
        "${extra[@]}" || status=$?
    echo "attempt $i/$attempts end=$(date -Is) status=$status"
    [[ $status -eq 0 || $status -eq 3 ]] && break   # 3 = source lock held
    (( i < attempts )) && sleep 1800
done
echo "end=$(date -Is) status=$status"
exit $status
