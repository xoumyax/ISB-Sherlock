#!/bin/bash
# Migration step: build ISB_DATA from the 113 archives and verify it.
#
# Ran as job 58347 on 2026-11-23 (DESTINATION VERIFIED). The archives were removed
# afterwards; to run it again, fetch them with ../download.sh, which prints this
# script's sbatch line.
#
# Runs the archive folder's own verify_destination.sh unchanged (archive sha256,
# extract, per-archive member counts against plan.json, sample sha256 == name).
# Samples are only hashed, never executed. Single-threaded and I/O bound: expect
# several hours (~216 GB read, ~345 GB written and re-read).
#
# Submit from anywhere, with the three roots in the environment (no defaults):
#
#   export ISB_ZIPS=... ISB_DATA=... ISB_WORK=...
#   mkdir -p "$ISB_WORK/reports/migration"
#   sbatch --export=ALL \
#     --output="$ISB_WORK/reports/migration/verify_destination-%j.out" \
#     scripts/slurm/verify_destination.sbatch
#
# The job refuses a non-empty ISB_DATA unless RESUME=1 is exported (re-running is
# safe: unzip -n never overwrites). Success is the last line DESTINATION VERIFIED.
#SBATCH --job-name=isb-verify-dest
#SBATCH --partition=def
#SBATCH --cpus-per-task=2
#SBATCH --mem=4G
#SBATCH --time=24:00:00
set -euo pipefail

for v in ISB_ZIPS ISB_DATA ISB_WORK; do
    [[ -n "${!v:-}" ]] || { echo "FATAL: $v is not set; export it before sbatch"; exit 2; }
done
[[ -f "$ISB_ZIPS/verify_destination.sh" ]] \
    || { echo "FATAL: $ISB_ZIPS/verify_destination.sh not found"; exit 2; }
if [[ -d "$ISB_DATA" && -n "$(ls -A "$ISB_DATA")" && "${RESUME:-0}" != 1 ]]; then
    echo "FATAL: $ISB_DATA is not empty; export RESUME=1 to continue a partial run"
    exit 2
fi

echo "host=$(hostname) job=${SLURM_JOB_ID:-none} start=$(date -Is)"
echo "ISB_ZIPS=$ISB_ZIPS"
echo "ISB_DATA=$ISB_DATA"
df -h "$(dirname "$ISB_DATA")" | tail -1

cd "$ISB_ZIPS"
status=0
bash "$ISB_ZIPS/verify_destination.sh" "$ISB_ZIPS" "$ISB_DATA" || status=$?
echo "end=$(date -Is) status=$status"
exit $status
