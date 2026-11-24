#!/bin/bash
#SBATCH --job-name=v1repro-stage1
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=16
#SBATCH --mem=192G
#SBATCH --time=01:00:00
#SBATCH --output=experiments/ISB-v1-Legacy/runs/stage1/slurm-%j.out
#SBATCH --error=experiments/ISB-v1-Legacy/runs/stage1/slurm-%j.out

# Stage 1 of the V1 reproduction: re-score V1's stored rules with V1's harness,
# three scans (template, yarGen, generators) against F_dev held + gen + G_eval,
# then compare every per-unit integer with V1's detection.json.
# CPU only. Static scanning: yara reads bytes, nothing is executed.
#
# Submit FROM THE GIT ROOT (the --output path above is relative to it):
#   sbatch experiments/ISB-v1-Legacy/slurm/stage1.sbatch

set -euo pipefail

cd "${SLURM_SUBMIT_DIR:?}"
EXP=experiments/ISB-v1-Legacy
if [[ ! -d "$EXP/inputs" || ! -f Sherlock/legacy/V1/YaraGen/Detection/harness.py ]]; then
    echo "[stage1] submit from the git root (missing $EXP/inputs or legacy/V1)" >&2
    exit 2
fi

# The dataset root: the environment first, then Sherlock/config/roots.yaml.
if [[ -z "${ISB_DATA:-}" ]]; then
    ISB_DATA="$(sed -n 's/^dataset_root:[[:space:]]*\([^[:space:]#]*\).*/\1/p' \
        Sherlock/config/roots.yaml)"
fi
if [[ -z "$ISB_DATA" || ! -d "$ISB_DATA" ]]; then
    echo "[stage1] ISB_DATA is not set and roots.yaml has no usable dataset_root" >&2
    exit 2
fi
export ISB_DATA

# conda's activation scripts are not nounset-clean.
set +u
source "$(conda info --base)/etc/profile.d/conda.sh"
conda activate sherlock
set -u

# python -I would ignore PYTHONHASHSEED; -P -s keeps the script dir, the cwd and
# the user site off sys.path while honouring it.
export PYTHONHASHSEED=0
export OMP_NUM_THREADS=8
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-j${SLURM_JOB_ID}"

python -P -s "$EXP/drivers/stage1_rescore.py" --run-id "$RUN_ID"
python -P -s "$EXP/drivers/acceptance.py" --run-dir "$EXP/runs/stage1/$RUN_ID"
echo "[stage1] done: $RUN_ID"
