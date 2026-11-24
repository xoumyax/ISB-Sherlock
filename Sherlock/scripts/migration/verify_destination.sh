#!/bin/bash
# Run on the NEW cluster after transferring ISB-Sherlock-Dataset-zips/ (all *.zip, *.zip.sha256,
# plan.json, lists/, verify_names.py, this script).
#
#   bash verify_destination.sh ZIPS_DIR DEST_DATASET_DIR
#
# 1. sha256 of every archive matches the old cluster's record
# 2. every archive unzips (sample archives use the password "infected")
# 3. every sample's sha256 equals its file name, and per-archive file counts match the lists
# Samples are only read (hashed), never executed. Keep the old cluster's copy until this passes.
set -euo pipefail
ZIPS=$(realpath "$1"); DEST=$(realpath -m "$2")
mkdir -p "$DEST"
cd "$ZIPS"
echo "[1/3] archive checksums"; cat ./*.zip.sha256 | sha256sum -c --quiet && echo "  all archive checksums OK"

echo "[2/3] extracting into $DEST"
python3 -I -c "
import json
for z in json.load(open('plan.json'))['archives']:
    print(z['name'], int(z['encrypt']), z['n_files'])" | while read -r NAME ENC NFILES; do
    PW=(); [[ "$ENC" == 1 ]] && PW=(-P infected)
    unzip -q -n "${PW[@]}" "$ZIPS/$NAME.zip" -d "$DEST"
    got=$(unzip -Z1 "$ZIPS/$NAME.zip" | wc -l)
    [[ "$got" == "$NFILES" ]] || { echo "COUNT MISMATCH $NAME: $got vs $NFILES"; exit 1; }
    echo "  $NAME: $got files"
done

echo "[3/3] sample content == name"
fail=0
for L in "$ZIPS"/lists/*.lst; do
    python3 -I "$ZIPS/verify_names.py" "$DEST" "$L" || fail=1
done
[[ $fail == 0 ]] && echo "DESTINATION VERIFIED" || { echo "VERIFICATION FAILED"; exit 1; }
