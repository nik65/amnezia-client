#!/usr/bin/env bash
# AA outer runner: every work unit is accounted separately from inner checks.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"; BUILD="$DIR/build"
mkdir -p "$BUILD"
cmake -S "$DIR" -B "$BUILD" -DCMAKE_BUILD_TYPE=Debug > "$DIR/build.log" 2>&1
BUILD_RC=$?
if [ $BUILD_RC -ne 0 ]; then cmake --build "$BUILD" -j2 >> "$DIR/build.log" 2>&1; BUILD_RC=$?; else
  cmake --build "$BUILD" -j2 >> "$DIR/build.log" 2>&1; BUILD_RC=$?; fi
GREEN_RC=1; OUTER_RC=1
if [ $BUILD_RC -eq 0 ]; then
  "$BUILD/aa_current_authority_tests" > "$DIR/green.log" 2>&1; GREEN_RC=$?
  "$BUILD/aa_current_authority_tests" --outer-fail-work > "$DIR/outer-fail-work.log" 2>&1; OUTER_RC=$?
else
  echo "build failed" > "$DIR/green.log"; echo "build failed" > "$DIR/outer-fail-work.log"
fi
python3 - "$DIR" "$BUILD_RC" "$GREEN_RC" "$OUTER_RC" <<'PY'
import json, sys, pathlib, hashlib, re
d = pathlib.Path(sys.argv[1]); brc, grc, orc = (int(x) for x in sys.argv[2:5])
g = (d/"green.log").read_text() if (d/"green.log").exists() else ""
m = re.search(r"works=(\d+) checks=(\d+) failures=(\d+) workFailures=(\d+)", g)
snap = json.load(open(d/"INPUT_SNAPSHOT.json"))
res = {
 "kind": "aa-automatic-current-authority-witness",
 "buildExit": brc,
 "greenExit": grc,
 "outerFailedWorkExit": orc,
 "outerFailedWorkContract": 23,
 "works": int(m.group(1)) if m else None,
 "checks": int(m.group(2)) if m else None,
 "failures": int(m.group(3)) if m else None,
 "workFailures": int(m.group(4)) if m else None,
 "verdict": "GREEN" if (brc == 0 and grc == 0 and orc == 23 and m and m.group(3) == "0") else "FAILED",
 "inputHashes": snap,
}
json.dump(res, open(d/"RESULT.json","w"), indent=1)
print(json.dumps(res, indent=1))
PY
