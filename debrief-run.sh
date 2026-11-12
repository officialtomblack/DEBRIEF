#!/usr/bin/env bash
# debrief-run.sh — your everyday DEBRIEF routine, in one command.
#
# The idea: after an outing, you want ALL your new captures folded into one
# database without thinking about it. This does that. It never misses a file and
# never double-counts one, because DEBRIEF skips any capture already in the
# database (matched by content) — so running it again is always safe.
#
#   ./debrief-run.sh          fold every new capture, then open the report
#   ./debrief-run.sh -n       dry-run: show exactly what it would do, change nothing
#   ./debrief-run.sh --clean  after folding, delete each .kismet that is CONFIRMED
#                             in the database (frees disk — read the warning below first)
#
# ─────────────────────────────────────────────────────────────────────────────
#  EDIT THESE TWO LINES for your machine, then you never touch them again:
DEBRIEF_DIR="$HOME/DEBRIEF"        # where you cloned DEBRIEF (the folder with swivel_enhance.py)
CAPTURES_DIR="$HOME/captures"      # the folder you drop your SWIVEL exports + any .kismet files into
# ─────────────────────────────────────────────────────────────────────────────

set -u
DRY=0; CLEAN=0
for a in "$@"; do case "$a" in
    -n|--dry-run) DRY=1 ;;
    --clean)      CLEAN=1 ;;
    *) echo "unknown option: $a  (use -n for a dry-run, --clean to delete folded Kismet)"; exit 2 ;;
esac; done

cd "$DEBRIEF_DIR" || { echo "Can't find DEBRIEF at $DEBRIEF_DIR — fix DEBRIEF_DIR at the top of this script."; exit 1; }
mkdir -p "$CAPTURES_DIR"

# 1. (Optional, automatic) If your phone is plugged in with USB debugging on AND you
#    installed the debug build, pull any session logs you don't already have. If adb
#    or the phone isn't there, this is skipped silently — the folder below still folds.
PKG="com.millie.civops2"
if command -v adb >/dev/null 2>&1 && adb get-state >/dev/null 2>&1; then
    for f in $(adb exec-out run-as "$PKG" ls -1 files/logs 2>/dev/null | tr -d '\r'); do
        case "$f" in *.ndjson) ;; *) continue ;; esac
        [ -f "$CAPTURES_DIR/$f" ] && continue        # already copied
        if [ "$DRY" = 1 ]; then echo "[dry-run] would pull $f from the phone"
        else adb exec-out run-as "$PKG" cat "files/logs/$f" > "$CAPTURES_DIR/$f" && echo "pulled $f from the phone"; fi
    done
fi

# 2. Gather every capture DEBRIEF understands from your folder.
FILES=()
for p in "$CAPTURES_DIR"/*.ndjson "$CAPTURES_DIR"/*.json "$CAPTURES_DIR"/*.csv "$CAPTURES_DIR"/*.kismet; do
    [ -f "$p" ] && FILES+=("$p")
done
if [ "${#FILES[@]}" -eq 0 ]; then
    echo "No capture files in $CAPTURES_DIR (looked for .ndjson / .json / .csv / .kismet)."
    echo "Export a session from SWIVEL and copy it there, then run this again."
    exit 1
fi

if [ "$DRY" = 1 ]; then
    echo "[dry-run] would fold ${#FILES[@]} file(s) into out/swivel.db, then open the report:"
    printf '    %s\n' "${FILES[@]}"
    [ "$CLEAN" = 1 ] && echo "[dry-run] --clean: would then delete each .kismet confirmed in the database."
    exit 0
fi

# 3. Fold everything (already-folded files are skipped automatically) and build the report.
echo "Folding ${#FILES[@]} file(s)..."
python3 swivel_enhance.py run "${FILES[@]}" --kismet-window 60 || { echo "DEBRIEF failed — nothing was deleted."; exit 1; }
python3 swivel_enhance.py report out/swivel.db
echo "Report ready: $DEBRIEF_DIR/out/swivel_report.html  — open it in your browser."

# 4. (Optional) --clean: delete each .kismet whose content is CONFIRMED in the database.
#    WARNING: after a .kismet is folded AND deleted, your database (out/swivel.db) and
#    whatever backups you keep of it are the ONLY copy of that capture. Only use --clean
#    if you back up out/swivel.db. A file is deleted ONLY once its content is confirmed
#    in the database, so a failed fold never deletes anything.
if [ "$CLEAN" = 1 ]; then
    for k in "$CAPTURES_DIR"/*.kismet; do
        [ -f "$k" ] || continue
        if python3 -I - "$k" <<'PY'
import sys, sqlite3, hashlib
h = hashlib.sha256()
with open(sys.argv[1], "rb") as f:
    for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
try:
    have = {x for (x,) in sqlite3.connect("out/swivel.db").execute("SELECT sha256 FROM ingested_files")}
except Exception:
    sys.exit(2)
sys.exit(0 if h.hexdigest() in have else 1)
PY
        then rm -f "$k" && echo "cleaned (folded + confirmed): $(basename "$k")"
        else echo "kept (not yet confirmed in the database): $(basename "$k")"; fi
    done
fi
