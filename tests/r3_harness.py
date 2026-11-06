"""R3 test harness: turn the synthetic cases into capture-format input files, run a tool on them, and
return what it attributed per address. Black-box on purpose, so the same cases run against the legacy
tool and the new one.

Adapters return {address: [{"radio": ..., "oui_vendor": ..., "oui_vendor_confidence": ...}, ...]}
(one entry per output row for that address). A tool that merges radios returns one entry.
"""
import csv, glob, json, os, sqlite3, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, "fixtures")
CASES_PATH = os.path.join(FIXTURES, "r3_cases.json")
OUI_FIXTURE = os.path.join(FIXTURES, "oui_fixture.txt")
LEGACY_TOOL = os.path.join(ROOT, "legacy", "swivel_crosscheck.py")

WIGLE_PREHEADER = "WigleWifi-1.4,appRelease=Kismet,model=fixture,release=,device=,display=,board=,brand="
WIGLE_HEADER = ["MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "RSSI", "CurrentLatitude",
                "CurrentLongitude", "AltitudeMeters", "AccuracyMeters", "Type"]
RADIO_OF_KIND = {"WIFI": "wifi", "BLE": "ble", "CLASSIC": "bt-classic", "BT": "bt-classic"}
FIXTURE_LAT, FIXTURE_LON = 12.345678, -98.765432        # synthetic, distinctive: the R1 test looks for them in output


def load_cases():
    with open(CASES_PATH, encoding="utf-8") as f:
        return json.load(f)["cases"]


def build_inputs(cases, in_dir):
    """Write the phone rows as SWIVEL ndjson and the Kismet rows as a .wiglecsv. Returns the two paths."""
    os.makedirs(in_dir, exist_ok=True)
    phone = os.path.join(in_dir, "r3_fixture_phone.ndjson")
    kismet = os.path.join(in_dir, "Kismet-r3-fixture.wiglecsv")
    with open(phone, "w", encoding="utf-8") as fp, open(kismet, "w", newline="", encoding="utf-8") as fk:
        fk.write(WIGLE_PREHEADER + "\n")
        w = csv.writer(fk)
        w.writerow(WIGLE_HEADER)
        for c in cases:
            for r in c["rows"]:
                if r["source"] == "phone":
                    row = {"iso_time": "2026-10-30T01:00:00-0400", "session_id": "r3fixture", "source": "PHONE",
                           "kind": r["kind"], "mac": r["mac"], "address_type": r.get("address_type", ""),
                           "vendor": r.get("vendor", ""), "classification": "FIXTURE", "ssid_or_name": r.get("ssid_or_name", ""),
                           "rssi": -60, "lat": FIXTURE_LAT, "lon": FIXTURE_LON, "gps_accuracy_m": 7.25}
                    if r.get("manufacturer"):
                        row["manufacturer"] = r["manufacturer"]
                    for k in r.get("_omit", []):
                        row.pop(k, None)
                    fp.write(json.dumps(row) + "\n")
                else:
                    w.writerow([r["mac"], r.get("ssid", ""), "", "2026-10-30 05:00:00", 0, -60, FIXTURE_LAT, FIXTURE_LON,
                                "", "7.25", r["type"]])
    return phone, kismet


def run_legacy(cases, work_dir):
    """Run the copied legacy `enhance` on the fixture. Known legacy bug worked around here so it doesn't hide
    the R3 result: it crashes on .wiglecsv, so the Kismet file is copied to a .csv name first."""
    phone, kismet = build_inputs(cases, os.path.join(work_dir, "in"))
    kismet_csv = kismet[: -len(".wiglecsv")] + ".csv"
    with open(kismet, encoding="utf-8") as src, open(kismet_csv, "w", encoding="utf-8") as dst:
        dst.write(src.read())
    out_dir = os.path.join(work_dir, "out")          # separate from inputs: legacy re-reads its own output
    os.makedirs(out_dir, exist_ok=True)
    cmd = [sys.executable, "-I", LEGACY_TOOL, "enhance", phone, kismet_csv,
           "--oui", OUI_FIXTURE, "--out", out_dir, "--keep-noise"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"legacy enhance failed ({proc.returncode}): {proc.stderr or proc.stdout}")
    outs = glob.glob(os.path.join(out_dir, "enhanced_*.csv"))
    if len(outs) != 1:
        raise RuntimeError(f"expected one legacy output CSV, found {outs}")
    result = {}
    with open(outs[0], encoding="utf-8") as f:
        for row in csv.DictReader(f):
            result.setdefault(row["mac"].upper(), []).append(
                {"radio": RADIO_OF_KIND.get(row["kind"], row["kind"]), "oui_vendor": row["vendor"] or None,
                 "oui_vendor_confidence": None})
    return result


NEW_TOOL = os.path.join(ROOT, "swivel_enhance.py")
REGISTRY_FIXTURE = os.path.join(FIXTURES, "registry")
result_returncode = [None]                              # the new tool's exit code from the last run_new


def run_new(cases, work_dir):
    """Run swivel_enhance.py on the fixture (.wiglecsv as-is) and read devices back from its DB.
    Exit 2 means the tool's own R3 check failed; the rows are still read so the test reports which case."""
    phone, kismet = build_inputs(cases, os.path.join(work_dir, "in"))
    db = os.path.join(work_dir, "out", "r3.db")
    proc = subprocess.run([sys.executable, "-I", NEW_TOOL, "run", phone, kismet, "--registry", REGISTRY_FIXTURE,
                           "--db", db, "--naive-tz", "UTC"], capture_output=True, text=True)
    if proc.returncode not in (0, 2):
        raise RuntimeError(f"swivel_enhance run failed ({proc.returncode}): {proc.stderr or proc.stdout}")
    result_returncode[0] = proc.returncode
    conn = sqlite3.connect(db)
    result = {}
    for addr, radio, vendor, conf in conn.execute(
            "SELECT address, radio, oui_vendor, oui_vendor_confidence FROM devices"):
        result.setdefault(addr.upper(), []).append(
            {"radio": radio, "oui_vendor": vendor, "oui_vendor_confidence": conf})
    conn.close()
    return result


ADAPTERS = {"legacy": run_legacy, "new": run_new}
CONFIDENCE_SUPPORTED = {"legacy": False, "new": True}
DEFAULT_TARGET = "new"
