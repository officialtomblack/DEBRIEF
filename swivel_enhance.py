#!/usr/bin/env python3
"""SWIVEL log-enhancer: raw captures in, one enriched SQLite database out. Offline except `fetch`.

  fetch               download the reference registries into data/ and rewrite SOURCES.md (URL, date, SHA-256)
  run FILE... [opts]  build or EXTEND the DB from captures (cumulative by default; --fresh rebuilds): sightings (immutable) + devices (derived), a CSV
                      and a run summary. Exits 2 if the R3 check fails.
  wigle DB [opts]     look up the Wi-Fi AP BSSIDs in a built DB on WiGLE (ONLINE; off until enabled in sources.json).
                      Fixed APs only — never client/BLE/randomized MACs, never GPS (R2). Caches to data/; `run` folds it in.

Inputs: SWIVEL session .ndjson, SWIVEL export .json, WigleCSV (.wiglecsv, or a .csv whose first line starts "WigleWifi"),
Kismet native .kismet log (SQLite; read immutably, never modified).
Captures are only read. By default each run APPENDS the given captures (deduped by content hash) and rebuilds devices from
all of them; --fresh rebuilds from only the files given. Dead rows (randomized, no enrich/cluster handle) are dropped from
the output unless --keep-noise; raw sightings keep every row.
The summary prints counts only, never addresses, names, SSIDs or coordinates (spec R1).
Spec: ../../Working/2026-10-30_log-enhancer_BUILD-SPEC_v1.md
"""
import argparse, collections, csv, datetime as dt, gzip, hashlib, html, json, math, os, re, shutil, sqlite3, statistics, sys, zlib
import urllib.error, urllib.parse, urllib.request
from zoneinfo import ZoneInfo

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")

# ---- reference registries ----

SIG = "https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers"
SOURCES = [  # (path under data/, URL, what it is)
    ("ieee/oui.csv", "https://standards-oui.ieee.org/oui/oui.csv", "IEEE MA-L registry (24-bit OUI)"),
    ("ieee/mam.csv", "https://standards-oui.ieee.org/oui28/mam.csv", "IEEE MA-M registry (28-bit)"),
    ("ieee/oui36.csv", "https://standards-oui.ieee.org/oui36/oui36.csv", "IEEE MA-S registry (36-bit)"),
    ("wireshark/manuf", "https://www.wireshark.org/download/automated/data/manuf", "Wireshark manuf (vendor fallback)"),
    ("bluetooth-sig/company_identifiers.yaml", f"{SIG}/company_identifiers/company_identifiers.yaml",
     "Bluetooth SIG company identifiers"),
    ("bluetooth-sig/service_uuids.yaml", f"{SIG}/uuids/service_uuids.yaml", "Bluetooth SIG 16-bit service UUIDs"),
    ("bluetooth-sig/member_uuids.yaml", f"{SIG}/uuids/member_uuids.yaml",
     "Bluetooth SIG member service UUIDs (the 0xFxxx UUIDs seen in the captures)"),
    ("bluetooth-sig/appearance_values.yaml", f"{SIG}/core/appearance_values.yaml", "Bluetooth SIG appearance values"),
    ("bluetooth-sig/class_of_device.yaml", f"{SIG}/core/class_of_device.yaml", "Bluetooth SIG Class of Device"),
    ("ringmast4r/master_oui.csv", "https://raw.githubusercontent.com/Ringmast4r/OUI-Master-Database/master/LISTS/master_oui.csv",
     "ringmast4r OUI-Master-Database device_type (oui_device_type)"),
]
YAML_KEY = {"company_identifiers.yaml": "company_identifiers", "service_uuids.yaml": "uuids", "member_uuids.yaml": "uuids",
            "appearance_values.yaml": "appearance_values", "class_of_device.yaml": "cod_services"}
# IEEE's firewall answers 200 with an HTML "Request Rejected" page when the User-Agent contains "(...; ...)";
# a plain name/version UA gets the file (found 2026-10-30). So every download is checked before it replaces anything.
UA = "swivel-log-enhancer/1.0"

# ALPR cameras: one whole-planet OSM download (surveillance:type=ALPR, ~150k nodes worldwide = DeFlock's own source).
# A worldwide set reveals nothing about where the captures are; near_alpr then matches offline. Overpass is flakier
# than the registries, so fetch_alpr is best-effort and separate from the all-or-nothing registry download.
# The main Overpass instance throttles whole-planet queries (DeFlock's tooling notes the same), so try mirrors in turn.
OVERPASS = ("https://overpass-api.de/api/interpreter", "https://overpass.kumi.systems/api/interpreter",
            "https://lz4.overpass-api.de/api/interpreter")
# Nodes only: ALPR cameras are mapped as points (a planet-wide `nwr ... out center` resolves way/relation geometry
# worldwide and the public servers drop it). A handful mapped as ways/areas are missed — fine for a coarse proximity flag.
ALPR_PATH = "osm/alpr.json"

SOURCES_PATH = os.path.join(HERE, "sources.json")   # the enrichment-sources manifest (toggles; stage 6)
WIGLE_PATH = "wigle/ap_cache.json"                   # BSSID -> location cache written by `wigle`, read offline by `run`


def check_download(rel, body):
    """Raise ValueError unless body looks like the registry it claims to be (a 200 can still be an error page)."""
    import yaml
    name = os.path.basename(rel)
    if body.lstrip()[:1] == b"<":
        raise ValueError("got an HTML page")
    if rel == "ringmast4r/master_oui.csv":
        if not body.startswith(b"oui,manufacturer,") or body.count(b"\n") < 1000:
            raise ValueError("not the ringmast4r master_oui.csv")
    elif name.endswith(".csv"):
        if not body.startswith(b"Registry,") or body.count(b"\n") < 100:
            raise ValueError("not an IEEE registry CSV")
    elif name == "manuf":
        if len(re.findall(rb"(?m)^[0-9A-F]{2}(?::[0-9A-F]{2}){2}", body)) < 10000:
            raise ValueError("not a Wireshark manuf file")
    else:
        doc = yaml.safe_load(body)
        if not isinstance(doc, dict) or not doc.get(YAML_KEY[name]):
            raise ValueError(f"YAML without a non-empty '{YAML_KEY[name]}' list")


def load_sources(path=SOURCES_PATH):
    """The sources manifest as a list of dicts, or None if it's missing/blank (callers then treat everything enabled)."""
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return None
    s = d.get("sources") if isinstance(d, dict) else None
    return s if isinstance(s, list) and s else None


def enabled_sources(sources):
    """Set of enabled source ids, or None (no manifest) = 'everything enabled' — the offline-safe default: a missing
    manifest must never silently switch vendor/tracker enrichment off. Online lookups are gated per-row, not by this."""
    if sources is None:
        return None
    return {s["id"] for s in sources if isinstance(s, dict) and s.get("enabled") and s.get("id")}


def source_id_for(rel):
    """Map a SOURCES download path (e.g. 'ieee/oui.csv') to its manifest source id."""
    top = rel.split("/", 1)[0]
    return {"ieee": "ieee_oui", "wireshark": "wireshark_manuf", "bluetooth-sig": "bluetooth_sig"}.get(top, top)


def cmd_fetch(args):
    bbox = parse_bbox(getattr(args, "alpr_bbox", None))   # validate up front so a typo'd box fails before any download
    enabled = enabled_sources(load_sources())          # None = no/blank manifest: download everything, as before
    on = lambda sid: enabled is None or sid in enabled
    got, skipped = [], []
    for rel, url, what in SOURCES:                     # download and check everything before replacing anything
        if not on(source_id_for(rel)):
            skipped.append(source_id_for(rel))
            continue
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=180) as r:
            body = r.read()
        try:
            check_download(rel, body)
        except ValueError as e:
            sys.exit(f"{url}: {e}. Nothing replaced. Download it by hand to data/{rel}; don't use a mirror.")
        got.append((rel, what, url, body))
        print(f"ok  data/{rel}  {len(body):,} bytes")
    for rel, _, _, body in got:
        path = os.path.join(DATA, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path + ".part", "wb") as f:
            f.write(body)
        os.replace(path + ".part", path)
    day = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    with open(os.path.join(HERE, "SOURCES.md"), "w", encoding="utf-8") as f:
        f.write("# Reference datasets (offline)\n\nWritten by `python3 swivel_enhance.py fetch`, which downloads these into "
                "`data/` (git-ignored). Re-run it to refresh; this file is rewritten each time.\nGeneric public registries "
                "downloaded in bulk: nothing about the captures is sent anywhere.\n\n"
                "| file | what | URL | downloaded (UTC) | bytes | SHA-256 |\n|---|---|---|---|---|---|\n")
        for rel, what, url, body in got:
            f.write(f"| `data/{rel}` | {what} | {url} | {day} | {len(body):,} | `{hashlib.sha256(body).hexdigest()}` |\n")
    print("wrote SOURCES.md")
    if on("osm_alpr"):
        fetch_alpr(bbox)                               # best-effort; near_alpr degrades to 'no_alpr_dataset' without it
    else:
        print("skip data/osm/alpr.json (osm_alpr disabled in sources.json)")
    if skipped:
        print(f"skipped (disabled in sources.json): {', '.join(sorted(set(skipped)))}")
    return 0


def _coord(v):
    """A usable coordinate: a real number, not a bool, finite (json.loads parses NaN/Infinity; bool is an int subclass)."""
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def parse_alpr(body):
    """Overpass JSON -> [(lat, lon)], one per element (a node's own lat/lon, or a way/relation 'center').
    Rejects non-finite / bool coords like num(); any malformed entry is skipped, never crashes a run."""
    out = []
    doc = json.loads(body)
    for e in (doc.get("elements", []) if isinstance(doc, dict) else []):
        if not isinstance(e, dict):
            continue
        c = e if _coord(e.get("lat")) else (e.get("center") or {})
        if not isinstance(c, dict):
            continue
        lat, lon = c.get("lat"), c.get("lon")
        if _coord(lat) and _coord(lon):
            out.append((lat, lon))
    return out


def alpr_query(bbox=None):
    """OverpassQL for ALPR camera nodes. Worldwide by default (reveals nothing about where you are, but the public
    servers often reject a planet-wide query). bbox=(S,W,N,E) fetches only that region — small and reliable, at the cost
    of telling Overpass roughly where you capture (a coarse box, not your route). The region is the caller's explicit
    choice; the tool never derives it from your GPS."""
    sel = 'node["surveillance:type"="ALPR"]'
    if bbox:
        s, w, n, e = bbox
        return f'[out:json][timeout:180];{sel}({s},{w},{n},{e});out;'
    return f'[out:json][timeout:900];{sel};out;'


def parse_bbox(s):
    """'S,W,N,E' -> (south, west, north, east) floats, or None (no bbox = worldwide). Exits on a malformed box so a typo
    can't silently fall back to a worldwide query the user didn't ask for."""
    if not s:
        return None
    try:
        p = [float(x) for x in s.split(",")]
    except ValueError:
        p = []
    if len(p) != 4 or not (-90 <= p[0] < p[2] <= 90) or not (-180 <= p[1] < p[3] <= 180):
        sys.exit(f"--alpr-bbox must be 'S,W,N,E' with S<N, W<E and in range; got {s!r}")
    return tuple(p)


def fetch_alpr(bbox=None):
    """Download surveillance:type=ALPR camera points (OSM via Overpass) into data/osm/alpr.json and append a SOURCES.md
    row. Worldwide by default; bbox=(S,W,N,E) fetches only that region (reliable where a planet-wide query is rejected).
    Best-effort: on any failure, print how to do it by hand and leave near_alpr saying 'no_alpr_dataset'."""
    q = alpr_query(bbox)
    data = urllib.parse.urlencode({"data": q}).encode()
    body, errs = None, []
    for url in OVERPASS:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=data, headers={"User-Agent": UA}),
                                        timeout=200 if bbox else 950) as r:
                body = r.read()
            n = len(parse_alpr(body))
            if bbox is None and n < 1000:              # a worldwide pull is tens of thousands; fewer means a partial/error reply
                raise ValueError(f"only {n} cameras parsed")
            break
        except Exception as e:                         # network, URLError, JSON, ValueError: try the next mirror
            errs.append(f"{url}: {e}")
            body = None
    if body is None:
        print("WARN  ALPR cameras not downloaded. near_alpr will report 'no_alpr_dataset'.")
        for e in errs:
            print(f"      - {e}")
        print(f"      By hand: POST data={q!r} to one of {OVERPASS}, save the JSON to data/{ALPR_PATH}")
        return
    path = os.path.join(DATA, ALPR_PATH)
    try:                                                 # best-effort to the end: a disk error here is not fatal to fetch
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path + ".part", "wb") as f:
            f.write(body)
        os.replace(path + ".part", path)                 # atomic: never leaves a half-written alpr.json
        with open(os.path.join(HERE, "SOURCES.md"), "a", encoding="utf-8") as f:
            scope = "bbox " + ",".join(map(str, bbox)) if bbox else "worldwide"
            f.write(f"| `data/{ALPR_PATH}` | OSM ALPR cameras ({scope}, surveillance:type=ALPR) | {url} | "
                    f"{dt.datetime.now(dt.timezone.utc):%Y-%m-%d} | {len(body):,} | `{hashlib.sha256(body).hexdigest()}` |\n")
    except OSError as e:
        print(f"WARN  downloaded {n:,} ALPR cameras but could not save them ({e}); near_alpr will report 'no_alpr_dataset'")
        return
    print(f"ok  data/{ALPR_PATH}  {len(body):,} bytes  ({n:,} cameras)")


class Registry:
    def __init__(self, d):
        import yaml
        # Each group is loaded only if its file is present, so a source disabled in sources.json (never fetched, or its
        # data/ files deleted) degrades enrichment instead of crashing the run. vendor()/classify() handle empty tables.
        self.ieee = {}                                  # hex prefix (6, 7 or 9 digits) -> (organization, list)
        for rel, name in (("ieee/oui.csv", "ieee_ma-l"), ("ieee/mam.csv", "ieee_ma-m"), ("ieee/oui36.csv", "ieee_ma-s")):
            p = os.path.join(d, rel)
            if not os.path.exists(p):
                continue
            with open(p, encoding="utf-8-sig", newline="") as f:
                for r in csv.DictReader(f):
                    self.ieee[r["Assignment"].strip().upper()] = (r["Organization Name"].strip(), name)
        self.manuf = {}                                 # (prefix bits, hex prefix) -> organization
        mp = os.path.join(d, "wireshark/manuf")
        if os.path.exists(mp):
            with open(mp, encoding="utf-8-sig") as f:
                for line in f:
                    parts = [p.strip() for p in line.rstrip("\n").split("\t")]
                    if line.startswith("#") or len(parts) < 2:
                        continue
                    pfx, _, bits = parts[0].partition("/")
                    h, bits = hexdigits(pfx), int(bits or 24)
                    if bits % 4 == 0 and len(h) >= bits // 4:
                        self.manuf[(bits, h[:bits // 4])] = parts[2] if len(parts) > 2 and parts[2] else parts[1]
        self.manuf_bits = sorted({b for b, _ in self.manuf}, reverse=True)
        self.device_type = {}                            # OUI hex prefix -> coarse device type (ringmast4r OUI-Master-Database)
        rp = os.path.join(d, "ringmast4r/master_oui.csv")
        if os.path.exists(rp):
            with open(rp, encoding="utf-8-sig", newline="") as f:
                for r in csv.DictReader(f):
                    t = (r.get("device_type") or "").strip()
                    if t:
                        self.device_type[hexdigits(r.get("oui"))] = t
        self.company = {}
        cp = os.path.join(d, "bluetooth-sig/company_identifiers.yaml")
        if os.path.exists(cp):
            with open(cp, encoding="utf-8-sig") as f:
                self.company = {e["value"]: e["name"] for e in yaml.safe_load(f)["company_identifiers"]}
        self.service_names = {}                          # SIG 16-bit service + member-service UUID -> name (advertised_services)
        for fn in ("service_uuids.yaml", "member_uuids.yaml"):
            fp = os.path.join(d, "bluetooth-sig", fn)
            if os.path.exists(fp):
                with open(fp, encoding="utf-8-sig") as f:
                    for e in (yaml.safe_load(f) or {}).get("uuids", []):
                        self.service_names[e["uuid"]] = e["name"]
        self.appearance = {}                             # GAP Appearance category number -> name (coarse BLE device_class)
        apf = os.path.join(d, "bluetooth-sig/appearance_values.yaml")
        if os.path.exists(apf):
            with open(apf, encoding="utf-8-sig") as f:
                self.appearance = {e["category"]: e["name"] for e in (yaml.safe_load(f) or {}).get("appearance_values", [])}
        self.cod = {}                                    # Class-of-Device major number -> short name (coarse BT-Classic device_class)
        cdf = os.path.join(d, "bluetooth-sig/class_of_device.yaml")
        if os.path.exists(cdf):
            with open(cdf, encoding="utf-8-sig") as f:   # keep the head ("Audio/Video"), drop the "(headset, speaker, ...)" tail
                self.cod = {e["major"]: e["name"].split("(")[0].strip() for e in (yaml.safe_load(f) or {}).get("cod_device_class", [])}
        self.signatures = load_signatures()              # code-adjacent, not a downloaded dataset, so loaded from HERE
        self.wigle = {}                                  # BSSID -> {lat, lon[, ssid]}: offline WiGLE AP cache (stage 6)
        wp = os.path.join(d, WIGLE_PATH)
        if os.path.exists(wp):
            try:                                         # a corrupt cache must not abort the run; just skip wigle_location
                with open(wp, encoding="utf-8") as f:
                    raw = json.load(f)
                self.wigle = {k: v for k, v in (raw.items() if isinstance(raw, dict) else ())
                              if isinstance(v, dict) and v.get("found") and _coord(v.get("lat")) and _coord(v.get("lon"))}
            except (ValueError, OSError) as e:
                print(f"WARN  ignoring unreadable {WIGLE_PATH} ({e}); wigle_location skipped", file=sys.stderr)
        self.beacondb = {}                               # BSSID -> {lat, lon}: offline beaconDB AP cache (keyless WiGLE alternative)
        bdp = os.path.join(d, BEACONDB_PATH)
        if os.path.exists(bdp):
            try:
                with open(bdp, encoding="utf-8") as f:
                    raw = json.load(f)
                self.beacondb = {k: v for k, v in (raw.items() if isinstance(raw, dict) else ())
                                 if isinstance(v, dict) and v.get("found") and _coord(v.get("lat")) and _coord(v.get("lon"))}
            except (ValueError, OSError) as e:
                print(f"WARN  ignoring unreadable {BEACONDB_PATH} ({e}); beacondb_location skipped", file=sys.stderr)
        self.alpr = []                                   # [(lat, lon)] worldwide ALPR cameras; empty until fetch_alpr ran
        ap = os.path.join(d, ALPR_PATH)
        if os.path.exists(ap):
            try:                                         # a corrupt/partial alpr.json must not abort the whole run
                with open(ap, "rb") as f:
                    self.alpr = parse_alpr(f.read())
            except (ValueError, OSError) as e:
                print(f"WARN  ignoring unreadable {ALPR_PATH} ({e}); near_alpr will report 'no_alpr_dataset'", file=sys.stderr)

    def vendor(self, h):
        """Most specific match for a 12-hex-digit address: IEEE MA-S, MA-M, MA-L, then Wireshark manuf.
        An MA-L hit on an "IEEE Registration Authority" parent block is not a vendor, so it falls through.
        A "Private" registration is a real assignment whose holder is withheld: no vendor, and the source says so."""
        for n in (9, 7, 6):
            hit = self.ieee.get(h[:n])
            if hit and not hit[0].startswith("IEEE Registration Authority"):
                return (None, hit[1] + ":private") if hit[0] == "Private" else hit
        for bits in self.manuf_bits:
            name = self.manuf.get((bits, h[:bits // 4]))
            if name and not name.startswith("IEEE Registration Authority"):
                return (None, "wireshark_manuf:private") if name == "Private" else (name, "wireshark_manuf")
        return None, None

    def device_type_for(self, h):
        """Coarse OUI-level device category (ringmast4r), most specific prefix first. A hint only (~half the OUIs
        classified); the caller gates it behind the same hard rule as vendor, so a randomized address never gets one."""
        for n in (9, 7, 6):
            t = self.device_type.get(h[:n])
            if t:
                return t
        return None

# ---- reading captures into sightings ----

RADIO = {"WIFI": "wifi", "BLE": "ble", "CLASSIC": "bt-classic", "BTC": "bt-classic", "BT": "bt-classic"}
ADDR_RE = re.compile(r"[0-9A-F]{2}([:-]?[0-9A-F]{2}){5}")
SIGHTING_COLS = ["source_file", "source_line", "source_format", "origin", "session_id", "address", "radio",
                 "address_type", "ts_raw", "ts_utc", "ts_tz", "rssi", "lat", "lon", "gps_accuracy", "name",
                 "security_raw", "ie_raw", "raw", "noise_reason"]


def hexdigits(s):
    s = s if isinstance(s, str) else ""                  # trust boundary: non-string input never crashes
    return "".join(c for c in s if c in "0123456789abcdefABCDEF").upper()


def txt(v):
    """A text column from untrusted input: strings as-is, other JSON values as JSON text, lone surrogates escaped."""
    if v is None or v == "":
        return None
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
    return s.encode("utf-8", "backslashreplace").decode("utf-8")


def norm_addr(s):
    """'aa-bb-cc-dd-ee-ff' / 'AABBCCDDEEFF' -> 'AA:BB:CC:DD:EE:FF'; anything else -> None (validated, not scraped)."""
    s = s.strip().upper() if isinstance(s, str) else ""
    if not ADDR_RE.fullmatch(s):
        return None
    h = hexdigits(s)
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def laa_bit(addr):
    return bool(int(addr[:2], 16) & 0x02)


def norm_ts(raw, naive_tz, naive_label=None):
    """-> ('YYYY-MM-DDTHH:MM:SS.mmmZ' in UTC, how) or (None, None). how = 'offset', or for a time with no offset
    naive_label / 'assumed:<zone>'. Fixed width, so sorting the text sorts by time (the legacy tool compared raw text)."""
    if not isinstance(raw, str) or not raw.strip():
        return None, None
    try:
        t = dt.datetime.fromisoformat(raw.strip())
        how = "offset"
        if t.tzinfo is None:
            # shortcut: in the repeated fall-back hour a naive time resolves to its first (DST) reading; capture with an offset if that matters
            t, how = t.replace(tzinfo=ZoneInfo(naive_tz)), naive_label or f"assumed:{naive_tz}"
        return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z", how
    except (ValueError, OverflowError):
        return None, None


def num(v, cast=float):
    try:
        x = cast(v) if v not in (None, "") and not isinstance(v, bool) else None
    except (TypeError, ValueError, OverflowError):
        return None
    if x is None or (isinstance(x, float) and not math.isfinite(x)) or (isinstance(x, int) and abs(x) > 2 ** 62):
        return None
    return x


def parse_ies(ie_raw):
    """SWIVEL's 'id:hex,id:hex,...' information elements -> [(id, bytes)]; unreadable entries are skipped."""
    out = []
    for part in (ie_raw or "").split(","):
        i, _, h = part.partition(":")
        try:
            out.append((int(i), bytes.fromhex(h)))
        except ValueError:
            pass
    return out


def security_ies(ie_raw):
    """The RSN element (48) and WPA vendor element (221, 00:50:F2:01) from the IE string, verbatim."""
    keep = [p for p in (ie_raw or "").split(",") if p.startswith("48:") or p.upper().startswith("221:0050F201")]
    return ",".join(keep) or None


def blank_sighting(path, line, fmt, origin, raw):
    s = dict.fromkeys(SIGHTING_COLS)
    s.update(source_file=os.path.basename(path), source_line=line, source_format=fmt, origin=origin, raw=raw)
    return s


def problem(s):
    if s["address"] is None:
        return "malformed_address"
    if s["radio"] is None:
        return "unknown_radio"
    if s["ts_utc"] is None:
        return "malformed_timestamp"
    return None


def phone_sighting(path, line, raw, rec, fmt, naive_tz):
    s = blank_sighting(path, line, fmt, "phone", raw)
    if not isinstance(rec, dict):
        s["noise_reason"] = "malformed_json"
        return s
    s["session_id"] = txt(rec.get("session_id")) or os.path.basename(path)
    kind = str(rec.get("kind") or "").strip().upper()
    if kind == "SWEEP":                                  # active subnet-sweep hit: a LAN device keyed by its real MAC (wifi); MAC-less (IP-only) hits stay sightings, IP kept in raw
        s["radio"], s["address"] = "wifi", norm_addr(rec.get("mac"))
    elif kind == "SELF":                                 # the phone's OWN network context, keyed by the joined AP's BSSID; an isolated radio so the phone's IP never lands on the AP's own row
        s["radio"], s["address"] = "self", norm_addr(rec.get("mac"))
    else:
        s["radio"] = RADIO.get(kind)
        s["address"] = norm_addr(rec.get("mac"))
    s["address_type"] = (txt(rec.get("address_type")) or "").strip() or None
    s["ts_raw"] = txt(rec.get("iso_time"))
    s["ts_utc"], s["ts_tz"] = norm_ts(rec.get("iso_time"), naive_tz)
    s["rssi"] = num(rec.get("rssi"), int)
    s["lat"], s["lon"], s["gps_accuracy"] = num(rec.get("lat")), num(rec.get("lon")), num(rec.get("gps_accuracy_m"))
    s["name"] = txt(rec.get("ssid_or_name"))            # verbatim: a trailing space makes a different SSID
    if s["radio"] == "wifi":
        s["ie_raw"] = txt(rec.get("information_elements"))
        s["security_raw"] = security_ies(s["ie_raw"])
    s["noise_reason"] = problem(s)
    return s


def wigle_sightings(path, naive_tz):
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as f:
        pre = f.readline()
        if not pre.startswith("WigleWifi"):
            sys.exit(f"{os.path.basename(path)}: not a WigleCSV (first line should start 'WigleWifi')")
        origin = "phone" if "appRelease=SWIVEL" in pre else "kismet" if "kismet" in pre.lower() else "other"
        # Kismet's exporter formats FirstSeen with gmtime_r (checked in /usr/bin/kismetdb_to_wiglecsv); SWIVEL's export
        # writes phone-local time (matches its .json's -0400 times), so only that one is read in --naive-tz.
        zone, label = (naive_tz, None) if origin == "phone" else ("UTC", "utc:kismet_wiglecsv" if origin == "kismet" else None)
        rd = csv.reader(f)
        header = next(rd, None) or []
        if "MAC" not in header:
            sys.exit(f"{os.path.basename(path)}: WigleCSV without its column-header line; nothing ingested")
        for row in rd:
            line = rd.line_num + 1                       # + the pre-header line
            if len(row) != len(header):                  # short or long: columns can't be trusted
                s = blank_sighting(path, line, "wiglecsv", origin, json.dumps(row, ensure_ascii=False))
                s["noise_reason"] = "malformed_row"
                yield s
                continue
            r = dict(zip(header, row))                   # by column name: Kismet writes WigleWifi-1.6, SWIVEL 1.4
            s = blank_sighting(path, line, "wiglecsv", origin, json.dumps(r, ensure_ascii=False))
            s["session_id"] = os.path.basename(path)
            s["radio"] = RADIO.get(r.get("Type", "").strip().upper())
            s["address"] = norm_addr(r.get("MAC"))
            s["ts_raw"] = r.get("FirstSeen") or None
            s["ts_utc"], s["ts_tz"] = norm_ts(r.get("FirstSeen"), zone, label)
            s["rssi"] = num(r.get("RSSI"), int)
            lat, lon = num(r.get("CurrentLatitude")), num(r.get("CurrentLongitude"))
            if (lat, lon) != (0.0, 0.0):                 # 0,0 is how WigleCSV writers say "no fix"
                s["lat"], s["lon"] = lat, lon
            s["gps_accuracy"] = num(r.get("AccuracyMeters"))
            s["name"] = r.get("SSID") or None
            if s["radio"] == "wifi":
                s["security_raw"] = r.get("AuthMode") or None
            s["noise_reason"] = problem(s)
            yield s


# ---- Kismet native .kismet log (SQLite). Schema from kismetwireless/kismet kis_databaselogfile.cc:
# devices(first_time,last_time,...,phyname,devmac,strongest_signal,avg_lat,avg_lon,...,bytes_data,type,device);
# alerts(ts_sec,ts_usec,phyname,devmac,lat,lon,header,json). Times are epoch seconds UTC; (0,0) coords = no fix;
# device/json blobs are plain JSON (not read here — the flat columns are stable across versions, the big blob is not). ----

KISMET_PHY = {"IEEE802.11": "wifi", "BTLE": "ble", "Bluetooth": "bt-classic"}   # other phys -> unknown_radio (kept, R5)


def epoch_utc(sec):
    """Kismet epoch seconds (UTC) -> ('YYYY-MM-DDTHH:MM:SS.mmmZ', 'utc:kismet_db') or (None, None)."""
    if not isinstance(sec, (int, float)) or isinstance(sec, bool) or sec <= 0:
        return None, None
    try:
        return dt.datetime.fromtimestamp(sec, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z", "utc:kismet_db"
    except (ValueError, OverflowError, OSError):
        return None, None


def _kismet_obj(blob):
    """A Kismet device blob (plain, zlib- or gzip-compressed JSON) as a dict, or None. Never raises (R5)."""
    obj = None
    if isinstance(blob, str):
        try:
            obj = json.loads(blob)
        except ValueError:
            obj = None
    if obj is None and isinstance(blob, (bytes, bytearray)):
        for dec in (lambda x: x, zlib.decompress, gzip.decompress):   # Kismet may store the blob plain or compressed
            try:
                obj = json.loads(dec(bytes(blob)))
                break
            except Exception:
                continue
    return obj if isinstance(obj, dict) else None


def kismet_probed_ssids(blob):
    """Probed SSIDs (the saved networks a client broadcasts in probe requests) from a Kismet device blob's
    dot11.device.probed_ssid_map. Tolerant: a missing key, schema drift, or an undecodable/compressed blob yields []
    and never raises (R5: never drop the row; R8: describes the device's broadcasts, not a person)."""
    obj = _kismet_obj(blob)
    if obj is None:
        return []
    d = obj.get("dot11.device")
    pm = d.get("dot11.device.probed_ssid_map") if isinstance(d, dict) else None
    entries = pm if isinstance(pm, list) else list(pm.values()) if isinstance(pm, dict) else []
    out = []
    for e in entries:
        if isinstance(e, dict):
            s = e.get("dot11.probedssid.ssid")
            if isinstance(s, str) and s:                  # skip the empty/wildcard broadcast probe
                out.append(s)
    return out


def kismet_advertised_ssids(blob):
    """Beaconed/advertised SSIDs from a Kismet AP device blob's dot11.device.advertised_ssid_map. Only an AP beacons an
    advertised SSID (a client probes -> probed_ssid_map), so an entry here is a positive AP fact. Each yields the SSID
    (Kismet fills the real name even when cloaked=1, once it sees a probe-response = the hidden-SSID reveal), the
    human-readable crypt string, the cloaked flag, and any WPS make/model/serial Kismet decoded (de-anonymizes an AP even
    behind BSSID randomization). Tolerant like kismet_probed_ssids: missing keys / schema drift / undecodable blob -> []
    and never raises (R5; R8: describes the AP, not a person)."""
    obj = _kismet_obj(blob)
    if obj is None:
        return []
    d = obj.get("dot11.device")
    am = d.get("dot11.device.advertised_ssid_map") if isinstance(d, dict) else None
    entries = am if isinstance(am, list) else list(am.values()) if isinstance(am, dict) else []
    out = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        ssid = e.get("dot11.advertisedssid.ssid")
        name, number = txt(e.get("dot11.advertisedssid.wps_model_name")), txt(e.get("dot11.advertisedssid.wps_model_number"))
        model = f"{name} ({number})" if name and number and number not in name else name or number
        wps = {k: v for k, v in (("make", txt(e.get("dot11.advertisedssid.wps_manuf"))),
                                  ("model", model), ("serial", txt(e.get("dot11.advertisedssid.wps_serial_number")))) if v}
        out.append({"ssid": ssid if isinstance(ssid, str) else "",
                    "cloaked": bool(e.get("dot11.advertisedssid.cloaked")),
                    "crypt": txt(e.get("dot11.advertisedssid.crypt_string")),   # captured for a later verified security_modes mapping
                    "wps": wps})
    return out


IPDATA_SOURCE = {1: "kismet_factoryguess", 2: "kismet_udptcp", 3: "kismet_arp", 4: "kismet_dhcp"}  # dot11.client.ipdata.type; 0=unknown/5=group skipped


def ipv4_from_u32(n):
    """Kismet's packed uint32 ipdata.address -> dotted IPv4. Low byte first (the value as stored on a little-endian
    capture host). shortcut: octet order UNVERIFIED against a live capture — confirm against a known gateway (e.g. a
    .1) and flip the shifts here if reversed."""
    try:
        n = int(n) & 0xFFFFFFFF
    except (ValueError, TypeError):
        return None
    return f"{n & 255}.{(n >> 8) & 255}.{(n >> 16) & 255}.{(n >> 24) & 255}"


def kismet_client_ips(blob):
    """[(client_mac, dotted_ipv4, source)] from a Kismet AP blob's dot11.device.client_map -> each client's
    dot11.client.ipdata (a packed uint32 address + a 'type' = dhcp/arp/udptcp/factoryguess). Kismet learns these ONLY
    from CLEARTEXT data frames (open/decrypted networks), so an all-encrypted capture yields none. IPv4 only (Kismet
    stores no IPv6). Tolerant like kismet_probed_ssids (R5); R8: describes the device, not a person."""
    obj = _kismet_obj(blob)
    if obj is None:
        return []
    d = obj.get("dot11.device")
    cm = d.get("dot11.device.client_map") if isinstance(d, dict) else None
    out = []
    for mac, c in (cm.items() if isinstance(cm, dict) else ()):
        if not isinstance(c, dict):
            continue
        ipd = c.get("dot11.client.ipdata")
        if not isinstance(ipd, dict):
            continue
        t = ipd.get("kismet.common.ipdata.type")
        src = IPDATA_SOURCE.get(t if isinstance(t, int) and not isinstance(t, bool) else -1)
        addr = ipd.get("kismet.common.ipdata.address")
        if src and isinstance(addr, (int, float)) and not isinstance(addr, bool) and int(addr) != 0:
            ip, m = ipv4_from_u32(addr), norm_addr(mac)
            if ip and m:
                out.append((m, ip, src))
    return out


def kismet_sightings(path):
    """One sighting per Kismet `devices` row (origin 'kismet'), with the device's IDS alerts (matched by radio+MAC) and
    a few Kismet-only fields carried in `raw`. Opened immutably: the capture is never written and no -wal/-shm is created.
    A corrupt or version-drifted .kismet exits cleanly (like a non-Kismet file) instead of throwing a traceback."""
    try:
        con = sqlite3.connect("file:" + urllib.parse.quote(os.path.abspath(path)) + "?immutable=1", uri=True)
    except sqlite3.Error as e:
        sys.exit(f"{os.path.basename(path)}: cannot open as a Kismet .kismet SQLite log ({e})")
    con.row_factory = sqlite3.Row
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "devices" not in tables:
            sys.exit(f"{os.path.basename(path)}: not a Kismet .kismet log (no 'devices' table)")
        have = {r[1] for r in con.execute("PRAGMA table_info(devices)")}
        if "devmac" not in have or "phyname" not in have:
            sys.exit(f"{os.path.basename(path)}: Kismet 'devices' table missing devmac/phyname")
        alerts = collections.defaultdict(set)            # (radio, address) -> {header}: an alert belongs to its own phy
        if "alerts" in tables:
            for a in con.execute("SELECT devmac, header, phyname FROM alerts"):
                mac = norm_addr(a["devmac"])
                if mac and a["header"]:
                    alerts[(KISMET_PHY.get((a["phyname"] or "").strip()), mac)].add(str(a["header"]))
        want = ["first_time", "last_time", "phyname", "devmac", "strongest_signal", "avg_lat", "avg_lon", "type", "bytes_data", "device"]
        cols = [c for c in want if c in have]            # tolerate schema drift: read whichever optional columns exist
        for n, row in enumerate(con.execute(f"SELECT {', '.join(cols)} FROM devices"), 1):
            g = lambda c: row[c] if c in cols else None
            s = blank_sighting(path, n, "kismet_db", "kismet", None)
            s["session_id"] = os.path.basename(path)
            s["radio"] = KISMET_PHY.get((g("phyname") or "").strip())
            s["address"] = norm_addr(g("devmac"))
            ft = g("first_time")
            s["ts_utc"], s["ts_tz"] = epoch_utc(ft)
            s["ts_raw"] = str(ft) if s["ts_utc"] else None   # don't store a truthy 'None'/'0' for a NULL/unset first_time
            sig = g("strongest_signal")
            s["rssi"] = sig if sig not in (None, 0) else None
            lat, lon = num(g("avg_lat")), num(g("avg_lon"))
            if (lat, lon) != (0.0, 0.0):                 # Kismet stores 0,0 (not NULL) when it has no location
                s["lat"], s["lon"] = lat, lon
            extra = {k: v for k, v in (("kismet_type", txt(g("type"))), ("bytes_data", g("bytes_data"))) if v not in (None, "", 0)}
            lt, last = g("last_time"), ft                 # trust last_time as an interval end only if sane: finite, >=first, <=+31d
            if (isinstance(ft, (int, float)) and not isinstance(ft, bool) and isinstance(lt, (int, float))
                    and not isinstance(lt, bool) and math.isfinite(lt) and ft <= lt <= ft + 31 * 86400):
                last = lt
            raw = {"last_time": last, "extra": extra, "alerts": sorted(alerts.get((s["radio"], s["address"]), ()))}
            probes = kismet_probed_ssids(g("device"))     # networks a client broadcasts it's looking for; kept local (R1/R2)
            if probes:
                raw["probed_ssids"] = probes
            adv = kismet_advertised_ssids(g("device"))    # beaconed SSIDs (AP): the SSID becomes device_name; crypt/WPS carried for derive
            if adv:
                ssid = next((a["ssid"] for a in adv if a["ssid"]), None)
                if ssid:
                    s["name"] = ssid                      # a native-.kismet-only AP gets its beaconed SSID as a name (was blank before)
                raw["advertised"] = adv
            s["raw"] = json.dumps(raw, ensure_ascii=False)
            s["noise_reason"] = problem(s)
            yield s
            for cmac, cip, csrc in kismet_client_ips(g("device")):   # IPs Kismet sniffed for this AP's clients -> a synthetic sighting per client MAC
                cs = blank_sighting(path, n, "kismet_db", "kismet", None)
                cs["session_id"] = s["session_id"]
                cs["radio"] = "wifi"                      # a client in an 802.11 AP's client_map is a Wi-Fi station
                cs["address"] = cmac
                cs["ts_utc"], cs["ts_tz"], cs["ts_raw"] = s["ts_utc"], s["ts_tz"], s["ts_raw"]
                cs["rssi"], cs["lat"], cs["lon"] = s["rssi"], s["lat"], s["lon"]
                cs["raw"] = json.dumps({"observed_ip": cip, "observed_ip_source": csrc,
                                        "observed_ip_confidence": "high" if csrc in ("kismet_dhcp", "kismet_arp") else "med"}, ensure_ascii=False)
                cs["noise_reason"] = problem(cs)
                yield cs
    except sqlite3.Error as e:
        sys.exit(f"{os.path.basename(path)}: unreadable Kismet .kismet log ({e})")
    finally:
        con.close()


def sightings_from(path, naive_tz):
    low = path.lower()
    if low.endswith(".kismet"):
        yield from kismet_sightings(path)
    elif low.endswith(".ndjson"):
        with open(path, encoding="utf-8-sig", errors="replace") as f:
            for n, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    rec = None
                yield phone_sighting(path, n, line.rstrip("\n"), rec, "swivel_ndjson", naive_tz)
    elif low.endswith(".json"):
        with open(path, encoding="utf-8-sig") as f:
            data = json.load(f)                          # a broken export has no rows to keep: stop loudly
        for n, rec in enumerate(data if isinstance(data, list) else [data], 1):
            yield phone_sighting(path, n, json.dumps(rec, ensure_ascii=False), rec, "swivel_json", naive_tz)
    elif low.endswith((".wiglecsv", ".csv")):
        yield from wigle_sightings(path, naive_tz)
    else:
        sys.exit(f"{os.path.basename(path)}: unsupported input (want .ndjson, .json, .wiglecsv/WigleCSV .csv, or .kismet)")

# ---- Wi-Fi security (IEEE 802.11-2020 9.4.2.24; WPA = the pre-RSN vendor element 00:50:F2:01) ----

SUITE_CIPHER = {1: "WEP", 2: "TKIP", 4: "CCMP", 5: "WEP", 8: "GCMP", 9: "GCMP", 10: "CCMP"}
RSN_AKM = {1: "EAP", 2: "PSK", 3: "EAP", 4: "PSK", 5: "EAP", 6: "PSK", 8: "SAE", 9: "SAE", 11: "EAP", 12: "EAP",
           13: "EAP", 18: "OWE", 19: "PSK", 20: "PSK", 23: "EAP", 24: "SAE", 25: "SAE"}
WPA3_AKM = {8, 9, 12, 13, 24, 25}                        # SAE family and the 192-bit (SHA-384) enterprise AKMs
WPA3_IF_MFP_REQUIRED = {1, 3, 5}                         # 802.1X AKMs are WPA3-Enterprise only with PMF required
WPA_AKM = {1: "EAP", 2: "PSK"}
NO_GROUP_TRAFFIC, USE_GROUP_CIPHER, MFPR = 7, 0, 0x0040


def parse_rsn(body, wpa=False):
    """RSN element body (for WPA: the body after 00:50:F2:01) -> (modes, akms, ciphers). Fields the element
    legitimately omits take the standard defaults; an empty, wrong-version or truncated element yields nothing."""
    oui, akm_table = (b"\x00\x50\xf2", WPA_AKM) if wpa else (b"\x00\x0f\xac", RSN_AKM)
    default_cipher = 2 if wpa else 4
    if len(body) < 2 or body[:2] != b"\x01\x00" or 2 < len(body) < 6:
        return set(), set(), set()

    def suite_list(i):                                   # -> (suites, next index, complete?)
        if len(body) < i + 2:
            return None, i, True
        n, i, out = int.from_bytes(body[i:i + 2], "little"), i + 2, []
        for _ in range(n):
            if len(body) < i + 4:
                return out, i, False
            out.append((body[i:i + 3], body[i + 3]))
            i += 4
        return out, i, True

    group = (body[2:5], body[5]) if len(body) >= 6 else (oui, default_cipher)
    pairwise, i, ok = suite_list(6)
    akms, mfp_required = None, False
    if pairwise is None:
        pairwise, akms = [(oui, default_cipher)], [(oui, 1)]
    elif ok:
        akms, i, ok = suite_list(i)
        if akms is None:
            akms = [(oui, 1)]                            # default AKM: 802.1X
        elif ok and len(body) >= i + 2:
            mfp_required = bool(int.from_bytes(body[i:i + 2], "little") & MFPR)
    akms = akms or []

    def cipher(s):
        o, t = s
        if o == oui and t == USE_GROUP_CIPHER and s is not group:
            return cipher(group)
        return SUITE_CIPHER.get(t, f"OTHER:{t}") if o == oui else f"OTHER:{o.hex()}:{t}"

    ciphers = {cipher(p) for p in pairwise}
    if not (group[0] == oui and group[1] == NO_GROUP_TRAFFIC):
        ciphers.add(cipher(group))
    modes, akm_names = set(), set()
    for o, t in akms:
        a = akm_table.get(t, f"OTHER:{t}") if o == oui else f"OTHER:{o.hex()}:{t}"
        akm_names.add(a)
        wpa3 = o == oui and not wpa and (t in WPA3_AKM or (t in WPA3_IF_MFP_REQUIRED and mfp_required))
        proto = "WPA" if wpa else "WPA3" if wpa3 else "WPA2"
        for p in pairwise:
            modes.add(f"OWE-{cipher(p)}" if a == "OWE" else f"{proto}-{a}-{cipher(p)}")
    return modes, akm_names, ciphers


CAPS_FLAGS = {"ESS", "IBSS", "MESH", "WPS", "MFPC", "MFPR", "P2P", "BLE", "RTT", "11MC", "PASSPOINT", "OWE_TRANSITION"}


def parse_caps(caps):
    """Android ScanResult.capabilities / WigleCSV AuthMode, e.g. '[WPA2-PSK-CCMP][RSN-PSK+SAE-CCMP][ESS][WPS]'.
    Used only when a sighting has no readable RSN/WPA element. OPEN only when every token is a known non-security
    flag; a token it can't read is kept as OTHER:<token>, never guessed."""
    modes, akms, ciphers = set(), set(), set()
    caps = caps or ""
    tokens = re.findall(r"\[([^\]]*)\]", caps)
    if caps.strip() and not tokens:
        return {f"OTHER:{caps.strip()}"}, set(), set()
    for tok in tokens:
        t = tok.upper()
        if t in CAPS_FLAGS:
            continue
        if t.startswith("WEP"):
            modes.add("WEP"), akms.add("NONE"), ciphers.add("WEP")
            continue
        found = [a for a in ("PSK", "SAE", "EAP", "OWE") if a in t]
        if not found or not t.startswith(("WPA", "RSN", "OWE")):
            modes.add(f"OTHER:{tok}")
            continue
        cs = [c for c in ("CCMP", "GCMP", "TKIP") if c in t] or ["?"]
        proto = "WPA" if t.startswith("WPA-") else "WPA3" if t.startswith("WPA3") else "WPA2"
        for a in found:
            p = "WPA3" if proto != "WPA" and (a == "SAE" or (a == "EAP" and "SUITE" in t and "B" in t)) else proto
            for c in cs:
                modes.add(f"OWE-{c}" if a == "OWE" else f"{p}-{a}-{c}")
        akms.update(found)
        ciphers.update(c for c in cs if c != "?")
    if not modes and tokens:                             # only known non-security flags, e.g. "[ESS]"
        modes.add("OPEN"), akms.add("NONE")
    return modes, akms, ciphers


WPS_OUI_TYPE, WPA_OUI_TYPE = bytes.fromhex("0050F204"), bytes.fromhex("0050F201")
WPS_ATTR = {0x1021: "make", 0x1023: "model_name", 0x1024: "model_number", 0x1042: "serial"}


def parse_wps(body):
    """WPS attributes (type/length big-endian) -> {make, model_name, model_number, serial} where present.
    Stops at a truncated attribute rather than storing half of it."""
    out, i = {}, 0
    while i + 4 <= len(body):
        t, n = int.from_bytes(body[i:i + 2], "big"), int.from_bytes(body[i + 2:i + 4], "big")
        if i + 4 + n > len(body):
            break
        v, i = body[i + 4:i + 4 + n], i + 4 + n
        if t in WPS_ATTR:
            s = v.decode("utf-8", "backslashreplace").strip("\x00 ").strip()
            if s:
                out[WPS_ATTR[t]] = s
    return out

# ---- devices (derived from sightings only) ----

DEVICE_COLS = [
    "address", "radio",
    "address_type", "address_type_source", "address_type_confidence",
    "is_randomized", "is_randomized_source", "is_randomized_confidence",
    "oui_vendor", "oui_vendor_source", "oui_vendor_confidence",
    "oui_device_type", "oui_device_type_source", "oui_device_type_confidence",
    "advertised_company", "advertised_company_id", "advertised_company_source", "advertised_company_confidence",
    "device_name", "device_name_source", "device_name_confidence",
    "device_class", "device_class_source", "device_class_confidence",
    "is_tracker", "tracker_type", "tracker_signature_source", "tracker_confidence",
    "apple_continuity_type", "apple_continuity_type_source", "apple_continuity_type_confidence",
    "advertised_services", "advertised_services_source", "advertised_services_confidence",
    "fingerprint_hash", "fingerprint_hash_source", "fingerprint_hash_confidence",
    "device_cluster_id",
    "location_clusters", "location_clusters_source", "location_clusters_confidence",
    "followed_flag", "followed_flag_source", "followed_flag_confidence",
    "security_modes", "security_modes_source", "security_modes_confidence",
    "security_conflict", "security_conflict_source", "security_conflict_confidence",
    "wps_enabled", "wps_enabled_source", "wps_enabled_confidence",
    "wps_make", "wps_make_source", "wps_make_confidence",
    "wps_model", "wps_model_source", "wps_model_confidence",
    "wps_serial", "wps_serial_source", "wps_serial_confidence",
    "first_seen", "first_seen_source", "first_seen_confidence",
    "last_seen", "last_seen_source", "last_seen_confidence",
    "sighting_count", "sessions_seen", "rssi_max", "rssi_median", "probed_ssids",
    "seen_by_phone", "seen_by_kismet",                   # facts (which source logged this address): no source/confidence pair
    "seen_by_both_within_window", "seen_by_both_within_window_source", "seen_by_both_within_window_confidence",
    "kismet_ids_alerts", "kismet_ids_alerts_source", "kismet_ids_alerts_confidence",
    "near_alpr", "near_alpr_source", "near_alpr_confidence",
    "wigle_location", "wigle_location_source", "wigle_location_confidence",   # stage 6: WiGLE AP geolocation (opt-in, cached)
    "beacondb_location", "beacondb_location_source", "beacondb_location_confidence",   # beaconDB AP geolocation (opt-in, keyless)
    "observed_ip", "observed_ip_source", "observed_ip_confidence",   # layer-3 IPv4: app subnet-sweep / own-network, or Kismet sniffed client ipdata
    "info_score", "noise_reason",                        # device-level meta: usefulness score + why-thin flag; drives the dead-row drop (stage 7)
]
NAME_SOURCE = {"wifi": "ssid", "ble": "advertised_local_name", "bt-classic": "bt_remote_name"}
TS_CONFIDENCE = {"offset": "high", "utc:kismet_wiglecsv": "high"}


def top(counter):
    """Most common value and a confidence that drops when sightings disagree."""
    v = counter.most_common(1)[0][0]
    return v, "high" if len(counter) == 1 else "med"


def company_ids(manufacturer):
    """SWIVEL 'manufacturer' hex (comma-separated entries) -> company IDs (first two bytes, little-endian)."""
    out = []
    for e in str(manufacturer or "").split(","):
        e = e.strip()
        if len(e) >= 4 and all(c in "0123456789abcdefABCDEF" for c in e[:4]):
            out.append(int(e[2:4] + e[0:2], 16))
    return out


def ble_view(rows):
    """address_type as the app reported it for this address's BLE sightings -> is_randomized (a guess, so low)."""
    types = collections.Counter(r["address_type"] for r in rows if r["address_type"])
    if not types:
        return None, None, None
    t = types.most_common(1)[0][0]
    if t.startswith("random"):
        return 1, "swivel_app_top_bit_guess", "low"
    if t == "public":
        return 0, "swivel_app_top_bit_guess", "low"
    return None, None, None


# ---- signatures: coarse device_class / tracker classification (data/signatures.json; no advert decoding) ----

BASE_UUID_SUFFIX = "00001000800000805F9B34FB"            # 0000XXXX-0000-1000-8000-00805f9b34fb -> XXXX is the 16-bit UUID
SIG_PATH = os.path.join(HERE, "signatures.json")


def load_signatures(path=SIG_PATH):
    with open(path, encoding="utf-8") as f:
        sigs = json.load(f)["signatures"]
    for s in sigs:                                       # parse the hex match values once
        s["_match"] = {k: (int(v, 16) if k in ("company_id", "apple_type", "service_uuid16") else v)
                       for k, v in s["match"].items()}
    return sigs


def uuid16s(rec):
    """16-bit service UUIDs present in a record's 'services' (128-bit hex) and 'service_data' keys."""
    out = set()
    sd = rec.get("service_data")
    entries = str(rec.get("services") or "").split(",") + (list(sd) if isinstance(sd, dict) else [])
    for entry in entries:
        h = hexdigits(entry)
        if len(h) == 32 and h[:4] == "0000" and h[8:] == BASE_UUID_SUFFIX:
            out.add(int(h[4:8], 16))
    return out


# Apple Continuity message types (company 0x004C TLV type byte -> name). A coarse, reverse-engineered PUBLIC mapping (facts,
# not Apple's data): lets us tell an AirTag/Find My broadcast from an iPhone presence beacon. Unknown bytes render as 0xNN.
APPLE_CONTINUITY_TYPES = {0x02: "iBeacon", 0x05: "AirDrop", 0x07: "ProximityPair", 0x08: "HeySiri", 0x09: "AirPlayTarget",
                          0x0A: "AirPlaySource", 0x0B: "MagicSwitch", 0x0C: "Handoff", 0x0D: "TetheringTarget",
                          0x0E: "TetheringSource", 0x0F: "NearbyAction", 0x10: "NearbyInfo", 0x12: "FindMy"}


def apple_tlv_types(rec):
    """Apple Continuity TLV type bytes present in the 0x004C manufacturer-data entry (type/length/value chain)."""
    types = set()
    for entry in str(rec.get("manufacturer") or "").split(","):
        h = hexdigits(entry.strip())
        if h[:4].upper() != "4C00":
            continue
        try:
            b = bytes.fromhex(h[4:])
        except ValueError:
            continue
        i = 0
        while i + 2 <= len(b):
            t, n = b[i], b[i + 1]
            if i + 2 + n > len(b):                        # truncated TLV: stop, don't guess
                break
            types.add(t)
            i += 2 + n
    return types


def appearance_value(rec):
    """GAP Appearance (AD type 0x19) as an int if the capture carries one. Kismet BLE devices may expose it; the SWIVEL
    phone app does not log it yet, so this is latent until the capture includes it. Accepts an int or a 0x.. string."""
    v = rec.get("appearance", rec.get("gap_appearance"))
    if v is None or isinstance(v, bool):
        return None
    try:
        return int(v, 16) if isinstance(v, str) and v.strip().lower().startswith("0x") else int(v)
    except (ValueError, TypeError):
        return None


def class_of_device_value(rec):
    """Bluetooth Class-of-Device as an int if the capture carries one. The SWIVEL phone app logs it for Classic
    (BluetoothClass.getDeviceClass()); Kismet may too. The major device class is bits 8-12. Accepts int or 0x.. string."""
    v = rec.get("class_of_device", rec.get("cod"))
    if v is None or isinstance(v, bool):
        return None
    try:
        return int(v, 16) if isinstance(v, str) and v.strip().lower().startswith("0x") else int(v)
    except (ValueError, TypeError):
        return None


def classify(recs, sigs):
    """Match coarse signatures against a device's records. Returns (device_class, is_tracker, tracker_type,
    tracker_source, confidence) for the first tracker match (else the first match), or all-None if nothing matches."""
    company = {c for rec in recs for c in company_ids(rec.get("manufacturer"))}
    uu = {u for rec in recs for u in uuid16s(rec)}
    at = {t for rec in recs for t in apple_tlv_types(rec)}
    present = {"company_id": company, "service_uuid16": uu, "apple_type": at}
    matched = [s for s in sigs if all(v in present[k] for k, v in s["_match"].items())]
    if not matched:
        return None, None, None, None, None
    best = next((s for s in matched if s["is_tracker"]), matched[0])
    src = "signatures.json:" + "+".join(sorted(s["id"] for s in matched))
    return best["device_class"], int(best["is_tracker"]), best["tracker_type"], src, best["confidence"]


def wifi_fingerprint(ie_raw):
    """A coarse, stable fingerprint of a Wi-Fi beacon: the sorted element IDs plus each vendor element's OUI:subtype.
    SHA-256, first 16 hex. Deterministic; coarse enough to collide across same-model APs, so it is not an identity."""
    ies = parse_ies(ie_raw)
    if not ies:
        return None
    ids = sorted(i for i, _ in ies)
    vendor = sorted(b[:4].hex() for i, b in ies if i == 221 and len(b) >= 4)
    canon = "ids:" + ",".join(map(str, ids)) + "|vendor:" + ",".join(vendor)
    return hashlib.sha256(canon.encode()).hexdigest()[:16]


def is_noise_address(addr):
    h = addr.replace(":", "")
    return h == "000000000000" or h == "FFFFFFFFFFFF"

# ---- location (stage 3): clusters, followed_flag, near_alpr. All offline, describes the DEVICE, never a person (R8) ----

def haversine_m(a, b):
    """Great-circle metres between two (lat, lon) points."""
    (lat1, lon1), (lat2, lon2) = a, b
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    x = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * 6371000.0 * math.asin(min(1.0, math.sqrt(x)))


def cluster_points(pts, max_m):
    """Greedy: each point joins the first cluster whose running centroid is within max_m, else starts a new one.
    Latitude centroid is a plain mean; longitude is a circular mean (correct across the +/-180 meridian).
    -> [(n, centroid_lat, centroid_lon)]. Order-dependent and coarse (hence 'med'); good enough for 'where was it seen'."""
    clusters = []                                        # each: [n, sum_lat, sum_sin_lon, sum_cos_lon]
    def centroid(c):
        return (c[1] / c[0], math.degrees(math.atan2(c[2] / c[0], c[3] / c[0])))
    for lat, lon in pts:
        rlon = math.radians(lon)
        for c in clusters:
            if haversine_m((lat, lon), centroid(c)) <= max_m:
                c[0] += 1; c[1] += lat; c[2] += math.sin(rlon); c[3] += math.cos(rlon)
                break
        else:
            clusters.append([1, lat, math.sin(rlon), math.cos(rlon)])
    return [(c[0], *centroid(c)) for c in clusters]


def ts_epoch(iso):
    """'YYYY-MM-DDTHH:MM:SS.mmmZ' -> POSIX seconds, or None."""
    if not iso:
        return None
    try:
        return dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return None


def cross_check(d, rows, window):
    """seen_by_phone / seen_by_kismet (facts: which source logged this address); and from Kismet rows, the Kismet-only
    extra fields, the IDS alerts, and whether a phone sighting falls within +/- window s of a Kismet observation of the
    same address (co-present). Describes the device's observations, never a person (R8)."""
    phone_rows = [r for r in rows if r["origin"] == "phone"]
    kismet_rows = [r for r in rows if r["origin"] == "kismet"]
    d["seen_by_phone"], d["seen_by_kismet"] = int(bool(phone_rows)), int(bool(kismet_rows))
    alerts, intervals, probes, adv_wps = set(), [], set(), {}
    for r in kismet_rows:
        first = last = ts_epoch(r["ts_utc"])
        if r["source_format"] == "kismet_db":            # native .kismet carries last_time, alerts and probes in raw
            try:
                rec = json.loads(r["raw"])
            except (ValueError, TypeError):
                rec = {}
            alerts.update(a for a in (rec.get("alerts") or []) if isinstance(a, str))
            probes.update(s for s in (rec.get("probed_ssids") or []) if isinstance(s, str) and s)
            for a in (rec.get("advertised") or []):       # Kismet-decoded beacon WPS (native .kismet only); make/model/serial
                if isinstance(a, dict) and isinstance(a.get("wps"), dict):
                    adv_wps.update(a["wps"])
            lt = rec.get("last_time")
            if first is not None and isinstance(lt, (int, float)) and not isinstance(lt, bool) and lt >= first:
                last = lt
        if first is not None:
            intervals.append((first, last))              # a Kismet WigleCSV sighting is a point (first == last)
    if alerts:
        d["kismet_ids_alerts"] = json.dumps(sorted(alerts))
        d["kismet_ids_alerts_source"], d["kismet_ids_alerts_confidence"] = "kismet_db_alerts", "high"
    if probes:
        d["probed_ssids"] = json.dumps(sorted(probes), ensure_ascii=False)
    for k in ("make", "model", "serial"):                # Kismet already decoded the AP's beacon WPS; fill what the phone IEs didn't (cross_check runs after wifi_security)
        col = f"wps_{k}"
        if adv_wps.get(k) and not d.get(col):
            d[col] = json.dumps([adv_wps[k]])
            d[col + "_source"], d[col + "_confidence"] = "kismet_advertised_ssid", "high"
    if phone_rows and intervals:
        ptimes = [t for t in (ts_epoch(r["ts_utc"]) for r in phone_rows) if t is not None]
        matched = any(f - window <= p <= l + window for p in ptimes for f, l in intervals)
        d["seen_by_both_within_window"] = int(matched)
        d["seen_by_both_within_window_source"] = f"kismet_window_{window:.0f}s"
        d["seen_by_both_within_window_confidence"] = "high" if matched else "low"

# ---- online enrichment (stage 6): WiGLE AP geolocation. Opt-in in sources.json, manual (you run `wigle`), and scoped
# to fixed Wi-Fi AP BSSIDs only — never client/BLE/randomized MACs, never your GPS (spec R2/R3). Each lookup is cached to
# data/wigle/ap_cache.json; `run` folds it into devices offline, so a BSSID is sent to WiGLE at most once. ----

def parse_wigle(body):
    """WiGLE network/search JSON -> {'lat','lon'[,'ssid']} for the first result with usable coords, else None.
    Rejects non-finite/bool coords (json allows NaN/Infinity) and never raises on a malformed body."""
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(doc, dict):
        return None
    for res in (doc.get("results") or []):
        if not isinstance(res, dict):
            continue
        lat, lon = res.get("trilat"), res.get("trilong")
        if _coord(lat) and _coord(lon):
            out = {"lat": lat, "lon": lon}
            if res.get("ssid"):
                out["ssid"] = txt(res.get("ssid"))
            return out
    return None


def wigle_lookup(token, netid, endpoint, timeout=30):
    """One WiGLE AP lookup; returns the raw response bytes. Sends ONLY the BSSID (netid) — no GPS, no other identifiers."""
    url = endpoint + "?" + urllib.parse.urlencode({"netid": netid})
    req = urllib.request.Request(url, headers={"Authorization": "Basic " + token, "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


BEACONDB_PATH = "beacondb/ap_cache.json"             # BSSID -> location cache written by `beacondb`, read offline by `run`


def parse_beacondb(body):
    """beaconDB geolocate JSON -> {'lat','lon'} for a real AP-based fix, else None. DROPS any response carrying a
    'fallback' key: beaconDB itself flags that as a guess from the query's own IP (where the lookup ran from), not the
    AP's location. Dropped for CORRECTNESS, not privacy — it would stamp the AP with a wrong location; we send only the
    BSSID and store no IP, and we never compare it to the capture's GPS."""
    try:
        doc = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(doc, dict) or doc.get("fallback"):
        return None
    loc = doc.get("location")
    if isinstance(loc, dict) and _coord(loc.get("lat")) and _coord(loc.get("lng")):
        return {"lat": loc["lat"], "lon": loc["lng"]}
    return None


def beacondb_lookup(endpoint, bssid, timeout=30):
    """One beaconDB lookup for a single AP BSSID; returns the raw response bytes. Sends ONLY the BSSID — no GPS, no other
    identifiers. beaconDB needs no API key."""
    data = json.dumps({"wifiAccessPoints": [{"macAddress": bssid}]}).encode()
    req = urllib.request.Request(endpoint, data=data, headers={"Content-Type": "application/json", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def load_wigle_cache(path):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_wigle_cache(path, cache):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".part"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False)
    os.replace(tmp, path)                                # atomic: never leaves a half-written cache


def ap_bssids_to_lookup(conn, cached):
    """Addresses eligible for a WiGLE lookup, from a built DB: fixed Wi-Fi APs only, never randomized/LAA, never
    BLE/Classic, never clients (spec R2/R3). "AP" is keyed on a positive origin fact — seen_by_phone=1, i.e. the address
    appeared in a phone Wi-Fi scan, and Android returns only APs. It is deliberately NOT keyed on device_name, IEs,
    wps_enabled or fingerprint_hash: a client's probe request (future Kismet monitor-mode input, spec lines 63/130) carries
    a device_name (the SSID it hunts for) and IEs too, so keying on those would send a client MAC to WiGLE. The laa_bit
    re-check on the normalized address is a second guard against a wrong is_randomized. Skips anything already cached.
    shortcut: a Kismet-only AP (seen_by_kismet but never by the phone) is not looked up; add a Kismet AP-type check when
    real Kismet AP data exists."""
    rows = conn.execute("SELECT address FROM devices WHERE radio='wifi' "
                        "AND (is_randomized IS NULL OR is_randomized=0) AND seen_by_phone=1 "
                        # value-first: a strict daily cap (WiGLE) should spend its budget on the APs that matter — the
                        # evil-twin-suspect (security_conflict) and info-rich (info_score) ones first, not arbitrary DB order
                        "ORDER BY coalesce(security_conflict,0) DESC, coalesce(info_score,0) DESC, address")
    return [a for (a,) in rows if not laa_bit(a) and a not in cached]


def cmd_wigle(args):
    src = next((s for s in (load_sources(args.sources) or []) if isinstance(s, dict) and s.get("id") == "wigle_ap"), None)
    if not src or not src.get("enabled"):
        print('wigle_ap is OFF in sources.json. Set its "enabled": true to allow WiGLE lookups — Wi-Fi AP BSSIDs only, '
              "never client/BLE/randomized MACs, never your GPS.")
        return 0
    env = src.get("key_env", "WIGLE_API_TOKEN")
    token = os.environ.get(env)
    if not token:
        print(f"Set {env} to your WiGLE 'Encoded for use' token (wigle.net -> Account). The tool reads it from the "
              "environment only; it is never written to a file or printed.")
        return 0
    if not os.path.exists(args.db):
        sys.exit(f"{args.db}: no such DB. Run `run` first to build it.")
    endpoint = src.get("endpoint") or "https://api.wigle.net/api/v2/network/search"
    cache_path = os.path.join(args.registry, WIGLE_PATH)
    if os.path.basename(os.path.abspath(args.registry)) != "data":   # the cache holds BSSIDs + coords + SSIDs (R1)
        print(f"WARNING (R1): the cache {os.path.relpath(cache_path)} is outside a 'data/' folder and may not be "
              "git-ignored — it holds BSSIDs, SSIDs and coordinates. Keep it off GitHub and any sync.", file=sys.stderr)
    cache = load_wigle_cache(cache_path)
    con = sqlite3.connect("file:" + urllib.parse.quote(os.path.abspath(args.db)) + "?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        targets = ap_bssids_to_lookup(con, cache)
    finally:
        con.close()
    print(f"{len(targets)} Wi-Fi AP BSSID(s) to look up; {len(cache)} already cached.")
    if args.dry_run:
        print("dry run: nothing sent to WiGLE.")
        return 0
    targets = targets[:max(0, args.max)]
    queried = found = 0
    for addr in targets:
        try:
            body = wigle_lookup(token, addr, endpoint)
        except urllib.error.HTTPError as e:
            if e.code == 401:                            # bad/revoked token: stop, but keep lookups already fetched this run
                print(f"WiGLE rejected the token (401). Check {env}. Queried {queried}, located {found}; cached.")
                break
            if e.code in (403, 429):                     # out of daily queries: keep what we have, stop cleanly
                print(f"WiGLE stopped us ({e.code}: likely the daily query cap). Queried {queried}, located {found}; "
                      "cached. Re-run later to continue.")
                break
            print(f"WiGLE error {e.code} on one BSSID; skipping it.")
            continue
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"network error ({e}); stopping. Queried {queried}, located {found}; cached.")
            break
        queried += 1
        hit = parse_wigle(body)
        rec = {"found": bool(hit), "fetched_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        if hit:
            rec.update(hit)
            found += 1
        cache[addr] = rec
    save_wigle_cache(cache_path, cache)
    print(f"queried {queried}, located {found}. Cache: data/{WIGLE_PATH} ({len(cache)} BSSIDs). "
          "Re-run `run` to fold wigle_location into devices.")
    return 0

def cmd_beacondb(args):
    src = next((s for s in (load_sources(args.sources) or []) if isinstance(s, dict) and s.get("id") == "beacondb_ap"), None)
    if not src or not src.get("enabled"):
        print('beacondb_ap is OFF in sources.json. Set its "enabled": true to allow beaconDB lookups — Wi-Fi AP BSSIDs '
              "only, never client/BLE/randomized MACs, never your GPS.")
        return 0
    if not os.path.exists(args.db):
        sys.exit(f"{args.db}: no such DB. Run `run` first to build it.")
    endpoint = src.get("endpoint") or "https://api.beacondb.net/v1/geolocate"
    cache_path = os.path.join(args.registry, BEACONDB_PATH)
    if os.path.basename(os.path.abspath(args.registry)) != "data":   # the cache holds BSSIDs + coords (R1)
        print(f"WARNING (R1): the cache {os.path.relpath(cache_path)} is outside a 'data/' folder and may not be "
              "git-ignored — it holds BSSIDs and coordinates. Keep it off GitHub and any sync.", file=sys.stderr)
    cache = load_wigle_cache(cache_path)                 # a plain JSON dict cache, shared load/save with wigle
    con = sqlite3.connect("file:" + urllib.parse.quote(os.path.abspath(args.db)) + "?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        targets = ap_bssids_to_lookup(con, cache)        # same scope guard as WiGLE: phone-seen, non-randomized Wi-Fi APs only
    finally:
        con.close()
    print(f"{len(targets)} Wi-Fi AP BSSID(s) to look up on beaconDB (free, no key); {len(cache)} already cached.")
    if args.dry_run:
        print("dry run: nothing sent to beaconDB.")
        return 0
    queried = found = dropped = 0
    for addr in targets[:max(0, args.max)]:
        try:
            body = beacondb_lookup(endpoint, addr)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):                     # rate-limited: keep what we have, stop cleanly
                print(f"beaconDB stopped us ({e.code}). Queried {queried}, located {found}; cached. Re-run later.")
                break
            print(f"beaconDB error {e.code} on one BSSID; skipping it.")
            continue
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"network error ({e}); stopping. Queried {queried}, located {found}; cached.")
            break
        queried += 1
        hit = parse_beacondb(body)                       # None when beaconDB fell back to an IP guess (wrong location, dropped)
        rec = {"found": bool(hit), "fetched_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        if hit:
            rec.update(hit); found += 1
        else:
            dropped += 1
        cache[addr] = rec
    save_wigle_cache(cache_path, cache)
    print(f"queried {queried}, located {found}, dropped {dropped} IP-fallback(s). Cache: data/{BEACONDB_PATH} "
          f"({len(cache)} BSSIDs). Re-run `run` to fold beacondb_location into devices.")
    return 0

# ---- noise rules (flag, never drop; thresholds are flags) ----

def _payload(rec):
    return any(rec.get(k) for k in ("ssid_or_name", "manufacturer", "services", "service_data", "information_elements"))


def has_payload(s):
    """Does this sighting carry anything identifying (a name, BLE advert payload, or a Kismet device classification)?"""
    if s["name"]:
        return True
    if s["source_format"] == "kismet_db":               # a Kismet device record is a classified observation, not a bare MAC
        return True
    if s["source_format"].startswith("swivel"):
        try:
            return _payload(json.loads(s["raw"]))
        except ValueError:
            return False
    return False


def sighting_key(s):
    """The identity of one observation: same device, time, signal and payload. Two rows with this key are the SAME
    sighting read twice -- a double EXPORT, or (the common case) the app's per-day file re-pulled after it grew with
    later drives. The raw sightings table keeps every such row; devices roll up from unique keys only (see derive), so
    a re-read can never inflate a device's counts. Works on both a collected dict and a sqlite3.Row (both index by name)."""
    return (s["address"], s["radio"], s["ts_raw"], s["rssi"], s["name"], s["security_raw"], s["ie_raw"], s["raw"])


def annotate_noise(sightings, min_sightings):
    """Set noise_reason on sightings the ingest pass left clean. Never overrides a malformed flag. Thresholds are
    flags: a device with <= min_sightings sightings and no payload on any of them is flagged single_sighting_no_payload."""
    for s in sightings:
        if s["noise_reason"] is None and s["address"] and is_noise_address(s["address"]):
            s["noise_reason"] = "zero_or_broadcast_address"
    seen = set()                                          # exact-duplicate: identical device+time+signal+payload
    for s in sightings:
        if s["noise_reason"] is not None:
            continue
        key = sighting_key(s)
        if key in seen:
            s["noise_reason"] = "duplicate_sighting"
        else:
            seen.add(key)
    groups = collections.defaultdict(list)
    for s in sightings:
        if s["address"] and s["radio"]:
            groups[(s["address"], s["radio"])].append(s)
    for rows in groups.values():
        if len(rows) <= min_sightings and not any(has_payload(s) for s in rows):
            for s in rows:
                if s["noise_reason"] is None:
                    s["noise_reason"] = "single_sighting_no_payload"
    return sightings


def device_row(addr, radio, rows, reg, ble_rows, before, nearest_alpr, loc):
    d = dict.fromkeys(DEVICE_COLS)
    d["address"], d["radio"] = addr, radio
    recs = [json.loads(r["raw"]) if r["source_format"].startswith("swivel") else {} for r in rows]
    laa, also_ble = laa_bit(addr), radio == "bt-classic" and bool(ble_rows)

    types = collections.Counter(r["address_type"] for r in rows if r["address_type"])
    if types:
        before["is_randomized"] += 1
    if radio == "wifi":                                  # the bit is the fact; the app's label stays in sightings
        d["address_type"], d["address_type_source"], d["address_type_confidence"] = (
            "local" if laa else "public", "laa_bit", "high")
    elif types:
        d["address_type"] = types.most_common(1)[0][0]
        d["address_type_source"] = "swivel_app_top_bit_guess" if radio == "ble" else "swivel_app_laa_bit_on_bredr"
        d["address_type_confidence"] = "low"

    if radio == "wifi":
        rnd = (int(laa), "laa_bit", "high")
    elif radio == "ble":
        rnd = ble_view(rows)
    elif also_ble:
        v, src, conf = ble_view(ble_rows)
        rnd = (v, src and "ble_sightings:" + src, conf)
    elif laa:
        rnd = (None, "laa_bit_set_on_bredr_address", None)
    else:
        rnd = (0, "bredr_address_public_by_spec", "med")
    d["is_randomized"], d["is_randomized_source"], d["is_randomized_confidence"] = rnd

    # R3: BLE never (strict until the app logs real address type); LAA never; Classic also seen as BLE never.
    # A zero/broadcast address is not a real assignment (it resolves to a registry owner), so never vendor it either.
    if any(rec.get("vendor") for rec in recs):
        before["oui_vendor"] += 1
    withheld = ("withheld:zero_or_broadcast_address" if is_noise_address(addr)
                else "withheld:ble_strict" if radio == "ble" else "withheld:laa_bit" if laa
                else "withheld:classic_also_seen_as_ble" if also_ble else None)
    if withheld:
        d["oui_vendor_source"] = withheld
    else:
        h = addr.replace(":", "")
        name, src = reg.vendor(h)
        d["oui_vendor"], d["oui_vendor_source"] = name, src or "no_registry_match"
        d["oui_vendor_confidence"] = ("high" if radio == "wifi" else "med") if name else None
        dtype = reg.device_type_for(h)                   # coarse OUI-level category; same hard-rule gate as vendor (else-only)
        if dtype:
            d["oui_device_type"], d["oui_device_type_source"], d["oui_device_type_confidence"] = dtype, "ringmast4r_oui_db", "low"

    if radio in ("ble", "bt-classic"):
        ids = collections.Counter(c for rec in recs for c in company_ids(rec.get("manufacturer")))
        if ids:
            order = [c for c, _ in ids.most_common()]
            d["advertised_company_id"] = ",".join(f"0x{c:04X}" for c in order)    # every ID seen, most common first
            named = [c for c in order if c in reg.company]
            if named:
                d["advertised_company"] = reg.company[named[0]]
                d["advertised_company_source"] = "bluetooth_sig_company_identifiers" + (
                    "+unassigned_in_sig_list" if len(named) < len(order) else "")
                d["advertised_company_confidence"] = ("high" if len(order) == 1
                                                      else "med" if named[0] == order[0] else "low")
            else:
                d["advertised_company_source"] = "unassigned_in_sig_list"   # flagged, never named

    names = collections.Counter(r["name"] for r in rows if r["name"])
    if names:
        before["device_name"] += 1
        d["device_name"], d["device_name_confidence"] = top(names)
        d["device_name_source"] = NAME_SOURCE.get(radio, radio)

    if radio in ("ble", "bt-classic"):
        dc, trk, ttype, tsrc, tconf = classify(recs, reg.signatures)
        if dc:                                           # device_class/fingerprint are tool-derived: no input "before"
            d["device_class"], d["device_class_source"], d["device_class_confidence"] = dc, tsrc, tconf
            d["is_tracker"], d["tracker_type"], d["tracker_signature_source"], d["tracker_confidence"] = trk, ttype, tsrc, tconf
        at = set()
        for rec in recs:
            at |= apple_tlv_types(rec)
        if at:                                           # Apple Continuity message types; keys on the advert, not the MAC (works on randomized); R8: device, not person
            d["apple_continuity_type"] = json.dumps(sorted(APPLE_CONTINUITY_TYPES.get(t, f"0x{t:02X}") for t in at), ensure_ascii=False)
            d["apple_continuity_type_source"], d["apple_continuity_type_confidence"] = "apple_continuity_tlv", "med"
        svcs = sorted({reg.service_names.get(u, f"0x{u:04X}") for rec in recs for u in uuid16s(rec)})
        if svcs:                                         # SIG service UUIDs the device advertises; keys on the advert (randomized-safe), R8
            d["advertised_services"] = json.dumps(svcs, ensure_ascii=False)
            d["advertised_services_source"], d["advertised_services_confidence"] = "bluetooth_sig_service_uuids", "high"
        if not d["device_class"]:                        # GAP Appearance -> coarse class, only when a signature didn't already set one
            appv = next((a for a in (appearance_value(rec) for rec in recs) if a is not None), None)
            name = reg.appearance.get(appv >> 6) if appv is not None else None
            if name and name != "Unknown":
                d["device_class"], d["device_class_source"], d["device_class_confidence"] = name, "bluetooth_sig_gap_appearance", "med"
        if not d["device_class"]:                        # Class-of-Device major -> coarse class (BT-Classic), last offline fallback
            cod = next((c for c in (class_of_device_value(rec) for rec in recs) if c is not None), None)
            major = (cod >> 8) & 0x1F if cod is not None else None
            name = reg.cod.get(major) if major not in (None, 0, 31) else None   # 0=Miscellaneous / 31=Uncategorized carry no class
            if name:
                d["device_class"], d["device_class_source"], d["device_class_confidence"] = name, "bluetooth_sig_class_of_device", "med"

    if radio == "wifi":
        wifi_security(d, rows, recs, before)
        fps = collections.Counter(fp for fp in (wifi_fingerprint(r["ie_raw"]) for r in rows) if fp)
        if fps:
            d["fingerprint_hash"] = fps.most_common(1)[0][0]
            d["fingerprint_hash_source"] = "wifi_ie_id_and_vendor_oui"
            d["fingerprint_hash_confidence"] = "med" if len(fps) == 1 else "low"
        if addr in reg.wigle:                            # stage 6: WiGLE's own location for this AP (approx, hence med)
            w = reg.wigle[addr]
            wloc = {"lat": round(w["lat"], 6), "lon": round(w["lon"], 6)}
            if w.get("ssid"):
                wloc["ssid"] = w["ssid"]
            d["wigle_location"] = json.dumps(wloc, ensure_ascii=False)
            d["wigle_location_source"], d["wigle_location_confidence"] = "wigle_api", "med"
        if addr in reg.beacondb:                         # beaconDB's own location for this AP (free/keyless WiGLE alternative)
            b = reg.beacondb[addr]
            d["beacondb_location"] = json.dumps({"lat": round(b["lat"], 6), "lon": round(b["lon"], 6)}, ensure_ascii=False)
            d["beacondb_location_source"], d["beacondb_location_confidence"] = "beacondb_api", "med"

    stamped = sorted((r["ts_utc"], r["ts_tz"]) for r in rows if r["ts_utc"])
    if any(r["ts_raw"] for r in rows):
        before["first_seen"] += 1
    if stamped:
        for col, (ts, how) in (("first_seen", stamped[0]), ("last_seen", stamped[-1])):
            d[col], d[col + "_source"] = ts, "timestamp_with_offset" if how == "offset" else how
            d[col + "_confidence"] = TS_CONFIDENCE.get(how, "med")
    rssi = [r["rssi"] for r in rows if r["rssi"] is not None]
    d["sighting_count"] = len(rows)
    d["sessions_seen"] = len({r["session_id"] for r in rows})
    if rssi:
        d["rssi_max"], d["rssi_median"] = max(rssi), statistics.median(rssi)

    cluster_m, follow_m, follow_s, window = loc
    cross_check(d, rows, window)

    ip_hits = []                                         # layer-3 IPv4 (never from passive RF): app subnet-sweep / own-network, or Kismet sniffed client ipdata
    for rec in recs:                                     # swivel SWEEP/SELF observations carry a dotted IPv4 in "ip"
        ipv = rec.get("ip")
        if isinstance(ipv, str) and ipv:
            ip_hits.append((ipv, "swivel_self" if str(rec.get("kind") or "").strip().upper() == "SELF" else "swivel_sweep"))
    for r in rows:                                       # Kismet synthetic client sightings carry observed_ip in raw
        if r["source_format"] == "kismet_db":
            try:
                kr = json.loads(r["raw"])
            except (ValueError, TypeError):
                kr = {}
            if kr.get("observed_ip"):
                ip_hits.append((kr["observed_ip"], kr.get("observed_ip_source", "kismet")))
    if ip_hits:                                          # one IP per device: prefer the most reliable provenance
        rank = {"kismet_dhcp": 5, "kismet_arp": 5, "swivel_self": 5, "swivel_sweep": 4, "kismet_udptcp": 3, "kismet_factoryguess": 1}
        ip, src = max(ip_hits, key=lambda t: rank.get(t[1], 2))
        rk = rank.get(src, 2)
        d["observed_ip"], d["observed_ip_source"] = ip, src
        d["observed_ip_confidence"] = "high" if rk >= 4 else "med" if rk >= 3 else "low"

    located = [r for r in rows if r["lat"] is not None and r["lon"] is not None]
    if not located:
        d["location_clusters_source"] = d["followed_flag_source"] = d["near_alpr_source"] = "no_location"
        return d
    clusters = cluster_points([(r["lat"], r["lon"]) for r in located], cluster_m)
    centroids = [(la, lo) for _, la, lo in clusters]
    d["location_clusters"] = json.dumps([{"lat": round(la, 6), "lon": round(lo, 6), "n": n} for n, la, lo in clusters])
    d["location_clusters_source"], d["location_clusters_confidence"] = f"greedy_{cluster_m:.0f}m", "med"
    # followed_flag: the SAME address at >=2 clusters > follow_m apart spanning > follow_s. A coarse candidate signal only
    # (it needs a persistent MAC; randomization hides a real tail). Describes the device's appearances, not a person (R8).
    # span is measured over the LOCATED sightings only, so a GPS-less sighting can't inflate the time span.
    tss = sorted(r["ts_utc"] for r in located if r["ts_utc"])
    span = ((dt.datetime.fromisoformat(tss[-1].replace("Z", "+00:00"))
             - dt.datetime.fromisoformat(tss[0].replace("Z", "+00:00"))).total_seconds()) if len(tss) >= 2 else 0.0
    maxsep = max((haversine_m(a, b) for i, a in enumerate(centroids) for b in centroids[i + 1:]), default=0.0)
    d["followed_flag"] = int(len(clusters) >= 2 and maxsep > follow_m and span > follow_s)
    d["followed_flag_source"] = f">=2_clusters_>{follow_m:.0f}m_apart_>{follow_s:.0f}s"
    d["followed_flag_confidence"] = "low"
    nd = min((v for v in (nearest_alpr(cen) for cen in centroids) if v is not None), default=None)
    if nd is not None:
        d["near_alpr"], d["near_alpr_source"], d["near_alpr_confidence"] = round(nd), "osm_alpr_nearest", "med"
    else:
        d["near_alpr_source"] = "no_alpr_dataset"
    return d


def wifi_security(d, rows, recs, before):
    """Union of every security mode and every WPS identity seen across sightings: never one value kept and the
    rest dropped. Several WPS identities on one BSSID stay visible as a set."""
    modes, srcs = set(), set()
    wps, wps_src, wps_vals = None, None, collections.defaultdict(set)
    had_security_text = False
    per_sighting = []                                    # each sighting's own mode set, for security_conflict
    for r, rec in zip(rows, recs):
        caps = txt(rec.get("security")) if r["source_format"].startswith("swivel") else r["security_raw"]
        had_security_text = had_security_text or bool(caps or r["security_raw"])
        ies = parse_ies(r["ie_raw"])
        bodies = [(b, False) for i, b in ies if i == 48] + [(b[4:], True) for i, b in ies if i == 221 and b[:4] == WPA_OUI_TYPE]
        smodes, got = set(), False
        for body, is_wpa in bodies:
            m, _, _ = parse_rsn(body, is_wpa)
            if m:
                smodes |= m
                srcs.add("wpa_ie" if is_wpa else "rsn_ie")
                got = True
        if bodies and not got:
            srcs.add("rsn_ie_unreadable")
        if not got and caps:
            m, _, _ = parse_caps(caps)
            smodes |= m
            if m:
                srcs.add("capabilities_string")
        modes |= smodes
        if smodes:
            per_sighting.append(frozenset(smodes))
        wps_body = b"".join(b[4:] for i, b in ies if i == 221 and b[:4] == WPS_OUI_TYPE)   # WPS may span elements
        if wps_body:
            wps, wps_src = 1, "wps_ie"
            w = parse_wps(wps_body)
            for k in ("make", "serial"):
                if k in w:
                    wps_vals[k].add(w[k])
            name, number = w.get("model_name"), w.get("model_number")
            model = f"{name} ({number})" if name and number and number not in name else name or number
            if model:
                wps_vals["model"].add(model)
        elif caps and "[WPS]" in caps and wps_src != "wps_ie":
            wps, wps_src = 1, "capabilities_string"
        elif wps is None and ies:
            wps, wps_src = 0, "wps_ie_absent"
        elif wps is None and caps:
            wps, wps_src = 0, "capabilities_string"
    before["security_modes"] += had_security_text
    if modes:
        src = "+".join(sorted(srcs))
        conf = "high" if srcs <= {"rsn_ie", "wpa_ie"} else "med"
        d["security_modes"] = json.dumps(sorted(modes))
        d["security_modes_source"], d["security_modes_confidence"] = src, conf
        # conflict when the device's own sightings disagree (e.g. OPEN once, WPA2 another time = downgrade/evil-twin signal)
        d["security_conflict"] = int(len(set(per_sighting)) > 1)
        d["security_conflict_source"] = "sighting_disagreement" if d["security_conflict"] else "consistent_across_sightings"
        d["security_conflict_confidence"] = "high"
    if wps is not None:
        d["wps_enabled"], d["wps_enabled_source"] = wps, wps_src
        d["wps_enabled_confidence"] = "high" if wps_src in ("wps_ie", "wps_ie_absent") else "med"
    for k in ("make", "model", "serial"):
        if wps_vals[k]:
            d[f"wps_{k}"] = json.dumps(sorted(wps_vals[k]))
            d[f"wps_{k}_source"], d[f"wps_{k}_confidence"] = "wps_ie", "high" if len(wps_vals[k]) == 1 else "med"


# Device-level usefulness + noise classification (stage 7). INFO_WEIGHTS/IDENTITY/HANDLE are tunable flags, not hardcoded
# magic: identity = a human-readable attribute; handle = a stable feature a later run/DB could enrich or cluster on.
INFO_WEIGHTS = {"oui_vendor": 3, "advertised_company": 3, "device_name": 3, "device_class": 3, "apple_continuity_type": 3,
                "oui_device_type": 2, "advertised_company_id": 2, "advertised_services": 2, "wigle_location": 2,
                "beacondb_location": 2, "security_modes": 2, "wps_make": 2, "wps_model": 2, "wps_serial": 2,
                "observed_ip": 2, "probed_ssids": 1, "fingerprint_hash": 1, "kismet_ids_alerts": 1}
IDENTITY = ("oui_vendor", "oui_device_type", "advertised_company", "device_name", "device_class", "apple_continuity_type",
            "advertised_services", "observed_ip")
HANDLE = ("probed_ssids", "fingerprint_hash", "advertised_company_id")


def score_and_reason(d):
    """info_score = weighted count of useful fields present (+ tracker / followed / Kismet-co-present signal). noise_reason
    classes a thin row: None = readable identity (keep); 'thin_but_tracked' = no identity but a behavioural signal worth
    keeping (followed across locations, co-present with Kismet, or a Kismet IDS alert -- the whole point of the tool);
    'thin_has_handle' = a feature a later run/DB can enrich or cluster on (keep); 'thin_real_oui' = no identity but a real
    (non-randomized) MAC a better OUI/geo DB can still fill (keep); 'dead_random_no_handle' = randomized MAC with no
    identity, no handle and no signal -> nothing can ever enrich, cluster or make it interesting. Only the last is dropped."""
    filled = lambda k: d.get(k) not in (None, "")
    score = (sum(w for k, w in INFO_WEIGHTS.items() if filled(k))
             + (3 if d.get("is_tracker") else 0) + (2 if d.get("followed_flag") == 1 else 0)
             + (1 if d.get("seen_by_both_within_window") == 1 else 0))
    has_identity = any(filled(k) for k in IDENTITY) or bool(d.get("is_tracker"))
    behavioural = d.get("followed_flag") == 1 or d.get("seen_by_both_within_window") == 1 or filled("kismet_ids_alerts")
    has_handle = any(filled(k) for k in HANDLE)
    is_rand = bool(d.get("is_randomized")) or laa_bit(d["address"])
    reason = (None if has_identity else "thin_but_tracked" if behavioural else "thin_has_handle" if has_handle
              else "thin_real_oui" if not is_rand else "dead_random_no_handle")
    return score, reason


def derive(conn, reg, cluster_distance=50.0, follow_distance=200.0, follow_min_span=300.0, kismet_window=60.0):
    """Rebuild devices from sightings (sightings itself is never touched). Returns ('filled before' counts,
    re-read sightings skipped). A device rolls up from UNIQUE sighting keys only, so re-ingesting an overlapping
    capture (append-growth, double EXPORT) does not inflate its counts; the raw sightings table still holds every row."""
    conn.execute("DELETE FROM devices")
    groups = collections.defaultdict(list)
    seen, dup_skipped = set(), 0                          # ORDER BY id => the earliest-ingested copy of a re-read sighting wins
    for r in conn.execute("SELECT * FROM sightings WHERE address IS NOT NULL AND radio IS NOT NULL ORDER BY id"):
        k = sighting_key(r)
        if k in seen:
            dup_skipped += 1
            continue
        seen.add(k)
        groups[(r["address"], r["radio"])].append(r)
    cache = {}                                           # nearest-camera distance, memoised per ~11 m centroid grid cell
    def nearest_alpr(cen):
        if not reg.alpr:
            return None
        key = (round(cen[0], 4), round(cen[1], 4))
        if key not in cache:
            cache[key] = min(haversine_m(cen, cam) for cam in reg.alpr)
        return cache[key]
    loc = (cluster_distance, follow_distance, follow_min_span, kismet_window)
    before = collections.Counter()
    for (addr, radio), rows in groups.items():
        d = device_row(addr, radio, rows, reg, groups.get((addr, "ble"), []), before, nearest_alpr, loc)
        d["info_score"], d["noise_reason"] = score_and_reason(d)
        conn.execute(f"INSERT INTO devices ({','.join(DEVICE_COLS)}) VALUES ({','.join('?' * len(DEVICE_COLS))})",
                     [d[c] for c in DEVICE_COLS])
    cluster_devices(conn)                                # stage 7: link rotating random Wi-Fi client MACs -> device_cluster_id
    return before, dup_skipped


def cluster_devices(conn):
    """Link rotating randomized Wi-Fi CLIENT MACs that are one physical device: identical 802.11 IE fingerprint AND an
    overlapping probe list (PNL Jaccard >= 0.5) (Vanhoef, AsiaCCS'16; validated against the Pintor/Atzori CC-BY labelled
    set). Offline and client-only: APs don't randomize and BLE/Classic use other mechanisms, so they never cluster here.
    Low confidence by nature -- identical models share an IE fingerprint, and modern iOS (16.1+) randomizes the sequence
    number and IE tokens, so a shared probe list is the only feature that reliably separates two random MACs; a probe list
    is therefore REQUIRED to merge. device_cluster_id is set only on members of a >=2 group (an actual link), never on a
    lone device, and never joined to a person (R8)."""
    rows = conn.execute("SELECT address, fingerprint_hash, probed_ssids FROM devices "
                        "WHERE radio='wifi' AND is_randomized=1 AND fingerprint_hash IS NOT NULL "
                        "AND probed_ssids IS NOT NULL").fetchall()
    by_fp = collections.defaultdict(dict)                # IE fingerprint -> {address: set(probed SSIDs)}
    for r in rows:
        try:
            pnl = set(json.loads(r["probed_ssids"]))
        except (ValueError, TypeError):
            continue
        if pnl:
            by_fp[r["fingerprint_hash"]][r["address"]] = pnl
    for fp, pnls in by_fp.items():
        addrs = list(pnls)
        parent = {a: a for a in addrs}
        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        for i, a in enumerate(addrs):                    # union two MACs whose probe lists overlap by Jaccard >= 0.5
            for b in addrs[i + 1:]:
                if len(pnls[a] & pnls[b]) / len(pnls[a] | pnls[b]) >= 0.5:
                    parent[find(a)] = find(b)
        comp = collections.defaultdict(list)
        for a in addrs:
            comp[find(a)].append(a)
        for group in comp.values():
            if len(group) >= 2:                          # >=2 random MACs sharing model + probe list = one device
                union = sorted(set().union(*(pnls[a] for a in group)))
                cid = hashlib.sha256((fp + "|" + "|".join(union)).encode("utf-8")).hexdigest()[:12]
                for a in group:
                    conn.execute("UPDATE devices SET device_cluster_id=? WHERE radio='wifi' AND address=?", (cid, a))


SCHEMA = f"""
CREATE TABLE sightings (id INTEGER PRIMARY KEY, {', '.join(SIGHTING_COLS)});
CREATE INDEX sightings_device ON sightings(address, radio);
CREATE TRIGGER sightings_immutable_u BEFORE UPDATE ON sightings BEGIN SELECT RAISE(ABORT, 'sightings is immutable'); END;
CREATE TRIGGER sightings_immutable_d BEFORE DELETE ON sightings BEGIN SELECT RAISE(ABORT, 'sightings is immutable'); END;
CREATE TABLE devices ({', '.join(DEVICE_COLS)}, PRIMARY KEY (address, radio));
CREATE TABLE ingested_files (sha256 TEXT PRIMARY KEY, filename TEXT, n_sightings INTEGER, ingested_at TEXT);
"""


def r3_check(conn):
    """Independent of the code that withheld vendors: recompute the rule from address, radio and is_randomized."""
    ble = {a for (a,) in conn.execute("SELECT address FROM devices WHERE radio='ble'")}
    rows = conn.execute("SELECT address, radio, is_randomized FROM devices WHERE oui_vendor IS NOT NULL").fetchall()
    return {"ble_with_oui_vendor": sum(r["radio"] == "ble" for r in rows),
            "randomized_with_oui_vendor": sum(bool(r["is_randomized"]) or laa_bit(r["address"]) for r in rows),
            "classic_also_ble_with_oui_vendor": sum(r["radio"] == "bt-classic" and r["address"] in ble for r in rows)}

# ---- run ----

def system_zone():
    p = os.path.realpath("/etc/localtime")
    return p.split("zoneinfo/", 1)[1] if "zoneinfo/" in p else "UTC"


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_replace(path, write):
    """Write to path.building then rename over path: never writes into an existing file (or a hard link to one)."""
    tmp = path + ".building"
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        write(f)
    os.replace(tmp, path)


def run(paths, db, csv_path, registry_dir, naive_tz, min_sightings=1,
        cluster_distance=50.0, follow_distance=200.0, follow_min_span=300.0, kismet_window=60.0,
        keep_noise=True, fresh=True):
    """Build or EXTEND the DB, devices CSV, cluster GeoJSON and summary file; return the summary dict (counts only).
    Accumulates when fresh is False: if the DB already exists, the given capture files are APPENDED (skipping any already
    ingested, by content hash) and devices is rebuilt from the whole accumulated sightings table. fresh defaults True here
    so a library/test call rebuilds from only the files given; the CLI `run` passes fresh False, so pressing run accumulates.
    Randomized devices with no handle to ever enrich or cluster (noise_reason 'dead_random_no_handle') are dropped from the
    output when keep_noise is False. The CLI `run` passes keep_noise False (so pressing run drops them); this function
    keeps them by default so a library/test caller is never surprised. The raw sightings keep every row, so it reverses."""
    ZoneInfo(naive_tz)                                   # fail early on a bad zone name
    summary_path = os.path.splitext(db)[0] + "_summary.txt"
    geojson_path = os.path.splitext(db)[0] + "_clusters.geojson"
    for out in (db, csv_path, summary_path, geojson_path):
        for p in paths:
            for o in (out, out + ".building"):
                if os.path.realpath(o) == os.path.realpath(p) or (os.path.exists(o) and os.path.samefile(o, p)):
                    sys.exit(f"refusing to write {os.path.basename(o)}: it is one of the inputs (raw captures are never overwritten)")
    reg = Registry(registry_dir)
    os.makedirs(os.path.dirname(os.path.abspath(db)), exist_ok=True)
    tmp = db + ".building"
    if os.path.exists(tmp):
        os.remove(tmp)
    accumulate = os.path.exists(db) and not fresh
    if accumulate:
        shutil.copyfile(db, tmp)                         # extend a COPY, then atomically replace: a crash leaves the old DB intact
    conn = sqlite3.connect(tmp)
    conn.row_factory = sqlite3.Row
    if not accumulate:
        conn.executescript(SCHEMA)
    else:                                                # migrate a DB from an earlier version: add any stage-7 table/columns
        conn.execute("CREATE TABLE IF NOT EXISTS ingested_files (sha256 TEXT PRIMARY KEY, filename TEXT, n_sightings INTEGER, ingested_at TEXT)")
        have_cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)")}
        for col in DEVICE_COLS:
            if col not in have_cols:
                conn.execute(f"ALTER TABLE devices ADD COLUMN {col}")
    already = {h for (h,) in conn.execute("SELECT sha256 FROM ingested_files")}
    seen, inputs, dupes, hashes = set(already), [], [], {}
    for p in paths:                                      # skip files ingested on an earlier run, and the same file passed twice
        h = file_sha256(p); hashes[p] = h
        (dupes if h in seen else inputs).append(p)
        seen.add(h)
    per_file, collected = [], []                         # collect, run the noise passes, then insert the new sightings immutably
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for p in inputs:
        rows = list(sightings_from(p, naive_tz))
        per_file.append((os.path.basename(p), len(rows)))
        collected.extend(rows)
        conn.execute("INSERT INTO ingested_files VALUES (?,?,?,?)", (hashes[p], os.path.basename(p), len(rows), now))
    annotate_noise(collected, min_sightings)
    conn.executemany(f"INSERT INTO sightings ({','.join(SIGHTING_COLS)}) VALUES ({','.join('?' * len(SIGHTING_COLS))})",
                     [[s[c] for c in SIGHTING_COLS] for s in collected])
    before, dup_skipped = derive(conn, reg, cluster_distance, follow_distance, follow_min_span, kismet_window)
    conn.commit()
    device_noise = dict(conn.execute("SELECT coalesce(noise_reason,'(kept: has identity)'), count(*) FROM devices GROUP BY 1 ORDER BY 2 DESC"))
    dead_n = conn.execute("SELECT count(*) FROM devices WHERE noise_reason='dead_random_no_handle'").fetchone()[0]
    if not keep_noise and dead_n:
        conn.execute("DELETE FROM devices WHERE noise_reason='dead_random_no_handle'")   # raw sightings keep every row; reversible with --keep-noise
        conn.commit()
    summary = summarize(conn, per_file, [os.path.basename(p) for p in dupes], before, reg, naive_tz)
    summary["duplicate_sightings_skipped"] = dup_skipped
    summary["device_noise"] = device_noise
    summary["dropped_dead"] = 0 if keep_noise else dead_n
    summary["kept_noise"] = keep_noise
    summary["accumulated"] = {"mode": "accumulate" if accumulate else "fresh",
                              "files_in_db": conn.execute("SELECT count(*) FROM ingested_files").fetchone()[0],
                              "sightings_in_db": conn.execute("SELECT count(*) FROM sightings").fetchone()[0]}
    rows = conn.execute(f"SELECT {','.join(DEVICE_COLS)} FROM devices ORDER BY radio, address").fetchall()
    conn.close()
    def write_csv(f):
        w = csv.writer(f)
        w.writerow(DEVICE_COLS)
        w.writerows(rows)
    write_replace(csv_path, write_csv)
    write_replace(geojson_path, lambda f: json.dump(clusters_geojson(rows), f))
    os.replace(tmp, db)
    write_replace(summary_path, lambda f: f.write(format_summary(summary) + "\n"))
    summary["files"] = (db, csv_path, geojson_path, summary_path)
    return summary


def clusters_geojson(rows):
    """One Point feature per device location cluster (GeoJSON is [lon, lat]). A local map layer for QGIS/offline maps;
    like the devices CSV it holds coordinates, so both are git-ignored and never printed."""
    feats = []
    for r in rows:
        if not r["location_clusters"]:
            continue
        for c in json.loads(r["location_clusters"]):
            feats.append({"type": "Feature", "geometry": {"type": "Point", "coordinates": [c["lon"], c["lat"]]},
                          "properties": {"address": r["address"], "radio": r["radio"], "sightings_here": c["n"],
                                         "device_class": r["device_class"], "is_tracker": r["is_tracker"],
                                         "tracker_type": r["tracker_type"], "followed_flag": r["followed_flag"],
                                         "near_alpr_m": r["near_alpr"]}})
    return {"type": "FeatureCollection", "features": feats}


FILL_FIELDS = ["is_randomized", "oui_vendor", "advertised_company", "device_name", "device_class",
               "fingerprint_hash", "security_modes", "wps_make", "wps_model", "wps_serial", "first_seen",
               "location_clusters"]


def summarize(conn, per_file, dupes, before, reg, naive_tz):
    q = lambda sql: conn.execute(sql).fetchall()
    q1 = lambda sql: conn.execute(sql).fetchone()[0]
    return {
        "registry": {"ieee_entries": len(reg.ieee), "manuf_entries": len(reg.manuf), "sig_company_ids": len(reg.company)},
        "inputs": per_file,
        "duplicate_inputs_skipped": dupes,
        "sightings_by_radio": dict(q("SELECT coalesce(radio,'(none)'), count(*) FROM sightings GROUP BY 1 ORDER BY 1")),
        "timestamps": dict(q("SELECT coalesce(ts_tz,'unparseable'), count(*) FROM sightings GROUP BY 1 ORDER BY 1")),
        "noise_reason": dict(q("SELECT coalesce(noise_reason,'(clean)'), count(*) FROM sightings GROUP BY 1 ORDER BY 1")),
        "devices_by_radio": dict(q("SELECT radio, count(*) FROM devices GROUP BY 1 ORDER BY 1")),
        "devices": q("SELECT count(*) FROM devices")[0][0],
        "filled": {f: (before.get(f, 0), q(f"SELECT count(*) FROM devices WHERE {f} IS NOT NULL")[0][0]) for f in FILL_FIELDS},
        "oui_vendor_source": dict(q("SELECT oui_vendor_source, count(*) FROM devices GROUP BY 1 ORDER BY 2 DESC")),
        "advertised_company_source": dict(q("SELECT coalesce(advertised_company_source,'(none)'), count(*) FROM devices "
                                            "WHERE radio != 'wifi' GROUP BY 1 ORDER BY 2 DESC")),
        "trackers_by_type": dict(q("SELECT tracker_type, count(*) FROM devices WHERE is_tracker=1 GROUP BY 1 ORDER BY 2 DESC")),
        "tracker_confidence": dict(q("SELECT tracker_confidence, count(*) FROM devices WHERE is_tracker=1 GROUP BY 1 ORDER BY 1")),
        "security_conflict": dict(q("SELECT coalesce(security_conflict,'(no security)'), count(*) FROM devices "
                                    "WHERE radio='wifi' GROUP BY 1 ORDER BY 1")),
        "seen_by": {"phone": q1("SELECT count(*) FROM devices WHERE seen_by_phone=1"),
                    "kismet": q1("SELECT count(*) FROM devices WHERE seen_by_kismet=1"),
                    "both": q1("SELECT count(*) FROM devices WHERE seen_by_phone=1 AND seen_by_kismet=1")},
        "both_within_window": dict(q("SELECT coalesce(seen_by_both_within_window,'(n/a)'), count(*) FROM devices GROUP BY 1 ORDER BY 1")),
        "ids_alert_devices": q1("SELECT count(*) FROM devices WHERE kismet_ids_alerts IS NOT NULL"),
        "followed_flag": dict(q("SELECT coalesce(followed_flag,'(no location)'), count(*) FROM devices GROUP BY 1 ORDER BY 1")),
        "near_alpr_source": dict(q("SELECT near_alpr_source, count(*) FROM devices GROUP BY 1 ORDER BY 2 DESC")),
        "near_alpr_buckets": dict(q("SELECT CASE WHEN near_alpr IS NULL THEN '(none)' WHEN near_alpr<100 THEN '<100m' "
                                    "WHEN near_alpr<500 THEN '100-500m' WHEN near_alpr<2000 THEN '0.5-2km' ELSE '>2km' END, "
                                    "count(*) FROM devices GROUP BY 1 ORDER BY coalesce(min(near_alpr), 1e18)")),
        "wigle_located": q1("SELECT count(*) FROM devices WHERE wigle_location IS NOT NULL"),
        "new_enrichment": {c: q1(f"SELECT count(*) FROM devices WHERE {c} IS NOT NULL") for c in
                           ("probed_ssids", "oui_device_type", "apple_continuity_type", "beacondb_location", "observed_ip")},
        "r3": r3_check(conn),
        "naive_tz": naive_tz,
    }


def format_summary(s):
    out = [f"SWIVEL log-enhancer run  {dt.datetime.now(dt.timezone.utc):%Y-%m-%dT%H:%M:%SZ}",
           f"registries: IEEE {s['registry']['ieee_entries']:,} · Wireshark manuf {s['registry']['manuf_entries']:,} · "
           f"SIG company IDs {s['registry']['sig_company_ids']:,}", "inputs (rows read -> sightings):"]
    out += [f"  {name}  {n:,}" for name, n in s["inputs"]]
    if s["duplicate_inputs_skipped"]:
        out.append(f"  skipped (same content as an earlier input): {', '.join(s['duplicate_inputs_skipped'])}")
    total = sum(n for _, n in s["inputs"])
    out += [f"sightings: {total:,}  by radio {s['sightings_by_radio']}",
            f"timestamps: {s['timestamps']}  (naive SWIVEL times read as {s['naive_tz']}; Kismet WigleCSV is UTC)",
            f"noise_reason (flagged, never dropped): {s['noise_reason']}",
            f"devices: {s['devices']:,}  by radio {s['devices_by_radio']}",
            "fields filled (devices; before = present in the input's own fields, after = this DB):"]
    out += [f"  {f:20s} {b:6,} -> {a:6,}" for f, (b, a) in s["filled"].items()]
    out += [f"oui_vendor by source: {s['oui_vendor_source']}",
            f"advertised_company by source (BLE + Classic): {s['advertised_company_source']}",
            f"trackers (is_tracker=1) by type: {s['trackers_by_type'] or '(none)'}  confidence {s['tracker_confidence'] or '{}'}",
            f"security_conflict (Wi-Fi: 1=sightings disagree, 0=consistent): {s['security_conflict']}",
            f"cross-check: seen_by_phone {s['seen_by']['phone']}, seen_by_kismet {s['seen_by']['kismet']}, "
            f"both {s['seen_by']['both']} (co-present within window: {s['both_within_window']}); "
            f"devices with Kismet IDS alerts {s['ids_alert_devices']}",
            f"followed_flag (coarse: same MAC at >=2 far clusters over time; 0=no): {s['followed_flag']}",
            f"near_alpr by source: {s['near_alpr_source']}  nearest-camera distance: {s['near_alpr_buckets']}",
            f"wigle_location (WiGLE AP geolocation): {s['wigle_located']} device(s) matched"]
    out.append(f"new enrichment (devices filled): {s['new_enrichment']}")
    if "accumulated" in s:
        out.append(f"accumulated DB: {s['accumulated']}")
    if "device_noise" in s:
        out.append(f"device noise (before drop): {s['device_noise']}")
        out.append((f"dead rows KEPT in output (--keep-noise): {s['device_noise'].get('dead_random_no_handle', 0)}"
                    if s.get("kept_noise") else
                    f"dropped as dead (randomized + no enrich/cluster handle; not in output, raw kept): {s['dropped_dead']}"))
    if s.get("duplicate_sightings_skipped"):
        out.append(f"re-read sightings collapsed in devices (raw log keeps every row): {s['duplicate_sightings_skipped']:,}")
    bad = sum(s["r3"].values())
    out.append(f"R3 check: {s['r3']}  ->  {'PASS' if not bad else 'FAIL'}")
    return "\n".join(out)


# ---- static high-value-device report (offline HTML; ranked by info_score, valuable columns, no coordinates) ----
# The main table's columns, in order: (field_or_computed, header). Computed ones are built in build_report_html.
REPORT_MAIN = [("info_score", "★"), ("radio", "radio"), ("address", "address"), ("oui_vendor", "vendor"),
               ("oui_device_type", "type"), ("device_name", "name"), ("device_class", "class"), ("observed_ip", "IP"),
               ("@tracker", "tracker"), ("@signals", "signals"), ("@located", "located"),
               ("sighting_count", "sight"), ("sessions_seen", "sess"), ("rssi_median", "rssi"), ("last_seen", "last seen")]
# Why each column group is worth having — shown in the report's legend (answers "why is this column needed").
REPORT_WHY = [
    ("Score", "`info_score` ranks a device by how much usable info it carries (vendor/name/class/continuity=3, "
     "type/services/IP/geo/WPS=2, probes/fingerprint/alerts=1). Sort by it — the richest devices float to the top."),
    ("Identity", "`oui_vendor` (hardware maker, withheld on randomized MACs — R3), `oui_device_type` (coarse category), "
     "`device_name`, `device_class` (signature → BLE Appearance → Classic Class-of-Device), `advertised_company` / "
     "`advertised_services` / `apple_continuity_type` (what the BLE advert claims — works on randomized MACs)."),
    ("Network", "`observed_ip` (layer-3, from the app sweep or Kismet — never from passive RF), `security_modes` / "
     "`wps_*` (Wi-Fi AP security + the make/model/serial WPS leaks), `probed_ssids` (the networks a client hunts for — "
     "a near-unique fingerprint)."),
    ("Surveillance signal", "`is_tracker`/`tracker_type` (Find My, Tile…), `followed_flag` (same MAC at ≥2 far places "
     "over time — coarse), `security_conflict` (an AP seen both OPEN and WPA2 — evil-twin signal), `kismet_ids_alerts`, "
     "`seen_by_both_within_window` (phone + Kismet saw it together)."),
    ("Presence", "`sighting_count` / `sessions_seen` / `rssi_*` / `first_seen` / `last_seen` / `seen_by_phone` / "
     "`seen_by_kismet` — how often, how strong, how recently, by which radio."),
    ("Located", "`wigle_location` / `beacondb_location` (opt-in AP geolocation) and `location_clusters` / `near_alpr` "
     "(from the capture's own GPS). This report shows only a badge/count — **no raw coordinates are written to this "
     "file**; use Datasette or the GeoJSON for the map."),
]


def _report_cell(row, field):
    """One main-table cell as (display_text, sort_key). Computed fields start with '@'."""
    if field == "@tracker":
        return (f"{row['tracker_type']}" if row["is_tracker"] else "", row["tracker_type"] or "")
    if field == "@signals":
        s = []
        if row["followed_flag"]:
            s.append("followed")
        if row["security_conflict"]:
            s.append("evil-twin?")
        if row["kismet_ids_alerts"]:
            s.append("IDS")
        if row["seen_by_both_within_window"]:
            s.append("phone+kismet")
        return (" · ".join(s), str(len(s)))
    if field == "@located":
        s = []
        if row["wigle_location"]:
            s.append("WiGLE")
        if row["beacondb_location"]:
            s.append("beaconDB")
        if row["location_clusters"]:
            try:
                s.append(f"{len(json.loads(row['location_clusters']))} place(s)")
            except (ValueError, TypeError):
                pass
        return (" · ".join(s), str(len(s)))
    v = row[field]
    if v is None:
        return ("", "")
    return (str(v), v if isinstance(v, (int, float)) else str(v))


def build_report_html(rows, dbname, generated):
    """A single self-contained HTML page: every device ranked by info_score, valuable columns up front, a click-to-expand
    per-device detail with each field's source+confidence, a legend, and client-side search / min-score filter / sort.
    Shows device detail (this is a local out/ artifact like the CSV) but writes NO raw coordinates."""
    esc = html.escape
    base_fields = [c for c in DEVICE_COLS if not c.endswith("_source") and not c.endswith("_confidence")]
    body = []
    for i, row in enumerate(rows):
        score = row["info_score"] if row["info_score"] is not None else 0
        tds, keys = [], []
        for field, _ in REPORT_MAIN:
            text, sort = _report_cell(row, field)
            keys.append(sort)
            cls = ' class="mono"' if field in ("address", "observed_ip") else ""
            tds.append(f'<td{cls} data-sort="{esc(str(sort))}">{esc(text)}</td>')
        # detail: every filled field with its provenance
        det = []
        for c in base_fields:
            v = row[c]
            if v is None or v == "" or c in ("address", "radio"):
                continue
            if c in ("location_clusters", "wigle_location", "beacondb_location"):   # R1: never write raw coordinates — summarize
                if c == "location_clusters":
                    try:
                        v = f"{len(json.loads(v))} cluster(s) [coords omitted — see Datasette/GeoJSON]"
                    except (ValueError, TypeError):
                        v = "present [coords omitted]"
                else:
                    v = "located [coords omitted]"
            src = row[c + "_source"] if (c + "_source") in row.keys() else None
            conf = row[c + "_confidence"] if (c + "_confidence") in row.keys() else None
            prov = f' <span class="prov">({esc(str(src))}{", " + esc(str(conf)) if conf else ""})</span>' if src else ""
            det.append(f'<div><span class="k">{esc(c)}</span> {esc(str(v))}{prov}</div>')
        detail = "".join(det) or "<div class='prov'>no enriched fields</div>"
        body.append(
            f'<tr class="dev" data-score="{score}" onclick="t({i})">' + "".join(tds) + "</tr>"
            f'<tr id="d{i}" class="detail" hidden><td colspan="{len(REPORT_MAIN)}"><div class="grid">{detail}</div></td></tr>')
    head = "".join(f'<th onclick="sortBy({j})">{esc(h)}</th>' for j, (_, h) in enumerate(REPORT_MAIN))
    legend = "".join(f"<dt>{esc(g)}</dt><dd>{why}</dd>" for g, why in REPORT_WHY)
    return (REPORT_HEAD
            + f'<h1>DEBRIEF — high-value devices</h1><p class="sub">{esc(dbname)} · {len(rows)} devices · generated '
              f'{esc(generated)} · ranked by info_score · <b>no coordinates in this file</b></p>'
            + '<div class="bar"><input id="q" placeholder="search…" oninput="flt()">'
              '<label>min ★ <input id="ms" type="number" value="0" min="0" style="width:4em" oninput="flt()"></label>'
              '<span id="n"></span></div>'
            + '<details class="legend"><summary>what the columns mean / why they matter</summary><dl>' + legend
            + '<dt>honesty</dt><dd>every enriched value carries its own <i>source</i> and <i>confidence</i> (shown in the '
              'row detail); a blank means "not determined", never a guess. Randomized MACs never get a vendor (R3).</dd>'
              '</dl></details>'
            + f'<table id="t"><thead><tr>{head}</tr></thead><tbody>' + "".join(body) + "</tbody></table>" + REPORT_TAIL)


REPORT_HEAD = ("<!doctype html><html lang=en><head><meta charset=utf-8>"
               "<meta name=viewport content='width=device-width,initial-scale=1'><title>DEBRIEF high-value devices</title>"
               "<style>"
               ":root{color-scheme:dark}body{background:#0b0f0d;color:#cfe3d8;font:13px/1.5 ui-monospace,Menlo,Consolas,monospace;margin:0;padding:16px}"
               "h1{color:#4ade80;font-size:18px;margin:0 0 2px}.sub{color:#7a8c82;margin:0 0 12px}"
               ".bar{position:sticky;top:0;background:#0b0f0d;padding:8px 0;display:flex;gap:14px;align-items:center;flex-wrap:wrap}"
               "input{background:#121a16;border:1px solid #243;color:#cfe3d8;border-radius:6px;padding:5px 8px;font:inherit}"
               "#q{min-width:min(280px,70vw)}#n{color:#7a8c82}"
               ".legend{margin:10px 0;border:1px solid #243;border-radius:8px;padding:6px 10px}.legend summary{cursor:pointer;color:#4ade80}"
               "dl{margin:8px 0}dt{color:#4ade80;margin-top:8px}dd{margin:2px 0 0;color:#b9ccc2}"
               "table{border-collapse:collapse;width:100%;margin-top:8px}th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #1a241f;white-space:nowrap}"
               "th{position:sticky;top:52px;background:#0f1713;color:#8fb;cursor:pointer;user-select:none}th:hover{color:#4ade80}"
               "tr.dev{cursor:pointer}tr.dev:hover td{background:#121a16}.mono{font-feature-settings:'tnum'}"
               ".detail td{background:#0e1512;white-space:normal}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:4px 18px}"
               ".k{color:#4ade80}.prov{color:#6b7d73}"
               "</style></head><body>")
REPORT_TAIL = ("<script>"
               "function t(i){var d=document.getElementById('d'+i);if(d)d.hidden=!d.hidden}"
               "function flt(){var q=document.getElementById('q').value.toLowerCase(),ms=+document.getElementById('ms').value||0,n=0;"
               "document.querySelectorAll('tr.dev').forEach(function(r){var ok=(+r.dataset.score>=ms)&&r.textContent.toLowerCase().indexOf(q)>-1;"
               "r.hidden=!ok;var d=document.getElementById('d'+[].indexOf.call(r.parentNode.children,r));"
               "if(ok)n++});document.getElementById('n').textContent=n+' shown'}"
               "function sortBy(j){var tb=document.querySelector('#t tbody'),rs=[].slice.call(tb.querySelectorAll('tr.dev'));"
               "var asc=tb.dataset.sj==j&&tb.dataset.sa!='1';tb.dataset.sj=j;tb.dataset.sa=asc?'1':'0';"
               "rs.sort(function(a,b){var x=a.children[j].dataset.sort,y=b.children[j].dataset.sort;"
               "var nx=parseFloat(x),ny=parseFloat(y);if(!isNaN(nx)&&!isNaN(ny)){x=nx;y=ny}return (x<y?-1:x>y?1:0)*(asc?1:-1)});"
               "rs.forEach(function(r){var i=[].indexOf.call(r.parentNode.children,r);var d=document.getElementById('d'+(r.getAttribute('onclick').match(/\\d+/)[0]));tb.appendChild(r);if(d)tb.appendChild(d)})}"
               "flt();</script></body></html>")


def cmd_report(args):
    if not os.path.exists(args.db):
        sys.exit(f"{args.db}: no such DB. Run `run` first to build it.")
    con = sqlite3.connect("file:" + urllib.parse.quote(os.path.abspath(args.db)) + "?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        where = "WHERE coalesce(info_score,0) >= ?" if args.min_score else ""
        q = f"SELECT * FROM devices {where} ORDER BY coalesce(info_score,0) DESC, radio, address"
        rows = con.execute(q, (args.min_score,) if args.min_score else ()).fetchall()
    finally:
        con.close()
    out = args.out or os.path.join(os.path.dirname(os.path.abspath(args.db)), "swivel_report.html")
    generated = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(out, "w", encoding="utf-8") as f:
        f.write(build_report_html(rows, os.path.basename(args.db), generated))
    print(f"wrote {out}  ({len(rows)} devices, ranked by info_score; no coordinates). Open it in a browser.")
    return 0


def cmd_run(args):
    db = args.db
    s = run(args.files, db, args.csv or os.path.splitext(db)[0] + "_devices.csv", args.registry, args.naive_tz,
            args.min_sightings, args.cluster_distance, args.follow_distance, args.follow_min_span, args.kismet_window,
            keep_noise=getattr(args, "keep_noise", True), fresh=getattr(args, "fresh", False))
    print(format_summary(s))
    print("\nwrote " + ", ".join(os.path.relpath(p) for p in s["files"]))
    # R1: the DB/CSV/GeoJSON hold coordinates, MACs, names and SSIDs. In out/ they are git-ignored; written elsewhere
    # (a custom --db/--csv) they are not, and a repo push would commit them. Warn loudly.
    default_out = os.path.join(HERE, "out")
    outside = [os.path.relpath(p) for p in s["files"] if os.path.dirname(os.path.abspath(p)) != default_out]
    if outside:
        print(f"WARNING (R1): these outputs are outside {os.path.relpath(default_out)}/ and are NOT git-ignored — they hold "
              f"coordinates, MACs, names and SSIDs. Keep them off GitHub and any sync: {', '.join(outside)}", file=sys.stderr)
    return 2 if sum(s["r3"].values()) else 0


def main():
    ap = argparse.ArgumentParser(description="DEBRIEF: SWIVEL + Kismet capture enhancer (offline).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    fp = sub.add_parser("fetch", help="download the reference registries into data/ and rewrite SOURCES.md")
    fp.add_argument("--alpr-bbox", help="S,W,N,E bounding box: fetch ALPR cameras only in this region (small, reliable) "
                    "instead of worldwide. Reveals the region to Overpass — your explicit choice, never derived from GPS.")
    fp.set_defaults(func=cmd_fetch)
    p = sub.add_parser("run", help="build the DB, devices CSV and run summary from capture files")
    p.add_argument("files", nargs="+", help="capture files (.ndjson, .json, .wiglecsv / WigleCSV .csv)")
    p.add_argument("--db", default=os.path.join(HERE, "out", "swivel.db"))
    p.add_argument("--csv", help="devices CSV (default: next to the DB)")
    p.add_argument("--registry", default=DATA, help="registry folder (default: data/)")
    p.add_argument("--naive-tz", default=system_zone(),
                   help="zone for SWIVEL timestamps without an offset (default: system zone)")
    p.add_argument("--min-sightings", type=int, default=1,
                   help="flag a device seen this many times or fewer with no payload as single_sighting_no_payload (default 1)")
    p.add_argument("--cluster-distance", type=float, default=50.0, help="metres: join sightings into one location cluster (default 50)")
    p.add_argument("--follow-distance", type=float, default=200.0,
                   help="metres: followed_flag needs clusters more than this far apart (default 200)")
    p.add_argument("--follow-min-span", type=float, default=300.0,
                   help="seconds: followed_flag needs sightings spanning more than this long (default 300)")
    p.add_argument("--kismet-window", type=float, default=60.0,
                   help="seconds: a phone sighting within +/- this of a Kismet observation of the same MAC counts as co-present (default 60)")
    p.add_argument("--keep-noise", action="store_true",
                   help="keep dead rows (randomized, no enrich/cluster handle) in the output; default drops them (raw sightings always kept)")
    p.add_argument("--fresh", action="store_true",
                   help="rebuild from ONLY the files given; default APPENDS them to an existing DB (deduped by content hash)")
    p.set_defaults(func=cmd_run)
    w = sub.add_parser("wigle", help="look up a built DB's Wi-Fi AP BSSIDs on WiGLE (online; off until enabled in sources.json)")
    w.add_argument("db", help="a DB built by `run` (opened read-only); its Wi-Fi AP BSSIDs are looked up")
    w.add_argument("--sources", default=SOURCES_PATH, help="sources manifest (default: sources.json)")
    w.add_argument("--registry", default=DATA, help="folder the BSSID cache is written under (default: data/)")
    w.add_argument("--max", type=int, default=100, help="most BSSIDs to query this run (WiGLE caps daily queries; default 100)")
    w.add_argument("--dry-run", action="store_true", help="print how many BSSIDs would be queried and send nothing")
    w.set_defaults(func=cmd_wigle)
    b = sub.add_parser("beacondb", help="look up a built DB's Wi-Fi AP BSSIDs on beaconDB (online, free/no-key; off until enabled in sources.json)")
    b.add_argument("db", help="a DB built by `run` (opened read-only); its Wi-Fi AP BSSIDs are looked up")
    b.add_argument("--sources", default=SOURCES_PATH, help="sources manifest (default: sources.json)")
    b.add_argument("--registry", default=DATA, help="folder the BSSID cache is written under (default: data/)")
    b.add_argument("--max", type=int, default=100, help="most BSSIDs to query this run (default 100)")
    b.add_argument("--dry-run", action="store_true", help="print how many BSSIDs would be queried and send nothing")
    b.set_defaults(func=cmd_beacondb)
    r = sub.add_parser("report", help="write a static HTML report of the devices, ranked by info_score (valuable columns, no coordinates)")
    r.add_argument("db", help="a DB built by `run` (opened read-only)")
    r.add_argument("--out", default=None, help="output HTML path (default: <db dir>/swivel_report.html)")
    r.add_argument("--min-score", type=int, default=0, help="only include devices with info_score >= this (default 0 = all)")
    r.set_defaults(func=cmd_report)
    args = ap.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
