# DEBRIEF — technical reference

*The how-and-why behind DEBRIEF. Start with the [main README](../README.md) if you're new.*

An offline, re-runnable pipeline that turns passive Wi‑Fi/Bluetooth capture logs into **one clean, queryable
SQLite dataset** for counter‑surveillance on your own captures — *what's near me, what's following me, what's watching me.*

It ingests **SWIVEL** phone captures (`.ndjson` / `.json`), **Kismet** native `.kismet` logs, and WigleCSV; merges them by
device (same MAC seen by the phone and by Kismet becomes one row); and enriches each device — vendor, coarse device type,
Apple‑Continuity advert intel, probed SSIDs, Wi‑Fi security/WPS, location clusters, a coarse "followed" candidate flag,
proximity to known ALPR cameras, and a phone↔Kismet cross‑check — **while refusing to guess where the data doesn't
support it.**

> Tooling for **authorized, personal** security research. It describes **devices, not people** (R8). Nothing about
> a capture leaves the machine: GPS and raw captures are never uploaded, and `data/`, `logs/`, `out/` are git‑ignored. The
> optional online lookups are manual, opt‑in, and limited to fixed infrastructure (Wi‑Fi AP BSSIDs) — never a client,
> BLE, or randomized MAC, and never your GPS.

Python **standard library only** — no installed dependencies in the tool itself (system PyYAML for the SIG files).

---

## The one thing to understand

`run` **accumulates.** Each `run` APPENDS the capture files you pass into the growing `out/swivel.db` (skipping any file
already ingested, by content hash) and rebuilds `devices` from the whole accumulated history — so pressing `run` after
every outing keeps building one dataset over time. Pass `--fresh` to rebuild from only the files given; you can still merge
several captures in one shot by listing them together. The raw `sightings` table is immutable (SQLite triggers block
UPDATE/DELETE); `devices` is rebuilt every run.

By default `run` also **drops dead rows** from the output: a randomized MAC with no identity, no enrich/cluster handle and
no behavioural signal (`noise_reason = dead_random_no_handle`) can never be enriched or linked, so it is left out of the
devices CSV/DB. The immutable `sightings` keep every row, so `--keep-noise` (or a later re-run) brings them back if more
data gives them a handle. Surviving rows carry an `info_score` (sort by it for the richest devices) and, when thin-but-kept,
a `noise_reason` (`thin_but_tracked` / `thin_has_handle` / `thin_real_oui`).

The loop is always: **get new data → `run` → (optional online lookups) → `run` again → browse.** Getting a capture off the
phone is covered in the [main README](../README.md#-use-it-on-your-own-captures).

## Quickstart

```bash
python3 swivel_enhance.py fetch                 # once: download the reference registries into data/ (writes SOURCES.md)
python3 swivel_enhance.py run logs/<phone>.ndjson <capture>.kismet --kismet-window 60
#   -> out/swivel.db, out/swivel_devices.csv, out/swivel_clusters.geojson, out/swivel_summary.txt
datasette out/swivel.db -m datasette_metadata.json      # browse at http://localhost:8001
python3 swivel_enhance.py report out/swivel.db                       # -> out/swivel_report.html: devices ranked by info_score, valuable columns, no coordinates
```

Combine several captures into one dataset by listing them all in one `run`. Tune location fields with
`--cluster-distance` / `--follow-distance` / `--follow-min-span`; set the phone↔Kismet co‑presence window with
`--kismet-window`.

## What it enriches (offline, from datasets downloaded once)

| field | from | notes |
|---|---|---|
| `oui_vendor` | IEEE MA‑S/M/L, Wireshark manuf | the hardware‑address owner; **withheld on randomized/LAA** (R3) |
| `oui_device_type` | ringmast4r OUI DB | coarse Router/Phone/Camera/IoT…; withheld like the vendor |
| `advertised_company` | Bluetooth SIG company IDs | what the advert *claims* (spoofable); allowed on randomized |
| `device_class` / `is_tracker` / `tracker_type` | `signatures.json`, then BLE GAP Appearance, then BT‑Classic Class‑of‑Device | coarse class: a signature match wins; else the SIG Appearance category (BLE) or the CoD major class (Classic), when the capture logs them |
| `apple_continuity_type` | hardcoded Continuity map | Find My vs Nearby Info vs Handoff vs Proximity Pair; works on randomized Apple MACs |
| `advertised_services` | Bluetooth SIG service + member UUIDs | the named services a BLE device advertises (Heart Rate, HID, Device Information, Google…; unknowns kept as hex); keys on the advert, randomized‑safe |
| `probed_ssids` | Kismet probe‑request frames | the network names a client broadcasts — a near‑unique fingerprint |
| `security_modes` / `wps_*` | Wi‑Fi RSN/WPA IEs | union across sightings; `security_conflict` flags OPEN‑vs‑WPA2 (evil‑twin signal) |
| `location_clusters` / `followed_flag` / `near_alpr` | the capture's own GPS + offline OSM ALPR set | per device; describes appearances, never a person (R8) |
| `seen_by_phone` / `seen_by_kismet` / `seen_by_both_within_window` / `kismet_ids_alerts` | phone↔Kismet merge | keeps "seen by both" honest with a time window |
| `wigle_location` / `beacondb_location` | WiGLE / beaconDB (online, opt‑in, AP‑only) | the one online step; manual, infrastructure‑only |
| `observed_ip` | SWIVEL app subnet sweep / own‑network record, or Kismet sniffed client IPs | layer‑3 IPv4 for a device — never from passive RF (that is layer‑2 only). `_source` says how it was learned: `swivel_sweep` (active ARP/connect sweep), `swivel_self` (the phone's own IP), `kismet_dhcp`/`kismet_arp`/`kismet_udptcp` (Kismet cleartext) |
| `device_cluster_id` | IE fingerprint + probe list | links one physical device across its rotating random MACs (client Wi‑Fi only; low confidence, needs probe data) |
| `info_score` / `noise_reason` | tool meta | usefulness score; why a thin row is kept, or (`dead_random_no_handle`) dropped from the output |

Every column is documented in **[FIELD-REFERENCE.md](FIELD-REFERENCE.md)**.

## Honest by construction

- **Every enriched field carries its own `_source` and `_confidence`.** Facts (counts, RSSI, which source saw it) carry
  neither. A blank means "not determined" — never a guess; the `_source` often says *why* (e.g.
  `oui_vendor_source = withheld:ble_strict`, or `no_registry_match`).
- **The hard rule (R3):** a randomized / locally‑administered address never gets a vendor. Enforced where the observation
  is built, **re‑audited independently every run** (`R3 check: … -> PASS`, exit code 2 on failure), and pinned by a
  regression test plus a mutation check.

| radio | `oui_vendor` |
|---|---|
| Wi‑Fi, LAA bit clear | IEEE MA‑S → MA‑M → MA‑L → Wireshark; **high** |
| Wi‑Fi, LAA bit set | never (`withheld:laa_bit`) |
| BLE | never, until the app logs a real address type (`withheld:ble_strict`) |
| Classic also seen as BLE | never (`withheld:classic_also_seen_as_ble`) |
| Classic only | as Wi‑Fi, but **med** |

- **Noise is flagged, never dropped (R5):** `duplicate_sighting`, `single_sighting_no_payload`, `malformed_*`,
  `unknown_radio`, `zero_or_broadcast_address` — all kept, with a `noise_reason`, so nothing silently disappears.
- **Identical re-reads collapse in `devices`, never in the raw log:** a byte-identical observation (double EXPORT, or the
  per-day file re-pulled after it grew) rolls into its device once, so counts never inflate — but the raw `sightings` row is
  still kept (reversible). `sighting_count` is therefore unique observations. A row carrying *more* info is a different
  observation, so it is always kept and merged, never dropped.
- **Captures are read‑only (R4):** a `.kismet` is opened immutably (no `-wal`/`-shm`); raw in, enriched copy out.
- **Aggregates only:** the run summary prints counts and distance *buckets*, never a raw address, name, SSID or
  coordinate. Coordinates live only in the git‑ignored `out/` files.

## Tests

```bash
python3 -m unittest discover -s tests            # the full suite (incl. the R3 hard-rule regression)
R3_TARGET=legacy python3 -m unittest discover -s tests   # the R3 cases against the old tool (must fail — proves the guard bites)
```

## Layout

| path | in repo? | what |
|---|---|---|
| `swivel_enhance.py` | yes | the tool (`fetch`, `run`, `wigle`, `beacondb`, `report`) |
| `sources.json` | yes | enrichment‑source manifest (per‑source `enabled` toggles) |
| `signatures.json` | yes | coarse BLE/Classic device/tracker signatures (edit to add families) |
| `tests/` | yes | tests + synthetic fixtures (capture‑format files are generated at test time) |
| `demo/` | yes | `make_demo.py` writes a synthetic capture to try the tool on |
| `docs/` | yes | this reference, the field reference, README images |
| `legacy/` | yes | the predecessor tool, verbatim, read‑only |
| `data/`, `logs/`, `out/` | **no (git‑ignored)** | downloaded datasets, copied captures, and outputs — GPS/MACs stay on the machine |

