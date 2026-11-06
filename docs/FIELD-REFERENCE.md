# `swivel_devices.csv` — field reference

**Date:** 2026-10-31 · **Source of truth:** `App/log-enhancer/swivel_enhance.py` (`device_row`, `wifi_security`,
`cross_check`, `classify`, `cluster_points`, `reg.vendor`). Every entry below was verified field-by-field against that code.

## How to read this file

- **One row per unique device**, keyed on `(address, radio)` — rebuilt fresh from the immutable `sightings` table on every
  `run`. All sightings of one address+radio merge into one row.
- **Most fields come as a trio:** `<field>` (value), `<field>_source` (how/where it was derived — a provenance tag), and
  `<field>_confidence` (`high` / `med` / `low`). A blank value means "not determined"; its `_source` often says why
  (`no_location`, `withheld:…`, `no_registry_match`).
- **Blank vs 0 matters.** Several flags are left **blank** when there's no evidence either way, and only `0` when there's
  positive evidence of absence. Noted per field.
- **Pure facts carry no trio:** `address`, `radio`, `sighting_count`, `sessions_seen`, `rssi_*`, `seen_by_phone`,
  `seen_by_kismet`.
- **Hard rule (R3):** a randomized / locally-administered address never gets a vendor — `oui_vendor` blank,
  `oui_vendor_source` a `withheld:…` tag.
- **List values are JSON** — the *union* of everything seen across sightings, never one kept and the rest dropped.

---

## Identity

**`address`** — Device hardware address (Wi-Fi BSSID, or BLE / BT-Classic MAC), normalized to uppercase colon hex. With
`radio` it's the primary key.

**`radio`** — Which radio saw it: exactly `wifi`, `ble`, or `bt-classic`.

**`address_type` / `_source` / `_confidence`** — `public` vs `local`/random. **Wi-Fi:** `local` if the address's U/L
("LAA") bit is set, else `public` — `source=laa_bit`, `high`, **always populated. BLE:** the app's reported type (a
top-bit guess) — `source=swivel_app_top_bit_guess`, `low`. **Classic:** the app's reported type —
`source=swivel_app_laa_bit_on_bredr`, `low`. For BLE and Classic the value **and** its source/confidence are **blank
unless the app logged an address_type** on at least one sighting.

**`is_randomized` / `_source` / `_confidence`** — `1` if randomized/locally-administered (so it can't be tracked over
time), `0` if not, **blank if unknown**. Wi-Fi: `int(LAA bit)`, `source=laa_bit`, `high`. BLE: from the app's
address-type (`source=swivel_app_top_bit_guess`, `low`; blank if the app logged no type). Classic also seen as BLE:
taken from the BLE sightings, `source=ble_sightings:swivel_app_top_bit_guess` (note the prefix); blank if those BLE
sightings carry no type. Classic-only with the LAA bit set: value and confidence blank, but
`source=laa_bit_set_on_bredr_address`. Ordinary Classic: `0`, `source=bredr_address_public_by_spec`, `med`.

**`oui_vendor` / `_source` / `_confidence`** — The IEEE/Wireshark registry owner of the address, subject to the hard
rule. **Withheld** (value and confidence blank): `source` is one of `withheld:zero_or_broadcast_address`,
`withheld:ble_strict`, `withheld:laa_bit`, `withheld:classic_also_seen_as_ble`. **Otherwise** the most-specific registry
match: `source` is `ieee_ma-s` | `ieee_ma-m` | `ieee_ma-l` | `wireshark_manuf`, confidence `high` (Wi-Fi) / `med`
(Classic). Two "no name" cases: a matched **Private** registration → blank vendor, `source=<tag>:private` (e.g.
`ieee_ma-l:private`), blank confidence; no match at all → blank vendor, `source=no_registry_match`, blank confidence.
This is the **address owner**, not the advertised SIG company (see `advertised_company`).

**`device_cluster_id`** — Links one physical device across its **rotating random Wi-Fi MACs**. Set by the stage-7
`cluster_devices` pass only on members of a **≥2-device group** that share an IE `fingerprint_hash` and an overlapping
`probed_ssids` set — an actual link, never a lone device, Wi-Fi clients only. Blank for everything else (most rows). Not
the same as `location_clusters`.

---

## Bluetooth advert & device class

**`advertised_company` / `advertised_company_id` / `_source` / `_confidence`** — (BLE/Classic) the Bluetooth-SIG company
owning the manufacturer-data company ID. `advertised_company_id` lists **every** company ID seen as hex (e.g. `0x004C`),
most-common first, and is filled whenever any company ID is present. The **name** (`advertised_company`) is filled only
when at least one seen ID is a **known** SIG company; if none is, the name stays blank with
`_source=unassigned_in_sig_list`. When named: `_source=bluetooth_sig_company_identifiers`, or
`…+unassigned_in_sig_list` if some (not all) seen IDs are unknown. Confidence: `high` = exactly one ID seen and known;
`med` = several IDs and the most-common one is the named known company; `low` = several IDs and the most-common is
unknown so a lower-ranked known ID is named. **This is a (spoofable) advert claim, not the hardware maker** — keep it
separate from `oui_vendor`.

**`apple_continuity_type` / `_source` / `_confidence`** — (BLE) JSON sorted list of the Apple **Continuity** message
types seen in the manufacturer-data TLV (e.g. `find_my`, `nearby_info`, `handoff`, `proximity_pair`; unknown types kept
as `0x<NN>`). Keys on the **advert**, not the MAC, so it survives Apple's MAC randomization. `source=apple_continuity_tlv`,
`med`. BLE only; blank otherwise.

**`advertised_services` / `_source` / `_confidence`** — (BLE) JSON sorted list of the Bluetooth-SIG **service UUIDs** the
device advertises, resolved to names (e.g. `Heart Rate`, `Device Information`, `Human Interface Device`; unknown 16-bit
UUIDs kept as `0x<XXXX>`). Also keys on the advert (randomized-safe). `source=bluetooth_sig_service_uuids`, `high`.

**`device_name` / `_source` / `_confidence`** — The name observed: Wi-Fi SSID (`source=ssid`), BLE local name
(`advertised_local_name`), or Classic remote name (`bt_remote_name`). `high` if one distinct name was seen, `med` if they
disagreed (most-common wins). A native-Kismet AP's **beaconed SSID** (`dot11.device.advertised_ssid_map`) now fills this
too (`source=ssid`), so a Kismet-only AP is no longer a nameless MAC; Kismet fills the real name even for a cloaked AP
once it sees a probe-response (the hidden-SSID reveal).

**`device_class` / `_source` / `_confidence`** — A coarse category assigned when the device matched a signature in
`signatures.json` (BLE/Classic only). `_source=signatures.json:<id>`, or `…:<id1>+<id2>` (sorted, `+`-joined) when several
matched. Confidence is **whatever the matched signature itself declares** (per-signature, not a fixed rule). When several
match, the class and confidence come from the **first tracker signature if present, else the first match**, while the
source still lists every matched id. When no signature matches, two offline fallbacks fill it (each `med`): the BLE
**GAP Appearance** category (`_source=bluetooth_sig_gap_appearance`, from the advert's AD type `0x19`), then the
BT-Classic **Class-of-Device** major class (`_source=bluetooth_sig_class_of_device`, from `getBluetoothClass()`). Both
are latent until the capture logs the field; the Class-of-Device major 0 (Miscellaneous) and 31 (Uncategorized) carry
no class and are skipped.

**`is_tracker` / `tracker_type` / `tracker_signature_source` / `tracker_confidence`** — `is_tracker=1` if the chosen best
signature is a tracker, `0` if a non-tracker signature matched, **blank if nothing matched**. `tracker_type` names the
family (e.g. `apple_find_my`, `tile`), set only on a match. `tracker_signature_source` is the same
`signatures.json:<ids>` string as `device_class_source`; `tracker_confidence` is the matched signature's declared
confidence (same value as `device_class_confidence`).

**`fingerprint_hash` / `_source` / `_confidence`** — (Wi-Fi only) SHA-256 of the sorted information-element IDs plus each
vendor IE's **first 4 bytes (the 3-byte OUI + the OUI type/subtype byte)**, first 16 hex chars
(`source=wifi_ie_id_and_vendor_oui`). **Deliberately coarse — it collides across same-model APs, so it's a device-*type*
signature, not an identity.** `med` if one fingerprint was seen, `low` if it varied.

**`observed_ip` / `_source` / `_confidence`** — The device's layer-3 **IPv4**, which a passive RF scan can never see (it
is layer-2 only). Filled from, in reliability order: the SWIVEL app's active subnet **sweep** (`swivel_sweep`, from the
kernel neighbour table after a connect-scan), the phone's **own-network** record (`swivel_self`), or **Kismet** sniffed
client ipdata — `kismet_dhcp` / `kismet_arp` (`high`), `kismet_udptcp` (`med`), `kismet_factoryguess` (`low`). One IP per
device (the most reliable source wins). Kismet IPs come only from **cleartext** traffic (open/decrypted networks), so an
all-encrypted capture yields none. IPv4 only (no IPv6 is captured). *shortcut: the Kismet packed-uint32 → dotted-quad
octet order is unverified against a live capture — confirm against a known gateway (e.g. a `.1`) and flip `ipv4_from_u32`
if reversed.*

---

## Location — stage 3, offline, describes the device not a person

**`location_clusters` / `_source` / `_confidence`** — JSON array of greedy clusters, one object per place:
`{"lat":…, "lon":…, "n":…}`. `lat`/`lon` are the cluster **centroid** (lat = mean, lon = circular mean, 6 dp); `n` =
number of **GPS-located** sightings in that cluster. Randomized / GPS-less sightings aren't counted, so **`sum(n)` can be
less than `sighting_count`**. Greedy join within `cluster_distance` m (default 50). `source=greedy_<N>m`, `med`. If the
device had no located sighting: value blank, `source=no_location`.

**`followed_flag` / `_source` / `_confidence`** — `1` if the **same address** appeared at ≥2 clusters more than
`follow_m` m apart, spanning more than `follow_s` s. `source=">=2_clusters_>…m_apart_>…s"`, `low`. A **coarse candidate
signal only**: needs a persistent MAC (randomization hides a real tail), and on a round-trip it fires often because you
retrace the route. Read as "worth a look," not "this followed you."

**`near_alpr` / `_source` / `_confidence`** — Whole metres from the device's nearest cluster centroid to the nearest OSM
ALPR camera (OSM nodes tagged `surveillance:type=ALPR` worldwide — DeFlock's dataset, **all ALPR vendors, not just
Flock**). `source=osm_alpr_nearest`, `med`. `source=no_alpr_dataset` when the camera set is empty (download skipped,
Overpass failed, or `alpr.json` unreadable); `source=no_location` when the device had no GPS fix.

---

## Wi-Fi security & WPS — union across sightings, nothing dropped

**`security_modes` / `_source` / `_confidence`** — JSON sorted list of every security mode seen, each a **composite
token** e.g. `WPA2-PSK-CCMP`, `WPA3-SAE-CCMP`, `OWE-CCMP`, `WEP`, `OPEN`, or `OTHER:<tok>`. `_source` is a `+`-joined
sorted set of the tags used: `rsn_ie`, `wpa_ie`, `capabilities_string`, `rsn_ie_unreadable`. Confidence `high` only if the
set is wholly RSN/WPA IEs (`{rsn_ie, wpa_ie}`); otherwise `med`.

**`security_conflict` / `_source` / `_confidence`** — `1` if the device's own sightings disagreed about security (e.g.
`OPEN` one scan, `WPA2` another) — a downgrade / evil-twin signal. `source=sighting_disagreement` vs
`consistent_across_sightings`, `high`.

**`wps_enabled` / `_source` / `_confidence`** — `1` if WPS was present (`wps_ie`, `high`; or `[WPS]` in the capabilities
string, `capabilities_string`, `med`); `0` if elements were present but no WPS IE (`wps_ie_absent`, `high`) or a
capabilities string was present with no `[WPS]` and no IEs (`capabilities_string`, `med`); **blank** if there was no WPS
evidence at all.

**`wps_make` / `wps_model` / `wps_serial` (+ `_source` / `_confidence`)** — Maker / model / serial, each a JSON sorted
list (a set — several kept). `source=wps_ie` (`high` single / `med` several) from the phone's WPS IE; or
`source=kismet_advertised_ssid` (`high`) from Kismet's already-decoded beacon WPS, which fills a native-Kismet AP the
phone's IEs didn't cover. `wps_model` is composed as `model_name (model_number)`. Present only when WPS leaks the
attribute — notable because these can name a device **even on a randomized BSSID**.

---

## Timing, counts, cross-check & online enrichment

**`first_seen` / `last_seen` (+ `_source` / `_confidence`)** — Earliest / latest sighting time normalized to UTC
(`YYYY-MM-DDTHH:MM:SS.mmmZ`). `_source` is the timestamp's provenance: `timestamp_with_offset` = phone time carrying a UTC
offset (`high`); `assumed:<zone>` = phone time with no offset, resolved in the configured naive zone, e.g.
`assumed:America/New_York` (`med`); `utc:kismet_wiglecsv` = Kismet WigleCSV FirstSeen (`high`); `utc:kismet_db` = native
`.kismet` first_time (`med`). (This drive's phone data carried offsets → `timestamp_with_offset`.)

**`sighting_count`** — Raw sightings merged into this device row (fact).

**`sessions_seen`** — Distinct capture sessions that observed it (fact).

**`rssi_max` / `rssi_median`** — Signal-strength stats (dBm) across sightings (facts): the closest approach and the
median. Closer ≈ stronger (less negative).

**`probed_ssids`** — JSON sorted list of the network names a **client** actively probed for — a near-unique behavioural
fingerprint (the SSIDs a device remembers and hunts for). Filled from **Kismet native `.kismet` logs only** (probe-request
frames need monitor mode; the phone app cannot capture them). Blank for APs and for phone-only captures.

**`seen_by_phone` / `seen_by_kismet`** — `1`/`0` facts: did the phone / did Kismet log this address (no trio).

**`seen_by_both_within_window` (+ `_source` / `_confidence`)** — `1` if some phone sighting time `p` falls within
`first - window ≤ p ≤ last + window` of a Kismet observation of the same address+radio (for native `.kismet` the
observation spans `first_time..last_time`; a WigleCSV sighting is a point). **Blank** unless the address was seen by
**both** phone and a timestamped Kismet sighting; `0` only when both exist but none matched. `source=kismet_window_<N>s`
(N = window seconds, e.g. `kismet_window_60s`); `high` if matched, `low` if not.

**`kismet_ids_alerts` (+ `_source` / `_confidence`)** — JSON sorted list of Kismet IDS alert names that fired on this
device. `source=kismet_db_alerts`, `high`.

**`wigle_location` (+ `_source` / `_confidence`)** — (Wi-Fi AP only, opt-in) WiGLE's own geolocation for this BSSID —
`{"lat":…, "lon":…[, "ssid":…]}` — folded from the local cache if you ran the `wigle` lookup. `source=wigle_api`, `med`.
Blank unless you enabled and ran it.

**`beacondb_location` (+ `_source` / `_confidence`)** — (Wi-Fi AP only, opt-in) beaconDB's **keyless** geolocation for
this BSSID — `{"lat":…, "lon":…}` — folded from the local cache if you ran the `beacondb` lookup. `source=beacondb_api`,
`med`. A free, no-key alternative to WiGLE, but with far thinner coverage (0 hits on this drive's area). Blank unless you
enabled and ran it.

---

## What's populated right now (this drive's DB)

- **Always filled:** `address`, `radio`, `sighting_count`, `sessions_seen`, `seen_by_phone`, `seen_by_kismet`,
  `first_seen`/`last_seen`, `rssi_*`, and the address/randomization/vendor trio (vendor withheld where the rule applies).
- **Radio-specific:** security/WPS + `fingerprint_hash` → Wi-Fi only; `advertised_company`, `device_class`, tracker
  fields → BLE/Classic only; `wigle_location` → Wi-Fi APs only (and only if you ran `wigle`).
- **Needs the camera dataset:** `near_alpr` shows `no_alpr_dataset` — the worldwide Overpass pull is failing right now;
  retry `fetch` later.
- **Rarely / conditionally filled:** `device_cluster_id` (only Wi-Fi clients linked across rotating MACs — a ≥2 group),
  `probed_ssids` (Kismet native captures only), `observed_ip` (app sweep / own-network, or Kismet cleartext only).
