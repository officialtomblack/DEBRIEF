"""Stage 1: timestamps, Classic/BLE separation, full vendor lists, attribution sources, Wi-Fi security, inputs,
immutability, and the R1/R3/R4/R5 guards. All inputs are synthetic and written to a temp dir; the registry is
tests/fixtures/registry (real rows, tiny)."""
import argparse, csv, json, os, shutil, sqlite3, subprocess, sys, tempfile, unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import swivel_enhance as se
import r3_harness as h

REG = os.path.join(HERE, "fixtures", "registry")
SWIVEL_PREHEADER = "WigleWifi-1.4,appRelease=SWIVEL,model=,release=,device=,display=,board=,brand="


def phone_row(mac, kind, **kw):
    row = {"iso_time": "2026-10-30T01:00:00-0400", "session_id": "t", "source": "PHONE", "kind": kind, "mac": mac,
           "address_type": "", "vendor": "", "ssid_or_name": "", "rssi": -60}
    row.update(kw)
    return row


def wigle_row(mac, kind="WIFI", first_seen="2026-10-30 05:00:00", ssid="", auth=""):
    return [mac, ssid, auth, first_seen, "0", "-60", "", "", "", "", kind]


class Built(unittest.TestCase):
    """Helpers: write synthetic inputs, run the pipeline, query the DB."""
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="st1_")
        self.dir = self._tmp.name
        self.db = os.path.join(self.dir, "out", "t.db")

    def tearDown(self):
        self._tmp.cleanup()

    def path(self, name):
        return os.path.join(self.dir, name)

    def ndjson(self, rows, name="p.ndjson", raw_lines=(), bom=False):
        p = self.path(name)
        with open(p, "w", encoding="utf-8") as f:
            f.write("﻿" if bom else "")
            f.writelines(json.dumps(r) + "\n" for r in rows)
            f.writelines(l + "\n" for l in raw_lines)
        return p

    def wigle(self, rows, name="k.wiglecsv", preheader=h.WIGLE_PREHEADER, header=h.WIGLE_HEADER, bom=False):
        p = self.path(name)
        with open(p, "w", encoding="utf-8", newline="") as f:
            f.write(("﻿" if bom else "") + preheader + "\n")
            w = csv.writer(f)
            if header:
                w.writerow(header)
            w.writerows(rows)
        return p

    def build(self, *paths, tz="America/New_York", min_sightings=0):
        # stage-1 tests use minimal payloadless rows to probe other behaviour; min_sightings=0 keeps the stage-2
        # single_sighting_no_payload rule from firing on them. Stage-2 tests exercise that rule with min_sightings>=1.
        self.summary = se.run(list(paths), self.db, self.db + ".csv", REG, tz, min_sightings)
        self.conn = sqlite3.connect(self.db)
        self.conn.row_factory = sqlite3.Row
        self.addCleanup(self.conn.close)

    def device(self, addr, radio):
        return self.conn.execute("SELECT * FROM devices WHERE address=? AND radio=?", (addr, radio)).fetchone()

    def count(self, sql, *a):
        return self.conn.execute(sql, a).fetchone()[0]


class Timestamps(Built):
    def test_formats_normalize_to_one_utc_format(self):
        self.assertEqual(se.norm_ts("2026-10-30T00:45:57-0400", "UTC"), ("2026-10-30T04:45:57.000Z", "offset"))
        self.assertEqual(se.norm_ts("2026-10-30 00:36:53", "America/New_York"),
                         ("2026-10-30T04:36:53.000Z", "assumed:America/New_York"))
        self.assertEqual(se.norm_ts("2026-10-30 04:36:53", "UTC", "utc:kismet_wiglecsv"),
                         ("2026-10-30T04:36:53.000Z", "utc:kismet_wiglecsv"))
        self.assertEqual(se.norm_ts("2026-10-30T04:36:53Z", "UTC")[0], "2026-10-30T04:36:53.000Z")
        self.assertEqual(se.norm_ts("2026-10-30T04:36:53.5+00:00", "UTC")[0], "2026-10-30T04:36:53.500Z")
        self.assertEqual(se.norm_ts("not a time", "UTC"), (None, None))
        self.assertEqual(se.norm_ts("0001-01-01T00:00:00+14:00", "UTC"), (None, None))   # overflow: flagged, no crash

    def test_mixed_format_inputs_sort_in_time_order(self):
        a = "00:00:0C:00:00:01"
        p = self.ndjson([phone_row(a, "WIFI", iso_time="2026-10-30T01:00:00-0400"),      # 05:00Z
                         phone_row(a, "WIFI", iso_time="2026-10-30T02:00:00+0000")])     # 02:00Z
        k = self.wigle([wigle_row(a, first_seen="2026-10-30 09:30:00")])                 # Kismet = UTC: 09:30Z
        s = self.wigle([wigle_row(a, first_seen="2026-10-30 03:00:00")], name="s_wigle.csv",
                       preheader=SWIVEL_PREHEADER)                                        # SWIVEL = local: 07:00Z
        self.build(p, k, s, tz="America/New_York")
        d = self.device(a, "wifi")
        self.assertEqual((d["first_seen"], d["last_seen"]), ("2026-10-30T02:00:00.000Z", "2026-10-30T09:30:00.000Z"))
        self.assertEqual((d["first_seen_source"], d["first_seen_confidence"]), ("timestamp_with_offset", "high"))
        self.assertEqual((d["last_seen_source"], d["last_seen_confidence"]), ("utc:kismet_wiglecsv", "high"))
        want = ["2026-10-30T02:00:00+0000", "2026-10-30T01:00:00-0400", "2026-10-30 03:00:00", "2026-10-30 09:30:00"]
        self.assertEqual([r[0] for r in self.conn.execute("SELECT ts_raw FROM sightings ORDER BY ts_utc")], want)
        self.assertNotEqual(sorted(want), want)        # what the legacy raw-text compare would have produced
        self.assertEqual(self.count("SELECT count(*) FROM sightings WHERE ts_tz='assumed:America/New_York'"), 1)


class Addresses(Built):
    def test_norm_addr(self):
        self.assertEqual(se.norm_addr("d0-03-4b-00-00-0c"), "D0:03:4B:00:00:0C")
        self.assertEqual(se.norm_addr("D0034B00000C"), "D0:03:4B:00:00:0C")
        for bad in ("xx:03:4b:00:00:0c", "D0:03:4B:00:00", "", None, 12345, "mac"):
            self.assertIsNone(se.norm_addr(bad))

    def test_c1_two_devices_and_classic_vendor_withheld(self):
        a = "D0:03:4B:00:00:0C"
        p = self.ndjson([phone_row("d0-03-4b-00-00-0c", "CLASSIC", address_type="public"),      # lowercase, dashes
                         phone_row(a, "BLE", address_type="random_static", manufacturer="4C001005"),
                         phone_row(a, "BLE", address_type="random_static", manufacturer="4C001005")])
        self.build(p)
        rows = self.conn.execute("SELECT radio, sighting_count FROM devices WHERE address=? ORDER BY radio", (a,)).fetchall()
        # the two BLE rows are byte-identical -> one observation logged twice; derive's exact-duplicate dedup rolls the
        # device up from UNIQUE sightings, so sighting_count is 1 -- but the raw sightings log keeps both rows (reversible).
        self.assertEqual([tuple(r) for r in rows], [("ble", 1), ("bt-classic", 1)])
        self.assertEqual(self.count("SELECT count(*) FROM sightings WHERE radio='ble'"), 2)
        c = self.device(a, "bt-classic")
        self.assertEqual((c["oui_vendor"], c["oui_vendor_source"]), (None, "withheld:classic_also_seen_as_ble"))
        self.assertEqual(self.device(a, "ble")["advertised_company"], "Apple, Inc.")


class Attribution(Built):
    EXPECT = {  # case id -> radio -> (is_randomized, source, confidence)
        "W1": {"wifi": (1, "laa_bit", "high")}, "W2": {"wifi": (1, "laa_bit", "high")}, "W3": {"wifi": (1, "laa_bit", "high")},
        "B1": {"ble": (1, "swivel_app_top_bit_guess", "low")}, "B2": {"ble": (1, "swivel_app_top_bit_guess", "low")},
        "B3": {"ble": (1, "swivel_app_top_bit_guess", "low")},
        "M1": {"ble": (None, None, None)}, "M2": {"ble": (None, None, None)}, "M3": {"ble": (None, None, None)},
        "M4": {"ble": (None, None, None)}, "M5": {"ble": (0, "swivel_app_top_bit_guess", "low")},
        "C1": {"ble": (1, "swivel_app_top_bit_guess", "low"),
               "bt-classic": (1, "ble_sightings:swivel_app_top_bit_guess", "low")},
        "C2": {"bt-classic": (None, "laa_bit_set_on_bredr_address", None)},
        "P1": {"wifi": (0, "laa_bit", "high")}, "P2": {"bt-classic": (0, "bredr_address_public_by_spec", "med")},
        "P3": {"wifi": (0, "laa_bit", "high")}, "P4": {"wifi": (0, "laa_bit", "high")},
    }

    def test_oui_device_type_filled_and_withheld_on_randomized(self):
        wifi = "00:00:0C:12:34:56"     # Cisco OUI -> device_type Router in the fixture; public MAC -> filled
        ble = "A4:83:E7:12:34:56"      # Apple OUI has a device_type, but BLE is withheld (R3) -> stays blank
        p = self.ndjson([phone_row(wifi, "WIFI", ssid_or_name="n"), phone_row(ble, "BLE")], name="dt.ndjson")
        self.build(p, tz="UTC")
        w = self.device(wifi, "wifi")
        self.assertEqual((w["oui_device_type"], w["oui_device_type_source"], w["oui_device_type_confidence"]),
                         ("Router", "ringmast4r_oui_db", "low"))
        self.assertIsNone(self.device(ble, "ble")["oui_device_type"])   # OUI has a type but the hard rule withholds it on BLE

    def test_apple_continuity_type(self):
        dev = "22:33:44:55:66:77"   # BLE; keys on the advert content, so a randomized Apple MAC is fine
        p = self.ndjson([phone_row(dev, "BLE", manufacturer="4C001202AABB1002CCDD")], name="apple.ndjson")
        self.build(p, tz="UTC")                           # 0x004C TLV chain: FindMy (0x12) + NearbyInfo (0x10)
        d = self.device(dev, "ble")
        self.assertEqual((json.loads(d["apple_continuity_type"]), d["apple_continuity_type_source"]),
                         (["FindMy", "NearbyInfo"], "apple_continuity_tlv"))

    def test_advertised_services_named_from_sig_uuids(self):
        dev = "24:33:44:55:66:79"   # BLE; keys on the advert, randomized-safe (R8: device, not person)
        p = self.ndjson([phone_row(dev, "BLE",
                         services="0000180d-0000-1000-8000-00805f9b34fb,0000fe2c-0000-1000-8000-00805f9b34fb")],
                        name="svc.ndjson")               # 0x180D Heart Rate (service UUID), 0xFE2C Google LLC (member UUID)
        self.build(p, tz="UTC")
        d = self.device(dev, "ble")
        self.assertEqual((json.loads(d["advertised_services"]), d["advertised_services_source"]),
                         (["Google LLC", "Heart Rate"], "bluetooth_sig_service_uuids"))

    def test_gap_appearance_fills_device_class_when_capture_has_it(self):
        dev = "26:33:44:55:66:7A"   # BLE, appearance category 1 (Phone); no signature match -> Appearance fills device_class
        p = self.ndjson([phone_row(dev, "BLE", appearance=64)], name="appear.ndjson")   # 64 = category 1 << 6
        self.build(p, tz="UTC")
        d = self.device(dev, "ble")
        self.assertEqual((d["device_class"], d["device_class_source"], d["device_class_confidence"]),
                         ("Phone", "bluetooth_sig_gap_appearance", "med"))

    def test_class_of_device_fills_device_class_for_classic(self):
        dev = "28:33:44:55:66:7B"   # BT-Classic, no signature match -> Class-of-Device fills device_class
        p = self.ndjson([phone_row(dev, "CLASSIC", class_of_device=524)], name="cod.ndjson")   # 524=0x20C, major (0x20C>>8)&0x1F = 2 (Phone)
        self.build(p, tz="UTC")
        d = self.device(dev, "bt-classic")
        self.assertEqual((d["device_class"], d["device_class_source"], d["device_class_confidence"]),
                         ("Phone", "bluetooth_sig_class_of_device", "med"))

    def test_class_of_device_uncategorized_major_carries_no_class(self):
        dev = "2A:33:44:55:66:7C"   # CoD major 31 (Uncategorized) is no information -> device_class stays empty
        p = self.ndjson([phone_row(dev, "CLASSIC", class_of_device=(31 << 8))], name="cod31.ndjson")
        self.build(p, tz="UTC")
        self.assertFalse(self.device(dev, "bt-classic")["device_class"])

    def test_is_randomized_and_address_type_sources_are_honest(self):
        cases = h.load_cases()
        self.build(*h.build_inputs(cases, self.path("in")), tz="UTC")
        self.assertEqual(set(self.EXPECT), {c["id"] for c in cases})
        for c in cases:
            for radio, want in self.EXPECT[c["id"]].items():
                with self.subTest(case=c["id"], radio=radio):
                    d = self.device(c["address"], radio)
                    self.assertEqual((d["is_randomized"], d["is_randomized_source"], d["is_randomized_confidence"]), want)
        w2 = self.device("1A:2B:3C:00:00:02", "wifi")   # app labelled it public; the bit says local, and the bit wins
        self.assertEqual((w2["address_type"], w2["address_type_source"], w2["address_type_confidence"]),
                         ("local", "laa_bit", "high"))
        self.assertEqual(self.device("A4:83:E7:00:00:0B", "ble")["address_type_confidence"], "low")

    def test_every_enriched_value_has_source_and_confidence(self):
        cases = h.load_cases()
        phone, kismet = h.build_inputs(cases, self.path("in"))
        a = "00:00:0C:00:00:40"
        extra = self.ndjson([phone_row(a, "WIFI", ssid_or_name="net-a", information_elements=f"48:{RSN_PSK}"),
                             phone_row(a, "WIFI", ssid_or_name="net-b", information_elements=f"48:{RSN_PSK}")], name="x.ndjson")
        self.build(phone, kismet, extra, tz="UTC")
        paired = [c for c in se.DEVICE_COLS if c + "_source" in se.DEVICE_COLS and c + "_confidence" in se.DEVICE_COLS]
        self.assertEqual(len(paired), 26)                  # 12 base + stage2 (device_class, fingerprint_hash, security_conflict)
        #   + oui_device_type (ringmast4r) + apple_continuity_type + beacondb_location + advertised_services (stage 8) + observed_ip (stage 9)
        #   + stage3 (location_clusters, followed_flag, near_alpr) + stage4 (seen_by_both_within_window,
        #   kismet_ids_alerts) + stage6 (wigle_location); seen_by_phone/seen_by_kismet are facts, no source/confidence pair
        for d in self.conn.execute("SELECT * FROM devices"):
            for c in paired:
                if d[c] is not None:
                    with self.subTest(device=d["address"], radio=d["radio"], field=c):
                        self.assertIsNotNone(d[c + "_source"])
                        self.assertIn(d[c + "_confidence"], ("high", "med", "low"))
        self.assertEqual(self.device(a, "wifi")["device_name_confidence"], "med")   # two SSIDs seen: not "high"


class VendorLists(Built):
    def test_most_specific_ieee_list_wins(self):
        reg = se.Registry(REG)
        self.assertEqual(reg.vendor("C85CE27ABCDE"), ("SYNERGY SYSTEMS AND SOLUTIONS", "ieee_ma-m"))
        self.assertEqual(reg.vendor("8C1F64AFA123"), ("DATA ELECTRONIC DEVICES, INC", "ieee_ma-s"))
        self.assertEqual(reg.vendor("00000C123456"), ("Cisco Systems, Inc", "ieee_ma-l"))
        # MA-L parent block owned by "IEEE Registration Authority" is not a vendor: falls through to manuf, else none.
        self.assertEqual(reg.vendor("C85CE2012345"), ("Fela Management AG", "wireshark_manuf"))
        self.assertEqual(reg.vendor("8C1F64000001"), (None, None))
        self.assertEqual(reg.vendor("000001ABCDEF"), ("Xerox Corporation", "wireshark_manuf"))
        self.assertEqual(reg.vendor("E4F14C000001"), (None, "ieee_ma-l:private"))   # "Private" is not a vendor name

    def test_company_ids_from_full_sig_list_and_unassigned_flagged(self):
        mixed = [phone_row("47:00:00:00:00:09", "BLE", address_type="random_rpa", manufacturer="02880011")] * 9 + \
                [phone_row("47:00:00:00:00:09", "BLE", address_type="random_rpa", manufacturer="4C001005")]
        p = self.ndjson([phone_row("47:00:00:00:00:01", "BLE", address_type="random_rpa", manufacturer="AB010203"),
                         phone_row("47:00:00:00:00:02", "BLE", address_type="random_rpa", manufacturer="02880011")] + mixed)
        self.build(p)
        meta, odd, mix = (self.device(f"47:00:00:00:00:0{i}", "ble") for i in (1, 2, 9))
        self.assertEqual((meta["advertised_company"], meta["advertised_company_id"], meta["advertised_company_confidence"]),
                         ("Meta Platforms, Inc.", "0x01AB", "high"))
        self.assertIsNone(meta["oui_vendor"])
        self.assertEqual((odd["advertised_company"], odd["advertised_company_id"], odd["advertised_company_source"]),
                         (None, "0x8802", "unassigned_in_sig_list"))
        # 9 sightings say 0x8802 (unassigned), 1 says Apple: Apple is named, but at low confidence and the 0x8802 stays visible
        self.assertEqual((mix["advertised_company"], mix["advertised_company_id"], mix["advertised_company_source"],
                          mix["advertised_company_confidence"]),
                         ("Apple, Inc.", "0x8802,0x004C", "bluetooth_sig_company_identifiers+unassigned_in_sig_list", "low"))

    @unittest.skipUnless(os.path.exists(os.path.join(se.DATA, "bluetooth-sig", "company_identifiers.yaml")),
                         "data/ not fetched (run: python3 swivel_enhance.py fetch)")
    def test_real_registries_are_the_full_lists(self):
        reg = se.Registry(se.DATA)
        self.assertEqual({len(k) for k in reg.ieee}, {6, 7, 9})          # MA-L, MA-M and MA-S all loaded
        self.assertGreater(len(reg.company), 4000)                       # not the legacy 22-ID subset
        self.assertEqual(reg.company[0x01AB], "Meta Platforms, Inc.")
        self.assertEqual(reg.company[0x012D], "Sony Corporation")
        self.assertNotIn(0x8802, reg.company)


RSN_PSK = "0100000FAC040100000FAC040100000FAC020C00"
RSN_PSK_SAE = "0100000FAC040100000FAC040200000FAC02000FAC08CC00"
RSN_SAE = "0100000FAC040100000FAC040100000FAC08CC00"
WPA_PSK_TKIP = "0050F20101000050F2020100" "0050F2020100" "0050F202"


def wps_tlv(t, s):
    return (t.to_bytes(2, "big") + len(s).to_bytes(2, "big") + s.encode()).hex().upper()


class Security(Built):
    def test_rsn_parse(self):
        p = lambda hx, wpa=False: se.parse_rsn(bytes.fromhex(hx), wpa)
        self.assertEqual(p(RSN_PSK), ({"WPA2-PSK-CCMP"}, {"PSK"}, {"CCMP"}))
        self.assertEqual(p(RSN_PSK_SAE)[0], {"WPA2-PSK-CCMP", "WPA3-SAE-CCMP"})
        self.assertEqual(p("0100000FAC020200000FAC02000FAC040100000FAC020000"),
                         ({"WPA2-PSK-TKIP", "WPA2-PSK-CCMP"}, {"PSK"}, {"TKIP", "CCMP"}))
        self.assertEqual(p("0100000FAC040100000FAC040100000FAC12C000")[0], {"OWE-CCMP"})
        self.assertEqual(p("0100000FAC090100000FAC090100000FAC0C0000")[0], {"WPA3-EAP-GCMP"})   # AKM 12: 192-bit
        self.assertEqual(p("0100000FAC040100000FAC040100000FAC0B0000")[0], {"WPA2-EAP-CCMP"})   # AKM 11 is not WPA3
        self.assertEqual(p("0100000FAC040100000FAC040100000FAC05C000")[0], {"WPA3-EAP-CCMP"})   # AKM 5 + MFPR
        self.assertEqual(p("0100000FAC040100000FAC040100000FAC058000")[0], {"WPA2-EAP-CCMP"})   # AKM 5, MFP capable only
        self.assertEqual(p("0100000FAC020100000FAC000100000FAC020000"), ({"WPA2-PSK-TKIP"}, {"PSK"}, {"TKIP"}))  # use group
        self.assertEqual(p("0100"), ({"WPA2-EAP-CCMP"}, {"EAP"}, {"CCMP"}))   # version only: the standard's defaults
        for bad in ("", "01", "0200000FAC040100000FAC040100000FAC02", "0100000F"):   # empty, short, version 2, cut group
            self.assertEqual(p(bad), (set(), set(), set()), bad)
        self.assertEqual(p("0100000FAC040200000FAC04")[1], set())           # truncated: no AKM invented
        self.assertEqual(p(WPA_PSK_TKIP[8:], wpa=True)[0], {"WPA-PSK-TKIP"})

    def test_capabilities_string_parse(self):
        self.assertEqual(se.parse_caps("[WPA2-PSK-CCMP][RSN-PSK+SAE-CCMP][ESS][WPS]")[0], {"WPA2-PSK-CCMP", "WPA3-SAE-CCMP"})
        self.assertEqual(se.parse_caps("[WPA2-EAP/SHA1-CCMP][RSN-EAP/SHA1-CCMP][ESS]")[0], {"WPA2-EAP-CCMP"})
        self.assertEqual(se.parse_caps("[RSN-EAP_SUITE_B_192-GCMP-256][ESS]")[0], {"WPA3-EAP-GCMP"})
        self.assertEqual(se.parse_caps("[ESS]"), ({"OPEN"}, {"NONE"}, set()))
        self.assertEqual(se.parse_caps("[WEP][ESS]")[0], {"WEP"})
        self.assertEqual(se.parse_caps("[OWE_TRANSITION][ESS]")[0], {"OPEN"})
        self.assertEqual(se.parse_caps("[WAPI-PSK][ESS]")[0], {"OTHER:WAPI-PSK"})      # unreadable is never OPEN
        self.assertEqual(se.parse_caps("WPA2 PSK AES")[0], {"OTHER:WPA2 PSK AES"})
        self.assertEqual(se.parse_caps(""), (set(), set(), set()))

    def test_wps_parse_stops_at_truncated_attribute(self):
        body = bytes.fromhex(wps_tlv(0x1021, "Make") + "10230010") + b"short"
        self.assertEqual(se.parse_wps(body), {"make": "Make"})

    def test_device_unions_every_mode_and_wps_identity(self):
        a = "00:00:0C:00:00:02"
        part = wps_tlv(0x1021, "FixtureCo") + wps_tlv(0x1023, "FX-1") + wps_tlv(0x1024, "100") + wps_tlv(0x1042, "SN123")
        cut = len(part) // 2 + 3                                   # split mid-attribute across two elements
        ies = f"0:46495854,48:{RSN_PSK},221:0050F204{part[:cut]},221:0050F204{part[cut:]}"
        other_wps = wps_tlv(0x1021, "OtherCo") + wps_tlv(0x1023, "FX-1") + wps_tlv(0x1024, "100") + wps_tlv(0x1042, "SN999")
        p = self.ndjson([phone_row(a, "WIFI", security="[WPA2-PSK-CCMP][ESS][WPS]", information_elements=ies),
                         phone_row(a, "WIFI", security="[RSN-SAE-CCMP][ESS]",
                                   information_elements=f"0:46495854,48:{RSN_SAE},221:0050F204{other_wps}"),
                         phone_row(a, "WIFI", security="[ESS]", information_elements="0:46495854")])
        self.build(p)
        d = self.device(a, "wifi")
        self.assertEqual(json.loads(d["security_modes"]), ["OPEN", "WPA2-PSK-CCMP", "WPA3-SAE-CCMP"])
        self.assertEqual((d["security_modes_source"], d["security_modes_confidence"]),
                         ("capabilities_string+rsn_ie", "med"))
        self.assertEqual(d["wps_enabled"], 1)
        self.assertEqual(json.loads(d["wps_make"]), ["FixtureCo", "OtherCo"])          # both identities kept
        self.assertEqual((json.loads(d["wps_model"]), d["wps_model_confidence"]), (["FX-1 (100)"], "high"))
        self.assertEqual((json.loads(d["wps_serial"]), d["wps_serial_confidence"]), (["SN123", "SN999"], "med"))
        raws = [r[0] for r in self.conn.execute("SELECT security_raw FROM sightings ORDER BY id")]
        self.assertEqual(raws, [f"48:{RSN_PSK}", f"48:{RSN_SAE}", None])

    def test_unreadable_rsn_falls_back_to_capabilities(self):
        a = "00:00:0C:00:00:03"
        p = self.ndjson([phone_row(a, "WIFI", security="[WPA2-PSK-CCMP][ESS]",
                                   information_elements="48:0200000FAC040100000FAC040100000FAC02")])
        self.build(p)
        d = self.device(a, "wifi")
        self.assertEqual((json.loads(d["security_modes"]), d["security_modes_source"], d["security_modes_confidence"]),
                         (["WPA2-PSK-CCMP"], "capabilities_string+rsn_ie_unreadable", "med"))

    def test_wiglecsv_authmode_and_wpa_vendor_element(self):
        k = self.wigle([wigle_row("00:00:0C:00:00:04", auth="[WPA2-PSK-CCMP][WPS][ESS]")])
        p = self.ndjson([phone_row("00:00:0C:00:00:05", "WIFI", security="[WPA-PSK-TKIP][ESS]",
                                   information_elements=f"0:46495854,221:{WPA_PSK_TKIP}")])
        self.build(k, p)
        kd, pd = self.device("00:00:0C:00:00:04", "wifi"), self.device("00:00:0C:00:00:05", "wifi")
        self.assertEqual(self.count("SELECT count(*) FROM sightings WHERE security_raw='[WPA2-PSK-CCMP][WPS][ESS]'"), 1)
        self.assertEqual((json.loads(kd["security_modes"]), kd["security_modes_source"], kd["wps_enabled"],
                          kd["wps_enabled_source"], kd["wps_enabled_confidence"]),
                         (["WPA2-PSK-CCMP"], "capabilities_string", 1, "capabilities_string", "med"))
        self.assertEqual((json.loads(pd["security_modes"]), pd["security_modes_source"]), (["WPA-PSK-TKIP"], "wpa_ie"))
        self.assertEqual(self.count("SELECT count(*) FROM sightings WHERE security_raw=?", f"221:{WPA_PSK_TKIP}"), 1)


class Behaviour(Built):
    def test_rssi_stats_and_sessions(self):
        a = "00:00:0C:00:00:06"
        p1 = self.ndjson([phone_row(a, "WIFI", rssi=-80, session_id="s1"), phone_row(a, "WIFI", rssi=-40, session_id="s1")])
        p2 = self.ndjson([phone_row(a, "WIFI", rssi=-50, session_id="s2")], name="q.ndjson")
        self.build(p1, p2)
        d = self.device(a, "wifi")
        self.assertEqual((d["rssi_max"], d["rssi_median"], d["sessions_seen"], d["sighting_count"]),
                         (-40, -50, 2, 3))


class Inputs(Built):
    def test_json_export_and_wiglecsv_rows_are_all_kept(self):
        j = self.path("e.json")
        with open(j, "w", encoding="utf-8") as f:
            json.dump([phone_row("00:00:0C:00:00:07", "WIFI"), phone_row("00:00:0C:00:00:08", "WIFI"), "oops"], f)
        good = wigle_row("00:00:0C:00:00:09")
        k = self.wigle([good, good[:5], good + ["extra"]])
        c = self.wigle([wigle_row("00:00:0C:00:00:0A")], name="other.csv")
        self.build(j, k, c)
        got = dict(self.conn.execute("SELECT source_format || ':' || coalesce(noise_reason,'clean'), count(*) "
                                     "FROM sightings GROUP BY 1").fetchall())
        self.assertEqual(got, {"swivel_json:clean": 2, "swivel_json:malformed_json": 1,
                               "wiglecsv:clean": 2, "wiglecsv:malformed_row": 2})
        long_raw = self.conn.execute("SELECT raw FROM sightings WHERE raw LIKE '%extra%'").fetchone()[0]
        self.assertEqual(json.loads(long_raw)[-1], "extra")                  # nothing cut from an over-long row

    def test_wiglecsv_without_header_stops_instead_of_eating_a_row(self):
        k = self.wigle([wigle_row("00:00:0C:00:00:0B")], header=None)
        with self.assertRaises(SystemExit):
            self.build(k)

    def test_byte_order_marks(self):
        j = self.path("b.json")
        with open(j, "w", encoding="utf-8") as f:
            f.write("﻿" + json.dumps([phone_row("00:00:0C:00:00:0C", "WIFI")]))
        self.build(self.ndjson([phone_row("00:00:0C:00:00:0D", "WIFI")], bom=True), j,
                   self.wigle([wigle_row("00:00:0C:00:00:0E")], bom=True))
        self.assertEqual(self.summary["noise_reason"], {"(clean)": 3})

    def test_garbage_typed_values_are_kept_not_fatal(self):
        lines = ['{"kind":"WIFI","mac":"00:00:0C:00:00:20","iso_time":"0001-01-01T00:00:00+14:00"}',
                 '{"kind":"BLE","mac":"47:00:00:00:00:21","iso_time":"2026-10-30T01:00:00-0400","rssi":1e999,'
                 '"ssid_or_name":{"x":1},"address_type":["random_rpa"],"manufacturer":5}',
                 '{"kind":"WIFI","mac":"00:00:0C:00:00:22","iso_time":"2026-10-30T01:00:00-0400",'
                 '"ssid_or_name":"bad\\ud800name","information_elements":123,"security":["x"],"lat":"NaN"}']
        self.build(self.ndjson([], raw_lines=lines))
        self.assertEqual(self.count("SELECT count(*) FROM sightings"), 3)
        self.assertEqual(self.summary["noise_reason"], {"(clean)": 2, "malformed_timestamp": 1})
        self.assertIsNone(self.conn.execute("SELECT rssi FROM sightings WHERE address='47:00:00:00:00:21'").fetchone()[0])

    def test_same_capture_twice_is_ingested_once(self):
        p = self.ndjson([phone_row("00:00:0C:00:00:23", "WIFI")])
        copy = self.path("copy.ndjson")
        shutil.copy(p, copy)
        self.build(p, p, copy)
        self.assertEqual(self.count("SELECT count(*) FROM sightings"), 1)
        self.assertEqual(self.summary["duplicate_inputs_skipped"], ["p.ndjson", "copy.ndjson"])


class Guards(Built):
    def test_sightings_immutable_and_devices_rebuildable(self):
        self.build(self.ndjson([phone_row("00:00:0C:00:00:30", "WIFI")]))
        with self.assertRaises(sqlite3.DatabaseError):
            self.conn.execute("UPDATE sightings SET rssi = 0")
        with self.assertRaises(sqlite3.DatabaseError):
            self.conn.execute("DELETE FROM sightings")
        first = [tuple(r) for r in self.conn.execute("SELECT * FROM devices ORDER BY address, radio")]
        se.derive(self.conn, se.Registry(REG))
        self.assertEqual([tuple(r) for r in self.conn.execute("SELECT * FROM devices ORDER BY address, radio")], first)

    def test_no_row_dropped_malformed_is_flagged(self):
        p = self.ndjson([phone_row("00:00:0C:00:00:31", "WIFI"), phone_row("not-a-mac", "WIFI"),
                         phone_row("00:00:0C:00:00:32", "LORA"), phone_row("00:00:0C:00:00:33", "WIFI", iso_time="soon")],
                        raw_lines=["{this is not json"])
        self.build(p)
        self.assertEqual(self.count("SELECT count(*) FROM sightings"), 5)
        self.assertEqual(self.summary["noise_reason"], {"(clean)": 1, "malformed_address": 1, "malformed_json": 1,
                                                        "malformed_timestamp": 1, "unknown_radio": 1})

    def test_refuses_to_write_over_an_input(self):
        p = self.ndjson([phone_row("00:00:0C:00:00:34", "WIFI")])
        k = self.wigle([wigle_row("00:00:0C:00:00:35")])
        with open(k, "rb") as f:
            before = f.read()
        link = self.path("linked.csv")
        os.link(k, link)                                           # a hard link is the same file under another name
        for db, out_csv in ((p, self.db + ".csv"), (self.db, k), (self.db, link)):
            with self.subTest(db=os.path.basename(db), csv=os.path.basename(out_csv)):
                with self.assertRaises(SystemExit):
                    se.run([p, k], db, out_csv, REG, "UTC")
        with open(k, "rb") as f:
            self.assertEqual(f.read(), before)

    def test_devices_csv_matches_the_table(self):
        cases = h.load_cases()
        self.build(*h.build_inputs(cases, self.path("in")), tz="UTC")
        with open(self.db + ".csv", encoding="utf-8", newline="") as f:
            rows = list(csv.reader(f))
        self.assertEqual(rows[0], se.DEVICE_COLS)
        self.assertEqual(len(rows) - 1, self.count("SELECT count(*) FROM devices"))

    def test_summary_prints_no_identifiers_or_coordinates(self):
        cases = h.load_cases()
        phone, kismet = h.build_inputs(cases, self.path("in"))
        proc = subprocess.run([sys.executable, "-I", h.NEW_TOOL, "run", phone, kismet, "--registry", REG,
                               "--db", self.db, "--naive-tz", "UTC"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("PASS", proc.stdout)
        with open(os.path.splitext(self.db)[0] + "_summary.txt", encoding="utf-8") as f:
            saved = f.read()
        needles = {str(h.FIXTURE_LAT), str(h.FIXTURE_LON), f"{h.FIXTURE_LAT:.4f}", f"{h.FIXTURE_LON:.4f}", "7.25"}
        for c in cases:
            for r in c["rows"]:
                needles |= {v for v in (r["mac"], r["mac"].replace(":", ""), r.get("ssid_or_name"), r.get("ssid")) if v}
        for out_name, text in (("stdout", proc.stdout + proc.stderr), ("summary file", saved)):
            self.assertEqual([n for n in needles if n in text], [], out_name)


class R3Guard(Built):
    def test_r3_check_catches_each_kind_of_violation(self):
        self.build(self.ndjson([phone_row("00:00:0C:00:00:50", "WIFI")]))
        ins = "INSERT INTO devices (address, radio, oui_vendor, is_randomized) VALUES (?, ?, ?, ?)"
        self.conn.execute(ins, ("47:00:00:00:00:51", "ble", "X", 1))
        self.conn.execute(ins, ("1A:2B:3C:00:00:52", "wifi", "X", 0))          # LAA by the address bit alone
        self.conn.execute(ins, ("D0:03:4B:00:00:53", "ble", None, 1))
        self.conn.execute(ins, ("D0:03:4B:00:00:53", "bt-classic", "X", 0))
        self.assertEqual(se.r3_check(self.conn), {"ble_with_oui_vendor": 1, "randomized_with_oui_vendor": 2,
                                                  "classic_also_ble_with_oui_vendor": 1})

    def test_run_exits_2_when_r3_fails(self):
        p = self.ndjson([phone_row("00:00:0C:00:00:54", "WIFI")])
        args = argparse.Namespace(files=[p], db=self.db, csv=None, registry=REG, naive_tz="UTC", min_sightings=0,
                                  cluster_distance=50.0, follow_distance=200.0, follow_min_span=300.0, kismet_window=60.0)
        with mock.patch.object(se, "r3_check", return_value={"ble_with_oui_vendor": 1}), \
             mock.patch("builtins.print"):
            self.assertEqual(se.cmd_run(args), 2)


class FetchChecks(unittest.TestCase):
    def test_bad_downloads_are_rejected(self):
        for rel, body in (("ieee/oui.csv", b"<html>Request Rejected</html>"), ("ieee/oui.csv", b"Registry,x\n"),
                          ("wireshark/manuf", b""), ("wireshark/manuf", b"maintenance"),
                          ("bluetooth-sig/company_identifiers.yaml", b"foo: 1"),
                          ("bluetooth-sig/company_identifiers.yaml", b"company_identifiers: []")):
            with self.subTest(rel=rel, body=body[:20]):
                with self.assertRaises(ValueError):
                    se.check_download(rel, body)

    @unittest.skipUnless(os.path.exists(os.path.join(se.DATA, "wireshark", "manuf")), "data/ not fetched")
    def test_real_downloads_pass(self):
        for rel, _, _ in se.SOURCES:
            with open(os.path.join(se.DATA, rel), "rb") as f:
                se.check_download(rel, f.read())


if __name__ == "__main__":
    unittest.main()
