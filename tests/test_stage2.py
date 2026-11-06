"""Stage 2: coarse signatures (device_class / is_tracker), Wi-Fi fingerprint_hash, security_conflict, noise rules.
All inputs synthetic; registry fixture is tests/fixtures/registry; signatures are the real data/signatures.json."""
import json, os, subprocess, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import swivel_enhance as se
from test_stage1 import Built, phone_row, wigle_row, REG


def svc(uuid16):
    """16-bit UUID -> the 32-hex 128-bit base-form the phone logs."""
    return f"0000{uuid16:04X}{se.BASE_UUID_SUFFIX}"


def apple(*tlvs):
    """Apple 0x004C manufacturer-data hex from (type, value_hex) TLVs."""
    body = "".join(f"{t:02X}{len(bytes.fromhex(v)):02X}{v}" for t, v in tlvs)
    return "4C00" + body


class SignatureUnits(unittest.TestCase):
    def setUp(self):
        self.sigs = se.load_signatures()

    def test_uuid16_and_apple_tlv_extraction(self):
        self.assertEqual(se.uuid16s({"services": svc(0xFEED) + "," + svc(0xFD5A)}), {0xFEED, 0xFD5A})
        self.assertEqual(se.uuid16s({"service_data": {"0000feaa-0000-1000-8000-00805f9b34fb": "40"}}), {0xFEAA})
        self.assertEqual(se.uuid16s({"services": "4772911ed07c46178241f4d10948d6ae"}), set())   # custom 128-bit, no uuid16
        self.assertEqual(se.apple_tlv_types({"manufacturer": apple((0x12, "0000"), (0x10, "05"))}), {0x12, 0x10})
        self.assertEqual(se.apple_tlv_types({"manufacturer": "4C00121900"}), set())             # TLV says len 25, truncated
        self.assertEqual(se.apple_tlv_types({"manufacturer": "75000102"}), set())               # not Apple

    def test_malformed_adverts_never_crash(self):
        for rec in ({"service_data": ["not", "a", "dict"]}, {"service_data": "feed"}, {"service_data": 5},
                    {"services": 123}, {"manufacturer": ["4C00"]}, {"manufacturer": None, "services": None}):
            with self.subTest(rec=rec):
                self.assertEqual(se.uuid16s(rec), set())
                self.assertIsInstance(se.apple_tlv_types(rec), set)
                self.assertEqual(se.classify([rec], self.sigs), (None,) * 5)

    def test_classify_matches_and_misses(self):
        def cls(recs):
            return se.classify(recs, self.sigs)
        self.assertEqual(cls([{"manufacturer": apple((0x12, "0000"))}])[:3], ("location_tracker", 1, "apple_find_my"))
        self.assertEqual(cls([{"services": svc(0xFEED)}])[:3], ("location_tracker", 1, "tile"))
        self.assertEqual(cls([{"services": svc(0xFEEC)}])[2], "tile")
        self.assertEqual(cls([{"services": svc(0xFE33)}])[2], "chipolo")
        self.assertEqual(cls([{"services": svc(0xFD5A)}])[:3], ("location_tracker", 1, "samsung_smarttag"))
        self.assertEqual(cls([{"services": svc(0xFD5A)}])[4], "low")             # Samsung UUID is company-wide
        self.assertEqual(cls([{"manufacturer": apple((0x10, "05"))}]), (None,) * 5)   # Apple Nearby, not Find My: no class
        self.assertEqual(cls([{"manufacturer": "750001020304"}]), (None,) * 5)        # Samsung company ID alone: not a tracker
        self.assertEqual(cls([{"services": "", "manufacturer": ""}]), (None,) * 5)

    def test_classify_prefers_a_tracker_over_a_non_tracker_match(self):
        # a record matching both a non-tracker and a tracker signature -> tracker wins, both ids in the source
        sigs = [{"id": "demo_service", "_match": {"service_uuid16": 0xFEED}, "device_class": "demo",
                 "is_tracker": False, "tracker_type": None, "confidence": "low"},
                {"id": "demo_tracker", "_match": {"service_uuid16": 0xFEED}, "device_class": "location_tracker",
                 "is_tracker": True, "tracker_type": "demo", "confidence": "med"}]
        dc, trk, ttype, src, conf = se.classify([{"services": svc(0xFEED)}], sigs)
        self.assertEqual((dc, trk, ttype, conf), ("location_tracker", 1, "demo", "med"))
        self.assertEqual(src, "signatures.json:demo_service+demo_tracker")   # both listed, sorted


class Signatures(Built):
    def test_tracker_fields_and_source_contract(self):
        p = self.ndjson([
            phone_row("47:00:00:00:00:01", "BLE", address_type="random_rpa", manufacturer=apple((0x12, "0000"))),
            phone_row("48:00:00:00:00:02", "BLE", address_type="random_static", services=svc(0xFEED)),
            phone_row("49:00:00:00:00:03", "BLE", address_type="public", manufacturer="750001020304"),  # Samsung phone
        ])
        self.build(p)
        find_my, tile, samsung_phone = (self.device(a, "ble") for a in
                                        ("47:00:00:00:00:01", "48:00:00:00:00:02", "49:00:00:00:00:03"))
        self.assertEqual((find_my["device_class"], find_my["is_tracker"], find_my["tracker_type"]),
                         ("location_tracker", 1, "apple_find_my"))
        self.assertEqual(find_my["tracker_signature_source"], "signatures.json:apple_find_my")
        self.assertIsNone(find_my["oui_vendor"])                                     # still R3-strict on BLE
        self.assertEqual((tile["tracker_type"], tile["tracker_confidence"]), ("tile", "med"))
        self.assertIsNone(samsung_phone["device_class"])                            # Samsung company ID alone: not flagged
        self.assertIsNone(samsung_phone["is_tracker"])
        for d in (find_my, tile):                                                    # source/confidence contract
            self.assertIsNotNone(d["device_class_source"])
            self.assertIn(d["device_class_confidence"], ("high", "med", "low"))
            self.assertIsNotNone(d["tracker_signature_source"])

    def test_signatures_file_is_cited(self):
        for s in se.load_signatures():
            with self.subTest(sig=s["id"]):
                self.assertTrue(s["citations"], f"{s['id']} has no citation")
                for c in s["citations"]:
                    self.assertTrue(c["url"] and c["where"])


class Fingerprint(Built):
    def test_fingerprint_is_stable_and_distinguishes(self):
        ie_a = "0:41,48:0100,221:0050F208AABB"
        ie_b = "0:41,48:0100,221:00904C0899"
        a1 = "00:00:0C:00:00:10"
        p = self.ndjson([phone_row(a1, "WIFI", information_elements=ie_a),
                         phone_row(a1, "WIFI", information_elements=ie_a),                 # same AP, same IEs
                         phone_row("00:00:0C:00:00:11", "WIFI", information_elements=ie_b)])
        self.build(p)
        da, db = self.device(a1, "wifi"), self.device("00:00:0C:00:00:11", "wifi")
        self.assertEqual(da["fingerprint_hash"], se.wifi_fingerprint(ie_a))
        self.assertEqual((len(da["fingerprint_hash"]), da["fingerprint_hash_confidence"]), (16, "med"))
        self.assertNotEqual(da["fingerprint_hash"], db["fingerprint_hash"])
        self.assertIsNone(se.wifi_fingerprint(""))

    def test_fingerprint_confidence_drops_when_sightings_differ(self):
        a = "00:00:0C:00:00:12"
        p = self.ndjson([phone_row(a, "WIFI", information_elements="0:41,48:0100"),
                         phone_row(a, "WIFI", information_elements="0:41,48:0100,45:AABB")])
        self.build(p)
        self.assertEqual(self.device(a, "wifi")["fingerprint_hash_confidence"], "low")


class SecurityConflict(Built):
    def test_conflict_when_sightings_disagree(self):
        a = "00:00:0C:00:00:20"
        p = self.ndjson([phone_row(a, "WIFI", security="[WPA2-PSK-CCMP][ESS]"),
                         phone_row(a, "WIFI", security="[ESS]")])                          # open once, WPA2 once
        self.build(p)
        d = self.device(a, "wifi")
        self.assertEqual((d["security_conflict"], d["security_conflict_source"]), (1, "sighting_disagreement"))
        self.assertEqual(json.loads(d["security_modes"]), ["OPEN", "WPA2-PSK-CCMP"])

    def test_no_conflict_when_consistent(self):
        a = "00:00:0C:00:00:21"
        p = self.ndjson([phone_row(a, "WIFI", security="[WPA2-PSK-CCMP][ESS]"),
                         phone_row(a, "WIFI", security="[WPA2-PSK-CCMP][ESS]")])
        self.build(p)
        d = self.device(a, "wifi")
        self.assertEqual((d["security_conflict"], d["security_conflict_source"]), (0, "consistent_across_sightings"))


class Noise(Built):
    def test_zero_and_broadcast_address_flagged_and_vendor_withheld(self):
        p = self.ndjson([phone_row("00:00:00:00:00:00", "WIFI", information_elements="0:41"),
                         phone_row("FF:FF:FF:FF:FF:FF", "WIFI", information_elements="0:41")])
        self.build(p, min_sightings=0)
        self.assertEqual(self.summary["noise_reason"], {"zero_or_broadcast_address": 2})
        z = self.device("00:00:00:00:00:00", "wifi")
        self.assertIsNone(z["oui_vendor"])                                          # must NOT resolve to XEROX
        self.assertEqual(z["oui_vendor_source"], "withheld:zero_or_broadcast_address")

    def test_exact_duplicate_flagged_first_kept_none_dropped(self):
        row = phone_row("00:00:0C:00:00:30", "WIFI", information_elements="0:41", ssid_or_name="net")
        p = self.ndjson([dict(row), dict(row), dict(row)])                          # three identical adverts
        self.build(p, min_sightings=0)
        self.assertEqual(self.count("SELECT count(*) FROM sightings"), 3)           # R5: nothing dropped
        self.assertEqual(self.summary["noise_reason"], {"(clean)": 1, "duplicate_sighting": 2})

    def test_single_sighting_no_payload_threshold(self):
        lone = phone_row("00:00:0C:00:00:31", "WIFI")                               # one row, just a MAC
        named = phone_row("00:00:0C:00:00:32", "WIFI", ssid_or_name="has-name")     # one row, but has a name
        self.build(self.ndjson([lone, named]), min_sightings=1)
        self.assertEqual(self.summary["noise_reason"], {"(clean)": 1, "single_sighting_no_payload": 1})
        # same data, rule off: nothing flagged
        self.build(self.ndjson([lone, named], name="q.ndjson"), min_sightings=0)
        self.assertEqual(self.summary["noise_reason"], {"(clean)": 2})

    def test_lone_ble_advert_payload_is_not_noise(self):
        # a tracker seen once, advert payload but no name, must NOT be flagged single_sighting_no_payload
        rows = [phone_row("47:00:00:00:00:40", "BLE", address_type="random_rpa", manufacturer=apple((0x12, "0000"))),
                phone_row("48:00:00:00:00:41", "BLE", address_type="random_static", services=svc(0xFEED)),
                phone_row("49:00:00:00:00:42", "BLE", address_type="random_rpa")]   # no name, no payload -> flagged
        self.build(self.ndjson(rows), min_sightings=1)
        self.assertEqual(self.summary["noise_reason"], {"(clean)": 2, "single_sighting_no_payload": 1})
        self.assertIsNone(self.device("49:00:00:00:00:42", "ble")["device_class"])

    def test_min_sightings_default_is_wired_through_argv(self):
        # end-to-end through cmd_run/argparse: default must be 1 (flags the lone payloadless device), --min-sightings 0 clears it
        p = self.ndjson([phone_row("00:00:0C:00:00:43", "WIFI")])
        base = [sys.executable, "-I", os.path.join(os.path.dirname(HERE), "swivel_enhance.py"), "run", p,
                "--registry", REG, "--db", self.db, "--naive-tz", "UTC"]
        default = subprocess.run(base, capture_output=True, text=True)
        self.assertEqual(default.returncode, 0, default.stderr)
        self.assertIn("single_sighting_no_payload': 1", default.stdout)
        off = subprocess.run(base + ["--min-sightings", "0", "--fresh"], capture_output=True, text=True)
        self.assertIn("{'(clean)': 1}", off.stdout)

    def test_duplicate_key_discriminates_on_signal_and_payload(self):
        row = phone_row("00:00:0C:00:00:44", "WIFI", information_elements="0:41", ssid_or_name="n")
        same_ts = dict(row, rssi=-70)                       # identical except RSSI, same timestamp -> NOT a duplicate
        renamed = dict(row, ssid_or_name="n2")              # identical except name -> NOT a duplicate
        self.build(self.ndjson([row, same_ts, renamed]), min_sightings=0)
        self.assertEqual(self.summary["noise_reason"], {"(clean)": 3})

    def test_noisy_device_still_appears_in_devices(self):
        p = self.ndjson([phone_row("00:00:00:00:00:00", "WIFI")])
        self.build(p, min_sightings=0)
        self.assertIsNotNone(self.device("00:00:00:00:00:00", "wifi"))              # flagged, not dropped


if __name__ == "__main__":
    unittest.main()
