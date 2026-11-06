"""Stage 6: the sources.json manifest (toggles) and WiGLE AP geolocation — opt-in, manual, scoped to Wi-Fi AP BSSIDs
only (never client/BLE/randomized MACs, never GPS), cached offline and folded into devices by `run`. All synthetic;
wigle_lookup (the only network call) is always mocked, so nothing ever leaves the machine during tests."""
import argparse, json, os, shutil, sqlite3, sys, tempfile, unittest
import urllib.error
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import swivel_enhance as se

REG = os.path.join(HERE, "fixtures", "registry")
RSN_PSK = "0100000FAC040100000FAC040100000FAC020C00"


def phone_wifi(mac, ssid="", ies=""):
    return {"iso_time": "2026-10-30T01:00:00-0400", "session_id": "t", "kind": "WIFI", "mac": mac,
            "address_type": "", "ssid_or_name": ssid, "rssi": -60, "information_elements": ies}


def phone_ble(mac):
    return {"iso_time": "2026-10-30T01:00:00-0400", "session_id": "t", "kind": "BLE", "mac": mac,
            "address_type": "public", "ssid_or_name": "", "rssi": -60, "manufacturer": "4C001005"}


class Manifest(unittest.TestCase):
    def tmp(self, sources):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d)
        p = os.path.join(d, "sources.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"sources": sources}, f)
        return p

    def test_load_and_enabled(self):
        self.assertIsNone(se.load_sources("/no/such/file.json"))          # missing -> None (treated as "all enabled")
        p = self.tmp([{"id": "a", "kind": "offline_bulk", "enabled": True},
                      {"id": "b", "kind": "offline_bulk", "enabled": False}])
        self.assertEqual(se.enabled_sources(se.load_sources(p)), {"a"})
        self.assertIsNone(se.enabled_sources(None))                       # no manifest => everything enabled (offline-safe)

    def test_source_id_for(self):
        self.assertEqual(se.source_id_for("ieee/oui.csv"), "ieee_oui")
        self.assertEqual(se.source_id_for("wireshark/manuf"), "wireshark_manuf")
        self.assertEqual(se.source_id_for("bluetooth-sig/company_identifiers.yaml"), "bluetooth_sig")

    def test_shipped_manifest_is_safe_by_default(self):
        src = {s["id"]: s for s in se.load_sources()}                     # the real sources.json next to the tool
        # The real safety gate is NOT the enabled flag: `run` never calls any API — online lookups fire only when the user
        # explicitly invokes `wigle`/`beacondb`, and WiGLE additionally needs a token in the env (no token -> nothing sent).
        # So wigle_ap may ship enabled (maintainer's choice) as long as it stays online_lookup + token-gated. Offline bulk all on.
        self.assertEqual(src["wigle_ap"]["kind"], "online_lookup")
        self.assertEqual(src["wigle_ap"]["key_env"], "WIGLE_API_TOKEN")   # token-gated: enabled or not, no token means no request
        self.assertTrue(all(s["enabled"] for s in src.values() if s["kind"] == "offline_bulk"))


class RegistryTolerance(unittest.TestCase):
    def test_missing_sources_do_not_crash_the_run(self):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d)         # an empty registry dir
        reg = se.Registry(d)
        self.assertEqual(reg.vendor("00000C123456"), (None, None))        # no vendor table -> no match, no crash
        self.assertEqual((reg.company, reg.manuf, reg.wigle), ({}, {}, {}))
        self.assertTrue(reg.signatures)                                   # code-adjacent, always present


class ParseWigle(unittest.TestCase):
    def body(self, results):
        return json.dumps({"success": True, "results": results}).encode()

    def test_first_usable_result(self):
        self.assertEqual(se.parse_wigle(self.body([{"trilat": 40.5, "trilong": -74.1, "ssid": "home"}])),
                         {"lat": 40.5, "lon": -74.1, "ssid": "home"})
        self.assertEqual(se.parse_wigle(self.body([{"trilat": 40.5, "trilong": -74.1}])),
                         {"lat": 40.5, "lon": -74.1})                     # ssid optional

    def test_rejects_bad_coords_and_bodies(self):
        self.assertIsNone(se.parse_wigle(self.body([])))                  # no results
        self.assertIsNone(se.parse_wigle(self.body([{"trilat": None, "trilong": -74.0}])))
        self.assertIsNone(se.parse_wigle(b'{"results":[{"trilat":true,"trilong":1.0}]}'))   # bool is not a coord
        self.assertIsNone(se.parse_wigle(b'{"results":[{"trilat":NaN,"trilong":1.0}]}'))    # non-finite rejected
        self.assertIsNone(se.parse_wigle(b"not json at all"))
        self.assertIsNone(se.parse_wigle(b"[]"))                          # a list, not a dict


class Built(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="st6_")
        self.dir = self._tmp.name
        self.db = os.path.join(self.dir, "out", "t.db")
        self.addCleanup(self._tmp.cleanup)

    def run_build(self, rows, registry=REG):
        p = os.path.join(self.dir, "p.ndjson")
        with open(p, "w", encoding="utf-8") as f:
            f.writelines(json.dumps(r) + "\n" for r in rows)
        return se.run([p], self.db, self.db + ".csv", registry, "UTC", 0)

    def conn(self):
        c = sqlite3.connect(self.db); c.row_factory = sqlite3.Row
        self.addCleanup(c.close)
        return c

    def reg_with_cache(self, cache, name="reg"):
        d = os.path.join(self.dir, name)
        shutil.copytree(REG, d)
        os.makedirs(os.path.join(d, "wigle"))
        with open(os.path.join(d, se.WIGLE_PATH), "w", encoding="utf-8") as f:
            json.dump(cache, f)
        return d


class ScopeGuard(Built):
    def test_phone_aps_selected_randomized_and_ble_excluded(self):
        self.run_build([phone_wifi("00:00:0C:00:00:01", ssid="apnet", ies=f"48:{RSN_PSK}"),   # phone AP -> selected
                        phone_wifi("00:00:0C:00:00:02"),                       # bare/hidden phone AP -> also selected
                        phone_wifi("02:00:0C:00:00:03", ssid="laa", ies=f"48:{RSN_PSK}"),      # LAA/randomized -> excluded
                        phone_ble("D0:03:4B:00:00:04")])                       # BLE -> excluded (not wifi)
        c = self.conn()
        self.assertEqual(set(se.ap_bssids_to_lookup(c, {})), {"00:00:0C:00:00:01", "00:00:0C:00:00:02"})
        self.assertEqual(se.ap_bssids_to_lookup(c, {"00:00:0C:00:00:01": {}, "00:00:0C:00:00:02": {}}), [])  # cached -> skip

    def test_guard_never_sends_a_client_or_kismet_only_mac(self):
        """Pins the R2 invariant directly: only a phone-seen, non-randomized Wi-Fi address is eligible. A device with a
        name or security but NOT seen by the phone (a future probe-request client, or a Kismet-only row) is never sent —
        so no future ingester can reintroduce a client-MAC leak by populating device_name/IEs."""
        con = sqlite3.connect(":memory:"); con.row_factory = sqlite3.Row
        self.addCleanup(con.close)
        con.executescript(se.SCHEMA)

        def dev(**kw):
            row = dict.fromkeys(se.DEVICE_COLS); row.update(radio="wifi", **kw)
            con.execute(f"INSERT INTO devices VALUES ({','.join('?' * len(se.DEVICE_COLS))})", [row[c] for c in se.DEVICE_COLS])
        dev(address="00:00:0C:00:00:01", is_randomized=0, seen_by_phone=1, security_modes='["WPA2-PSK-CCMP"]')  # phone AP
        dev(address="00:00:0C:00:00:02", is_randomized=0, seen_by_phone=1)                                      # bare phone AP
        dev(address="00:00:0C:00:00:03", is_randomized=0, seen_by_phone=0, device_name="HOME_WIFI")             # probe client
        dev(address="00:00:0C:00:00:04", is_randomized=0, seen_by_phone=0, security_modes='["OPEN"]')           # kismet-only AP
        dev(address="02:00:0C:00:00:05", is_randomized=1, seen_by_phone=1, security_modes='["OPEN"]')           # randomized/LAA
        self.assertEqual(set(se.ap_bssids_to_lookup(con, {})), {"00:00:0C:00:00:01", "00:00:0C:00:00:02"})


class Fold(Built):
    def test_cache_folds_into_the_wifi_ap_only(self):
        self.run_build([phone_wifi("00:00:0C:00:00:01", ssid="apnet", ies=f"48:{RSN_PSK}"),
                        phone_ble("D0:03:4B:00:00:04")])
        reg = self.reg_with_cache({"00:00:0C:00:00:01": {"found": True, "lat": 40.5, "lon": -74.1, "ssid": "apnet"},
                                   "D0:03:4B:00:00:04": {"found": True, "lat": 1.0, "lon": 2.0},   # BLE addr: never applied
                                   "00:00:0C:00:00:09": {"found": False}})                         # not in DB: ignored
        c = self.conn()
        se.derive(c, se.Registry(reg))
        ap = c.execute("SELECT wigle_location, wigle_location_source, wigle_location_confidence FROM devices "
                       "WHERE address='00:00:0C:00:00:01' AND radio='wifi'").fetchone()
        self.assertEqual((json.loads(ap[0]), ap[1], ap[2]),
                         ({"lat": 40.5, "lon": -74.1, "ssid": "apnet"}, "wigle_api", "med"))
        self.assertIsNone(c.execute("SELECT wigle_location FROM devices WHERE radio='ble'").fetchone()[0])  # wifi-only fold

    def test_registry_skips_notfound_and_bad_coord_entries(self):
        reg = self.reg_with_cache({"AA": {"found": False, "lat": 1.0, "lon": 2.0},
                                   "BB": {"found": True, "lat": None, "lon": 2.0},
                                   "CC": {"found": True, "lat": 1.0, "lon": 2.0}}, name="reg2")
        self.assertEqual(set(se.Registry(reg).wigle), {"CC"})


class CmdWigle(Built):
    ENV = "WIGLE_TEST_TOKEN"

    def args(self, **kw):
        base = dict(db=self.db, sources=None, registry=self.dir, max=100, dry_run=False)
        base.update(kw)
        return argparse.Namespace(**base)

    def manifest(self, enabled):
        p = os.path.join(self.dir, "sources.json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"sources": [{"id": "wigle_ap", "kind": "online_lookup", "enabled": enabled, "key_env": self.ENV,
                                    "endpoint": "https://api.wigle.net/api/v2/network/search"}]}, f)
        return p

    def set_token(self):
        os.environ[self.ENV] = "x"
        self.addCleanup(lambda: os.environ.pop(self.ENV, None))

    def test_disabled_source_sends_nothing(self):
        with mock.patch.object(se, "wigle_lookup", side_effect=AssertionError("must not call")), mock.patch("builtins.print"):
            self.assertEqual(se.cmd_wigle(self.args(sources=self.manifest(False))), 0)

    def test_missing_key_sends_nothing(self):
        os.environ.pop(self.ENV, None)
        with mock.patch.object(se, "wigle_lookup", side_effect=AssertionError("must not call")), mock.patch("builtins.print"):
            self.assertEqual(se.cmd_wigle(self.args(sources=self.manifest(True))), 0)

    def test_queries_only_scoped_aps_and_caches(self):
        self.run_build([phone_wifi("00:00:0C:00:00:01", ssid="apnet", ies=f"48:{RSN_PSK}"),
                        phone_wifi("02:00:0C:00:00:03", ssid="laa", ies=f"48:{RSN_PSK}"),   # randomized/LAA -> never queried
                        phone_ble("D0:03:4B:00:00:04")])                                    # BLE -> never queried
        self.set_token()
        sent = []

        def fake(token, netid, endpoint, timeout=30):
            sent.append(netid)
            return json.dumps({"results": [{"trilat": 40.5, "trilong": -74.1, "ssid": "apnet"}]}).encode()
        with mock.patch.object(se, "wigle_lookup", side_effect=fake), mock.patch("builtins.print"):
            self.assertEqual(se.cmd_wigle(self.args(sources=self.manifest(True))), 0)
        self.assertEqual(sent, ["00:00:0C:00:00:01"])               # only the clean AP's BSSID left the machine
        cache = json.load(open(os.path.join(self.dir, se.WIGLE_PATH)))
        self.assertEqual(cache["00:00:0C:00:00:01"]["found"], True)
        self.assertEqual((cache["00:00:0C:00:00:01"]["lat"], cache["00:00:0C:00:00:01"]["lon"]), (40.5, -74.1))

    def test_dry_run_sends_nothing(self):
        self.run_build([phone_wifi("00:00:0C:00:00:01", ssid="apnet", ies=f"48:{RSN_PSK}")])
        self.set_token()
        with mock.patch.object(se, "wigle_lookup", side_effect=AssertionError("must not call")), mock.patch("builtins.print"):
            self.assertEqual(se.cmd_wigle(self.args(sources=self.manifest(True), dry_run=True)), 0)
        self.assertFalse(os.path.exists(os.path.join(self.dir, se.WIGLE_PATH)))

    def test_max_caps_queries(self):
        self.run_build([phone_wifi(f"00:00:0C:00:00:0{i}", ssid="a", ies=f"48:{RSN_PSK}") for i in (1, 2, 3)])
        self.set_token()
        n = []
        with mock.patch.object(se, "wigle_lookup", side_effect=lambda *a, **k: n.append(1) or b'{"results":[]}'), \
             mock.patch("builtins.print"):
            se.cmd_wigle(self.args(sources=self.manifest(True), max=2))
        self.assertEqual(len(n), 2)

    def test_rate_limit_stops_cleanly_and_keeps_cache(self):
        self.run_build([phone_wifi("00:00:0C:00:00:01", ssid="a", ies=f"48:{RSN_PSK}"),
                        phone_wifi("00:00:0C:00:00:05", ssid="b", ies=f"48:{RSN_PSK}")])
        self.set_token()
        calls = []

        def fake(token, netid, endpoint, timeout=30):
            calls.append(netid)
            if len(calls) == 1:
                return json.dumps({"results": [{"trilat": 1.0, "trilong": 2.0}]}).encode()
            raise urllib.error.HTTPError(endpoint, 429, "too many", None, None)
        with mock.patch.object(se, "wigle_lookup", side_effect=fake), mock.patch("builtins.print"):
            self.assertEqual(se.cmd_wigle(self.args(sources=self.manifest(True))), 0)
        self.assertEqual(len(calls), 2)                              # stopped at the 429, didn't keep hammering
        self.assertEqual(len(json.load(open(os.path.join(self.dir, se.WIGLE_PATH)))), 1)   # the one success persisted


class R1(Built):
    def test_summary_prints_the_count_never_the_coordinates(self):
        reg = self.reg_with_cache({"00:00:0C:00:00:01": {"found": True, "lat": 40.123456, "lon": -74.654321}})
        summary = self.run_build([phone_wifi("00:00:0C:00:00:01", ssid="apnet", ies=f"48:{RSN_PSK}")], registry=reg)
        text = se.format_summary(summary)
        self.assertIn("1 device(s) matched", text)
        for needle in ("40.123456", "40.1234", "-74.654321", "-74.6543"):
            self.assertNotIn(needle, text)


class BeaconDB(unittest.TestCase):
    def test_parse_drops_ip_fallback(self):
        real = b'{"location":{"lat":45.1,"lng":-122.9},"accuracy":40}'
        self.assertEqual(se.parse_beacondb(real), {"lat": 45.1, "lon": -122.9})   # real AP fix -> lng mapped to lon
        fb = b'{"accuracy":25000,"fallback":"ipf","location":{"lat":40.7,"lng":-74.0}}'
        self.assertIsNone(se.parse_beacondb(fb))          # IP guess of OUR location -> dropped (R1/R2)
        self.assertIsNone(se.parse_beacondb(b"not json"))
        self.assertIsNone(se.parse_beacondb(b'{"accuracy":1}'))   # no location key


if __name__ == "__main__":
    unittest.main()
