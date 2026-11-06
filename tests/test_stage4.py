"""Stage 4: Kismet native .kismet reader, phone<->Kismet time-window matching (seen_by_both_within_window),
kismet_ids_alerts. The .kismet fixture is built at test time on Kismet's real schema
(kis_databaselogfile.cc); it is SYNTHETIC — no real capture. Nothing under logs/ or out/ is touched."""
import datetime as dt, gzip, hashlib, json, os, sqlite3, sys, unittest, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import swivel_enhance as se
from test_stage1 import Built, phone_row, REG

EPOCH = 1_762_000_000                                     # fixed base time (UTC); no Date.now in tests


def iso(epoch):
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


# Kismet's real devices/alerts DDL (kis_databaselogfile.cc). Subsets are inserted by column name; the rest default NULL.
DEVICES_DDL = ("CREATE TABLE devices (first_time INT, last_time INT, devkey TEXT, phyname TEXT, devmac TEXT, "
               "strongest_signal INT, min_lat REAL, min_lon REAL, max_lat REAL, max_lon REAL, avg_lat REAL, avg_lon REAL, "
               "reported_min_lat REAL, reported_min_lon REAL, reported_max_lat REAL, reported_max_lon REAL, "
               "reported_avg_lat REAL, reported_avg_lon REAL, bytes_data INT, type TEXT, device BLOB, "
               "UNIQUE(phyname, devmac) ON CONFLICT REPLACE)")
ALERTS_DDL = ("CREATE TABLE alerts (ts_sec INT, ts_usec INT, phyname TEXT, devmac TEXT, lat REAL, lon REAL, "
              "header TEXT, json BLOB)")


def make_kismet(path, devices, alerts=(), with_alerts_table=True):
    """devices: list of dicts (phyname, devmac, first_time, last_time, signal, lat, lon, type, bytes). alerts: (phyname,
    devmac, ts_sec, header)."""
    if os.path.exists(path):                             # a test may rebuild the same fixture path
        os.remove(path)
    con = sqlite3.connect(path)
    try:
        con.execute(DEVICES_DDL)
        if with_alerts_table:
            con.execute(ALERTS_DDL)
        for d in devices:
            con.execute("INSERT INTO devices (first_time,last_time,devkey,phyname,devmac,strongest_signal,avg_lat,"
                        "avg_lon,bytes_data,type,device) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (d["first_time"], d.get("last_time", d["first_time"]), d["devmac"], d["phyname"], d["devmac"],
                         d.get("signal", -55), d.get("lat", 0.0), d.get("lon", 0.0), d.get("bytes", 0),
                         d.get("type", "Wi-Fi AP"), d.get("device", b"{}")))
        for a in alerts:
            con.execute("INSERT INTO alerts (ts_sec,ts_usec,phyname,devmac,lat,lon,header,json) VALUES (?,?,?,?,?,?,?,?)",
                        (a[2], 0, a[0], a[1], 0.0, 0.0, a[3], b"{}"))
        con.commit()
    finally:
        con.close()


class Reader(Built):
    def kismet(self, devices, alerts=(), name="synthetic.kismet", **kw):
        p = self.path(name)
        make_kismet(p, devices, alerts, **kw)
        return p

    def test_reads_devices_flat_columns(self):
        wifi = "AA:BB:CC:00:04:01"
        ble = "AA:BB:CC:00:04:02"
        nofix = "AA:BB:CC:00:04:03"
        k = self.kismet([
            {"phyname": "IEEE802.11", "devmac": wifi, "first_time": EPOCH, "last_time": EPOCH + 600, "signal": -42,
             "lat": 40.0, "lon": -75.0, "type": "Wi-Fi AP", "bytes": 1234},
            {"phyname": "BTLE", "devmac": ble, "first_time": EPOCH, "signal": 0, "type": "BTLE"},   # signal 0 -> None
            {"phyname": "IEEE802.11", "devmac": nofix, "first_time": EPOCH, "lat": 0.0, "lon": 0.0},   # 0,0 -> no fix
        ])
        self.build(k, tz="UTC")
        w = self.device(wifi, "wifi")
        self.assertEqual((w["seen_by_kismet"], w["seen_by_phone"]), (1, 0))
        self.assertEqual((w["first_seen"], w["first_seen_source"]), (se.epoch_utc(EPOCH)[0], "utc:kismet_db"))
        self.assertEqual((w["rssi_max"], w["sighting_count"]), (-42, 1))
        self.assertEqual(self.device(ble, "ble")["rssi_max"], None)                 # Kismet signal 0 means "unset"
        self.assertEqual(json.loads(self.device(nofix, "wifi")["location_clusters"] or "null"), None)   # 0,0 dropped
        self.assertIsNone(self.device(nofix, "wifi")["location_clusters"])

    def test_probed_ssids_helper(self):
        j = {"dot11.device": {"dot11.device.probed_ssid_map": [
            {"dot11.probedssid.ssid": "A"}, {"dot11.probedssid.ssid": ""}, {"x": 1}]}}
        s = json.dumps(j)
        self.assertEqual(se.kismet_probed_ssids(s), ["A"])                           # plain str blob
        self.assertEqual(se.kismet_probed_ssids(s.encode()), ["A"])                  # plain bytes blob
        self.assertEqual(se.kismet_probed_ssids(zlib.compress(s.encode())), ["A"])   # zlib-compressed blob
        self.assertEqual(se.kismet_probed_ssids(gzip.compress(s.encode())), ["A"])   # gzip-compressed blob
        self.assertEqual(se.kismet_probed_ssids(b"not json"), [])                    # undecodable -> []
        self.assertEqual(se.kismet_probed_ssids(None), [])
        self.assertEqual(se.kismet_probed_ssids(b"{}"), [])                          # no probe map -> []

    def test_probed_ssids_from_device_blob(self):
        mac = "AA:BB:CC:00:04:20"
        blob = json.dumps({"dot11.device": {"dot11.device.probed_ssid_map": [
            {"dot11.probedssid.ssid": "HomeNet"}, {"dot11.probedssid.ssid": "attwifi"},
            {"dot11.probedssid.ssid": ""}]}}).encode()                               # "" wildcard probe -> skipped
        k = self.kismet([{"phyname": "IEEE802.11", "devmac": mac, "first_time": EPOCH, "device": blob}])
        self.build(k, tz="UTC")
        self.assertEqual(json.loads(self.device(mac, "wifi")["probed_ssids"]), ["HomeNet", "attwifi"])

    def test_advertised_ssids_helper(self):
        j = {"dot11.device": {"dot11.device.advertised_ssid_map": [
            {"dot11.advertisedssid.ssid": "HomeAP", "dot11.advertisedssid.crypt_string": "WPA2-PSK-CCMP",
             "dot11.advertisedssid.wps_manuf": "FixtureCo", "dot11.advertisedssid.wps_model_name": "FX-1",
             "dot11.advertisedssid.wps_model_number": "100", "dot11.advertisedssid.wps_serial_number": "SN1",
             "dot11.advertisedssid.cloaked": 0},
            {"dot11.advertisedssid.ssid": "", "dot11.advertisedssid.cloaked": 1}]}}       # hidden, not yet revealed
        s = json.dumps(j)
        out = se.kismet_advertised_ssids(s)
        self.assertEqual((out[0]["ssid"], out[0]["crypt"], out[0]["cloaked"]), ("HomeAP", "WPA2-PSK-CCMP", False))
        self.assertEqual(out[0]["wps"], {"make": "FixtureCo", "model": "FX-1 (100)", "serial": "SN1"})
        self.assertEqual((out[1]["ssid"], out[1]["cloaked"]), ("", True))
        self.assertEqual(se.kismet_advertised_ssids(zlib.compress(s.encode()))[0]["ssid"], "HomeAP")   # compressed blob
        self.assertEqual(se.kismet_advertised_ssids(b"not json"), [])                     # undecodable -> []
        self.assertEqual(se.kismet_advertised_ssids(b"{}"), [])                           # no advertised map -> []

    def test_advertised_ssid_fills_name_and_wps_for_kismet_ap(self):
        mac = "AA:BB:CC:00:04:30"
        blob = json.dumps({"dot11.device": {"dot11.device.advertised_ssid_map": [
            {"dot11.advertisedssid.ssid": "KismetAP", "dot11.advertisedssid.wps_manuf": "AcmeNet",
             "dot11.advertisedssid.wps_model_name": "RT-1", "dot11.advertisedssid.wps_serial_number": "SN9"}]}}).encode()
        k = self.kismet([{"phyname": "IEEE802.11", "devmac": mac, "first_time": EPOCH, "device": blob}])
        self.build(k, tz="UTC")
        d = self.device(mac, "wifi")                                                      # a Kismet-only AP, never seen by phone
        self.assertEqual((d["device_name"], d["device_name_source"]), ("KismetAP", "ssid"))
        self.assertEqual((json.loads(d["wps_make"]), d["wps_make_source"]), (["AcmeNet"], "kismet_advertised_ssid"))
        self.assertEqual((json.loads(d["wps_model"]), json.loads(d["wps_serial"])), (["RT-1"], ["SN9"]))

    def test_unknown_phy_is_flagged_not_dropped(self):
        k = self.kismet([{"phyname": "RTL433", "devmac": "AA:BB:CC:00:04:10", "first_time": EPOCH}])
        self.build(k, tz="UTC")
        self.assertEqual(self.count("SELECT count(*) FROM sightings"), 1)           # R5: kept
        self.assertEqual(self.summary["noise_reason"], {"unknown_radio": 1})

    def test_not_a_kismet_db_exits(self):
        p = self.path("bogus.kismet")
        con = sqlite3.connect(p)                                                     # a SQLite file with no devices table
        con.execute("CREATE TABLE something (x INT)"); con.commit(); con.close()
        with self.assertRaises(SystemExit):
            self.build(p, tz="UTC")

    def test_missing_alerts_table_is_fine(self):
        k = self.kismet([{"phyname": "IEEE802.11", "devmac": "AA:BB:CC:00:04:11", "first_time": EPOCH}],
                        with_alerts_table=False)
        self.build(k, tz="UTC")
        self.assertEqual(self.device("AA:BB:CC:00:04:11", "wifi")["seen_by_kismet"], 1)

    def test_capture_not_modified_and_no_sidecar_files(self):
        k = self.kismet([{"phyname": "IEEE802.11", "devmac": "AA:BB:CC:00:04:12", "first_time": EPOCH}])
        sha = lambda f: hashlib.sha256(__import__("pathlib").Path(f).read_bytes()).hexdigest()
        before = sha(k)
        self.build(k, tz="UTC")                                                      # read immutably (R4)
        self.assertEqual(sha(k), before)
        for sidecar in (k + "-wal", k + "-shm", k + "-journal"):
            self.assertFalse(os.path.exists(sidecar), sidecar)

    def test_schema_drift_missing_optional_columns_still_reads(self):
        # an older/other-version Kismet whose devices table lacks strongest_signal/type/bytes_data: read it anyway
        p = self.path("drift.kismet")
        con = sqlite3.connect(p)
        con.execute("CREATE TABLE devices (first_time INT, last_time INT, devkey TEXT, phyname TEXT, devmac TEXT, "
                    "avg_lat REAL, avg_lon REAL, device BLOB)")
        con.execute("INSERT INTO devices (first_time,devkey,phyname,devmac,avg_lat,avg_lon,device) VALUES (?,?,?,?,?,?,?)",
                    (EPOCH, "k", "IEEE802.11", "AA:BB:CC:00:04:50", 0.0, 0.0, b"{}"))
        con.commit(); con.close()
        self.build(p, tz="UTC")
        d = self.device("AA:BB:CC:00:04:50", "wifi")
        self.assertEqual((d["seen_by_kismet"], d["rssi_max"]), (1, None))

    def test_corrupt_file_exits_cleanly_not_traceback(self):
        p = self.path("corrupt.kismet")
        with open(p, "wb") as f:
            f.write(b"this is not a sqlite database" * 20)
        with self.assertRaises(SystemExit):                                          # clean exit, not an uncaught DatabaseError
            self.build(p, tz="UTC")

    def test_null_first_time_not_counted_as_filled(self):
        k = self.kismet([{"phyname": "IEEE802.11", "devmac": "AA:BB:CC:00:04:51", "first_time": None}])
        self.build(k, tz="UTC")
        self.assertEqual(self.summary["noise_reason"], {"malformed_timestamp": 1})
        self.assertEqual(self.summary["filled"]["first_seen"], (0, 0))               # a NULL first_time must not inflate 'before'


class CrossCheck(Built):
    def both(self, phone_iso, k_first, k_last, mac="AA:BB:CC:00:04:20"):
        p = self.ndjson([phone_row(mac, "WIFI", iso_time=phone_iso)])
        k = self.path("x.kismet")
        make_kismet(k, [{"phyname": "IEEE802.11", "devmac": mac, "first_time": k_first, "last_time": k_last}])
        self.build(p, k, tz="UTC")
        return self.device(mac, "wifi")

    def test_seen_by_phone_kismet_both(self):
        phone_only = "AA:BB:CC:00:04:21"
        kismet_only = "AA:BB:CC:00:04:22"
        both = "AA:BB:CC:00:04:23"
        p = self.ndjson([phone_row(phone_only, "WIFI", iso_time=iso(EPOCH)),
                         phone_row(both, "WIFI", iso_time=iso(EPOCH + 100))])
        k = self.path("c.kismet")
        make_kismet(k, [{"phyname": "IEEE802.11", "devmac": kismet_only, "first_time": EPOCH},
                        {"phyname": "IEEE802.11", "devmac": both, "first_time": EPOCH, "last_time": EPOCH + 200}])
        self.build(p, k, tz="UTC")
        self.assertEqual((self.device(phone_only, "wifi")["seen_by_phone"], self.device(phone_only, "wifi")["seen_by_kismet"]), (1, 0))
        self.assertEqual((self.device(kismet_only, "wifi")["seen_by_phone"], self.device(kismet_only, "wifi")["seen_by_kismet"]), (0, 1))
        b = self.device(both, "wifi")
        self.assertEqual((b["seen_by_phone"], b["seen_by_kismet"], b["seen_by_both_within_window"]), (1, 1, 1))
        self.assertEqual(self.summary["seen_by"], {"phone": 2, "kismet": 2, "both": 1})

    def test_window_match_inside_and_outside(self):
        inside = self.both(iso(EPOCH + 300), EPOCH, EPOCH + 600)         # phone mid-interval
        self.assertEqual((inside["seen_by_both_within_window"], inside["seen_by_both_within_window_confidence"]), (1, "high"))
        self.assertEqual(inside["seen_by_both_within_window_source"], "kismet_window_60s")
        outside = self.both(iso(EPOCH + 100_000), EPOCH, EPOCH + 600)    # phone hours later: same MAC, not co-present
        self.assertEqual((outside["seen_by_kismet"], outside["seen_by_both_within_window"], outside["seen_by_both_within_window_confidence"]),
                         (1, 0, "low"))

    def test_window_boundary_is_inclusive_and_tunable(self):
        at = self.both(iso(EPOCH + 660), EPOCH, EPOCH + 600)             # exactly last_time + 60 s window -> inclusive match
        self.assertEqual(at["seen_by_both_within_window"], 1)
        just_over = self.both(iso(EPOCH + 661), EPOCH, EPOCH + 600)      # 1 s past the window -> no match
        self.assertEqual(just_over["seen_by_both_within_window"], 0)
        se.derive(self.conn, se.Registry(REG), kismet_window=120.0)      # same data, wider knob -> match
        self.assertEqual(self.device("AA:BB:CC:00:04:20", "wifi")["seen_by_both_within_window"], 1)

    def test_only_one_source_leaves_window_null(self):
        k = self.path("k.kismet")
        make_kismet(k, [{"phyname": "IEEE802.11", "devmac": "AA:BB:CC:00:04:24", "first_time": EPOCH}])
        self.build(k, tz="UTC")
        self.assertIsNone(self.device("AA:BB:CC:00:04:24", "wifi")["seen_by_both_within_window"])   # Kismet-only: N/A

    def test_absurd_last_time_does_not_fake_copresence(self):
        # a corrupt capture with a garbage last_time must not stretch the co-presence window to "always"
        mac = "AA:BB:CC:00:04:25"
        p = self.ndjson([phone_row(mac, "WIFI", iso_time=iso(EPOCH + 10_000))])      # hours after the real interval
        k = self.path("absurd.kismet")
        make_kismet(k, [{"phyname": "IEEE802.11", "devmac": mac, "first_time": EPOCH, "last_time": 10 ** 18}])
        self.build(p, k, tz="UTC")
        self.assertEqual(self.device(mac, "wifi")["seen_by_both_within_window"], 0)


class Alerts(Built):
    def test_ids_alerts_merged_by_devmac(self):
        tagged = "AA:BB:CC:00:04:30"
        clean = "AA:BB:CC:00:04:31"
        k = self.path("a.kismet")
        make_kismet(k, [{"phyname": "IEEE802.11", "devmac": tagged, "first_time": EPOCH},
                        {"phyname": "IEEE802.11", "devmac": clean, "first_time": EPOCH}],
                    alerts=[("IEEE802.11", tagged, EPOCH, "APSPOOF"), ("IEEE802.11", tagged, EPOCH + 5, "DEAUTHFLOOD")])
        self.build(k, tz="UTC")
        t = self.device(tagged, "wifi")
        self.assertEqual(json.loads(t["kismet_ids_alerts"]), ["APSPOOF", "DEAUTHFLOOD"])   # sorted, deduped by set
        self.assertEqual((t["kismet_ids_alerts_source"], t["kismet_ids_alerts_confidence"]), ("kismet_db_alerts", "high"))
        self.assertIsNone(self.device(clean, "wifi")["kismet_ids_alerts"])
        self.assertEqual(self.summary["ids_alert_devices"], 1)

    def test_alert_matched_by_radio_not_just_mac(self):
        # a dual-mode device shares one MAC across Wi-Fi and BTLE; a BTLE alert must tag only the ble row
        mac = "AA:BB:CC:00:04:32"
        k = self.path("dual.kismet")
        make_kismet(k, [{"phyname": "IEEE802.11", "devmac": mac, "first_time": EPOCH},
                        {"phyname": "BTLE", "devmac": mac, "first_time": EPOCH}],
                    alerts=[("BTLE", mac, EPOCH, "BTLE_ANOMALY")])
        self.build(k, tz="UTC")
        self.assertEqual(json.loads(self.device(mac, "ble")["kismet_ids_alerts"]), ["BTLE_ANOMALY"])
        self.assertIsNone(self.device(mac, "wifi")["kismet_ids_alerts"])             # not mis-attributed across radios
        self.assertEqual(self.summary["ids_alert_devices"], 1)


if __name__ == "__main__":
    unittest.main()
