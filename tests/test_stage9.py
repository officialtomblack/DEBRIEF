"""Stage 9: layer-3 IP collection. The SWIVEL app's active subnet sweep (kind SWEEP) and own-network record (kind SELF)
carry a dotted IPv4; the Kismet reader lifts observed client IPs out of an AP blob's dot11.device.client_map. All inputs
are synthetic (no real capture, no real address). Proves observed_ip fills, and that the phone's own IP never lands on
the joined AP's own row."""
import json, os, re, sys, types, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import swivel_enhance as se
from test_stage1 import Built, phone_row
from test_stage4 import make_kismet, EPOCH

# 192.168.1.50 packed low-byte-first, matching ipv4_from_u32's documented order (self-consistent with the decoder).
IP_U32 = 192 | (168 << 8) | (1 << 16) | (50 << 24)


class IpUnit(unittest.TestCase):
    def test_ipv4_from_u32_round_trips(self):
        self.assertEqual(se.ipv4_from_u32(IP_U32), "192.168.1.50")
        self.assertEqual(se.ipv4_from_u32(0), "0.0.0.0")
        self.assertIsNone(se.ipv4_from_u32("not-an-int"))

    def test_kismet_client_ips_helper(self):
        blob = json.dumps({"dot11.device": {"dot11.device.client_map": {
            "AA:BB:CC:00:09:11": {"dot11.client.ipdata": {"kismet.common.ipdata.type": 4, "kismet.common.ipdata.address": IP_U32}},
            "AA:BB:CC:00:09:12": {"dot11.client.ipdata": {"kismet.common.ipdata.type": 0, "kismet.common.ipdata.address": IP_U32}},  # type 0 (unknown) -> skipped
            "AA:BB:CC:00:09:13": {"dot11.client.ipdata": {"kismet.common.ipdata.type": 4, "kismet.common.ipdata.address": 0}},        # address 0 -> skipped
        }}})
        self.assertEqual(se.kismet_client_ips(blob), [("AA:BB:CC:00:09:11", "192.168.1.50", "kismet_dhcp")])
        self.assertEqual(se.kismet_client_ips(b"not json"), [])      # tolerant (R5)


class SweepAndSelf(Built):
    def test_sweep_fills_observed_ip(self):
        mac = "DC:A6:32:00:09:01"   # a swept LAN host, keyed by its real MAC (wifi)
        p = self.ndjson([phone_row(mac, "SWEEP", ip="10.0.0.23")], name="sweep.ndjson")
        self.build(p, tz="UTC")
        d = self.device(mac, "wifi")
        self.assertEqual((d["observed_ip"], d["observed_ip_source"], d["observed_ip_confidence"]),
                         ("10.0.0.23", "swivel_sweep", "high"))

    def test_self_record_never_contaminates_the_joined_ap(self):
        bssid = "E0:63:DA:00:09:02"   # the AP the phone is joined to: seen passively AND named in a SELF record
        p = self.ndjson([phone_row(bssid, "WIFI", ssid_or_name="HomeAP"),
                         phone_row(bssid, "SELF", ip="192.168.1.5", gateway_ip="192.168.1.1")], name="self.ndjson")
        self.build(p, tz="UTC")
        self.assertIsNone(self.device(bssid, "wifi")["observed_ip"])            # the AP's own row carries NO phone IP
        self.assertEqual(self.device(bssid, "self")["observed_ip"], "192.168.1.5")  # the phone's own IP lives on the isolated self row


class KismetClientIp(Built):
    def test_client_map_ip_becomes_a_device_observed_ip(self):
        ap = "F0:9F:C2:00:09:03"
        client = "AA:BB:CC:00:09:21"
        blob = json.dumps({"dot11.device": {"dot11.device.client_map": {
            client: {"dot11.client.ipdata": {"kismet.common.ipdata.type": 4, "kismet.common.ipdata.address": IP_U32}}}}}).encode()
        k = self.path("clients.kismet")
        make_kismet(k, [{"phyname": "IEEE802.11", "devmac": ap, "first_time": EPOCH, "type": "Wi-Fi AP", "device": blob}])
        self.build(k, tz="UTC")
        d = self.device(client, "wifi")                                         # the client is lifted out as its own wifi device
        self.assertEqual((d["observed_ip"], d["observed_ip_source"], d["observed_ip_confidence"]),
                         ("192.168.1.50", "kismet_dhcp", "high"))


class Report(Built):
    def test_report_structure_ranks_and_omits_coordinates(self):
        ap, host = "AA:BB:CC:00:09:31", "DC:A6:32:00:09:32"
        p = self.ndjson([phone_row(ap, "WIFI", ssid_or_name="Net", lat=45.1235, lon=-122.9235),
                         phone_row(host, "SWEEP", ip="10.0.0.9")], name="rep.ndjson")
        self.build(p, tz="UTC")
        out = self.path("r.html")
        se.cmd_report(types.SimpleNamespace(db=self.db, out=out, min_score=0))
        txt = open(out, encoding="utf-8").read()
        self.assertIn(ap, txt)
        self.assertIn(host, txt)
        self.assertIn("high-value devices", txt)
        self.assertIn("what the columns mean", txt)                      # legend answers "why each column"
        self.assertIn("swivel_sweep", txt)                              # per-device source/provenance is shown
        self.assertEqual(re.findall(r"[-]?\d{1,3}\.\d{4,}", txt), [])   # R1: no raw coordinates, despite a located device
        self.assertIn("coords omitted", txt)                            # the located device's cluster is summarized, not dumped

    def test_report_min_score_filters_everything_out(self):
        p = self.ndjson([phone_row("AA:BB:CC:00:09:33", "WIFI", ssid_or_name="Net")], name="rep2.ndjson")
        self.build(p, tz="UTC")
        out = self.path("r2.html")
        se.cmd_report(types.SimpleNamespace(db=self.db, out=out, min_score=999))
        self.assertEqual(open(out, encoding="utf-8").read().count('class="dev"'), 0)


if __name__ == "__main__":
    unittest.main()
