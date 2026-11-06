"""Stage 7: cumulative ingest (append by content hash + fresh=True), the dead-row drop (info_score / noise_reason and
keep_noise), and device_cluster_id clustering of rotating random Wi-Fi client MACs. Synthetic inputs, real tiny registry."""
import json, os, sqlite3, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import swivel_enhance as se

REG = os.path.join(HERE, "fixtures", "registry")


def phone_row(mac, kind, **kw):
    row = {"iso_time": "2026-10-30T01:00:00-0400", "session_id": "t", "source": "PHONE", "kind": kind, "mac": mac,
           "address_type": "", "vendor": "", "ssid_or_name": "", "rssi": -60}
    row.update(kw)
    return row


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="st7_")
        self.dir = self._tmp.name
        self.db = os.path.join(self.dir, "out", "t.db")
        self.addCleanup(self._tmp.cleanup)

    def ndjson(self, rows, name):
        p = os.path.join(self.dir, name)
        with open(p, "w", encoding="utf-8") as f:
            f.writelines(json.dumps(r) + "\n" for r in rows)
        return p

    def run_(self, *paths, keep_noise=False, fresh=False, min_sightings=0):
        return se.run(list(paths), self.db, self.db + ".csv", REG, "UTC", min_sightings,
                      keep_noise=keep_noise, fresh=fresh)

    def conn(self):
        c = sqlite3.connect(self.db)
        c.row_factory = sqlite3.Row
        self.addCleanup(c.close)
        return c

    def sight_count(self, addr):
        return self.conn().execute("SELECT sighting_count FROM devices WHERE address=?", (addr,)).fetchone()[0]


class DeadDrop(Base):
    DEAD = "22:33:44:55:66:77"    # LAA bit set -> randomized; BLE with no name/manufacturer -> no identity, no handle
    GOOD = "00:00:0C:11:22:33"    # Cisco OUI, public wifi AP -> has a vendor -> real identity

    def test_dead_dropped_by_default_good_kept(self):
        p = self.ndjson([phone_row(self.DEAD, "BLE", address_type="random"),
                         phone_row(self.GOOD, "WIFI", ssid_or_name="net")], "p.ndjson")
        s = self.run_(p)
        c = self.conn()
        self.assertIsNone(c.execute("SELECT 1 FROM devices WHERE address=?", (self.DEAD,)).fetchone())
        self.assertIsNotNone(c.execute("SELECT 1 FROM devices WHERE address=?", (self.GOOD,)).fetchone())
        self.assertEqual(c.execute("SELECT count(*) FROM sightings WHERE address=?", (self.DEAD,)).fetchone()[0], 1)
        self.assertEqual(s["dropped_dead"], 1)
        g = c.execute("SELECT info_score, noise_reason FROM devices WHERE address=?", (self.GOOD,)).fetchone()
        self.assertIsNone(g["noise_reason"])
        self.assertGreater(g["info_score"], 0)

    def test_keep_noise_keeps_and_flags_dead(self):
        p = self.ndjson([phone_row(self.DEAD, "BLE", address_type="random")], "p.ndjson")
        s = self.run_(p, keep_noise=True)
        r = self.conn().execute("SELECT noise_reason FROM devices WHERE address=?", (self.DEAD,)).fetchone()
        self.assertEqual(r["noise_reason"], "dead_random_no_handle")
        self.assertEqual(s["dropped_dead"], 0)


class Cumulative(Base):
    A = "00:00:0C:11:22:33"
    B = "00:00:0C:44:55:66"

    def test_appends_and_skips_already_ingested(self):
        a = self.ndjson([phone_row(self.A, "WIFI", ssid_or_name="a")], "a.ndjson")
        b = self.ndjson([phone_row(self.B, "WIFI", ssid_or_name="b")], "b.ndjson")
        s1 = self.run_(a)
        self.assertEqual(s1["accumulated"]["sightings_in_db"], 1)
        s2 = self.run_(a, b)                              # a already ingested -> skipped; b appended
        self.assertEqual(s2["accumulated"]["mode"], "accumulate")
        self.assertEqual(s2["accumulated"]["files_in_db"], 2)
        self.assertEqual(s2["accumulated"]["sightings_in_db"], 2)
        self.assertEqual(self.conn().execute("SELECT count(*) FROM devices").fetchone()[0], 2)

    def test_fresh_rebuilds_from_only_given_files(self):
        a = self.ndjson([phone_row(self.A, "WIFI", ssid_or_name="a")], "a.ndjson")
        b = self.ndjson([phone_row(self.B, "WIFI", ssid_or_name="b")], "b.ndjson")
        self.run_(a)
        s = self.run_(b, fresh=True)
        self.assertEqual(s["accumulated"]["mode"], "fresh")
        self.assertEqual(s["accumulated"]["sightings_in_db"], 1)

    def test_appended_file_does_not_inflate_device(self):
        """Append-growth: the phone appends later drives into ONE per-day file, so a re-pull is a SUPERSET with a new
        content hash -> file-hash dedup lets it through and it is ingested whole. The raw sightings log must keep every
        row (reversible), but the device must roll up from UNIQUE sightings only -- a re-read can't inflate its counts."""
        t1, t2, t3 = "2026-10-30T09:00:00-0400", "2026-10-30T09:05:00-0400", "2026-10-30T14:00:00-0400"
        am = self.ndjson([phone_row(self.A, "WIFI", ssid_or_name="a", iso_time=t1),
                          phone_row(self.A, "WIFI", ssid_or_name="a", iso_time=t2)], "am.ndjson")
        full = self.ndjson([phone_row(self.A, "WIFI", ssid_or_name="a", iso_time=t1),
                            phone_row(self.A, "WIFI", ssid_or_name="a", iso_time=t2),
                            phone_row(self.A, "WIFI", ssid_or_name="a", iso_time=t3)], "full.ndjson")
        self.run_(am)
        self.assertEqual(self.sight_count(self.A), 2)                 # two distinct observations so far
        s = self.run_(full)                                          # same day's file after it grew -> appended whole
        self.assertEqual(s["accumulated"]["sightings_in_db"], 5)     # raw log keeps all 5 rows (immutable, reversible)
        self.assertEqual(s["duplicate_sightings_skipped"], 2)        # the two am rows, read a second time
        self.assertEqual(self.sight_count(self.A), 3)                # device rolled up from 3 unique sightings, NOT 5
        self.assertEqual(self.conn().execute("SELECT count(*) FROM devices").fetchone()[0], 1)


class Cluster(Base):
    def make_db(self):
        c = sqlite3.connect(":memory:")
        c.row_factory = sqlite3.Row
        c.executescript(se.SCHEMA)
        self.addCleanup(c.close)
        return c

    def ins(self, c, addr, fp, pnl, radio="wifi", is_rand=1):
        c.execute("INSERT INTO devices (address, radio, is_randomized, fingerprint_hash, probed_ssids) VALUES (?,?,?,?,?)",
                  (addr, radio, is_rand, fp, None if pnl is None else json.dumps(pnl)))

    def ids(self, c):
        return {r["address"]: r["device_cluster_id"] for r in c.execute("SELECT address, device_cluster_id FROM devices")}

    def test_same_model_overlapping_probes_cluster(self):
        c = self.make_db()
        self.ins(c, "02:11:11:11:11:11", "FP1", ["Home", "Work", "Cafe"])
        self.ins(c, "06:22:22:22:22:22", "FP1", ["Home", "Work"])     # Jaccard 2/3 >= 0.5 -> same device
        self.ins(c, "0A:33:33:33:33:33", "FP1", ["Zzz"])              # no overlap -> its own, no link
        se.cluster_devices(c)
        ids = self.ids(c)
        self.assertEqual(ids["02:11:11:11:11:11"], ids["06:22:22:22:22:22"])
        self.assertIsNotNone(ids["02:11:11:11:11:11"])
        self.assertIsNone(ids["0A:33:33:33:33:33"])

    def test_different_fingerprint_never_merges(self):
        c = self.make_db()
        self.ins(c, "02:11:11:11:11:11", "FP1", ["Home", "Work"])
        self.ins(c, "06:22:22:22:22:22", "FP2", ["Home", "Work"])     # identical probes but different model -> no merge
        se.cluster_devices(c)
        self.assertEqual(list(self.ids(c).values()), [None, None])

    def test_aps_and_public_macs_never_cluster(self):
        c = self.make_db()
        self.ins(c, "00:00:0C:11:22:33", "FP1", ["Home", "Work"], is_rand=0)   # public AP, not randomized
        self.ins(c, "00:00:0C:44:55:66", "FP1", ["Home", "Work"], is_rand=0)
        se.cluster_devices(c)
        self.assertEqual(list(self.ids(c).values()), [None, None])


if __name__ == "__main__":
    unittest.main()
