"""Stage 3: location clusters, followed_flag (tunable distance/time), near_alpr (offline), GeoJSON export.
All inputs synthetic; no real coordinates or camera data. Distances use lat offsets (1 deg lat ~ 111 320 m)."""
import collections, json, os, shutil, subprocess, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import swivel_enhance as se
from test_stage1 import Built, phone_row, REG

M_PER_DEG_LAT = 111_320.0                                 # metres per degree of latitude (lon unused: offsets are lat-only)
BASE_LAT, BASE_LON = 40.0, -75.0
T0 = "2026-10-30T01:00:00-0400"


def dlat(metres):
    return metres / M_PER_DEG_LAT


def loc_row(mac, metres_north, iso_time=T0, kind="WIFI"):
    """A sighting of `mac` at BASE + metres_north (m) at iso_time."""
    return phone_row(mac, kind, lat=BASE_LAT + dlat(metres_north), lon=BASE_LON, iso_time=iso_time)


class Geometry(unittest.TestCase):
    def test_haversine_known_distances(self):
        self.assertAlmostEqual(se.haversine_m((0, 0), (1, 0)) / 1000, 111.2, delta=0.3)   # 1 deg lat
        self.assertAlmostEqual(se.haversine_m((BASE_LAT, BASE_LON), (BASE_LAT + dlat(300), BASE_LON)), 300, delta=1)
        self.assertEqual(se.haversine_m((BASE_LAT, BASE_LON), (BASE_LAT, BASE_LON)), 0.0)

    def test_cluster_points_groups_near_splits_far(self):
        pts = [(BASE_LAT, BASE_LON), (BASE_LAT + dlat(20), BASE_LON), (BASE_LAT + dlat(300), BASE_LON)]
        cl = se.cluster_points(pts, 50.0)
        self.assertEqual(sorted(n for n, _, _ in cl), [1, 2])                 # two within 50 m, one far off
        big = se.cluster_points(pts, 1000.0)
        self.assertEqual([n for n, _, _ in big], [3])                        # one cluster when the threshold is wide

    def test_cluster_centroid_correct_across_antimeridian(self):
        # two points either side of the +/-180 meridian, ~7 m apart in reality -> one cluster near the dateline
        cl = se.cluster_points([(0.0, 179.99997), (0.0, -179.99997)], 50.0)
        self.assertEqual(len(cl), 1)
        n, lat, lon = cl[0]
        self.assertEqual(n, 2)
        self.assertLess(se.haversine_m((lat, lon), (0.0, 180.0)), 20)         # centroid on the dateline, NOT at lon 0

    def test_parse_alpr_reads_nodes_centers_skips_junk(self):
        body = b'{"elements":[{"lat":1.0,"lon":2.0},{"center":{"lat":3.0,"lon":4.0}},{"foo":1},"junk",{"lat":"x","lon":5}]}'
        self.assertEqual(se.parse_alpr(body), [(1.0, 2.0), (3.0, 4.0)])
        self.assertEqual(se.parse_alpr(b'[]'), [])                           # not a dict -> nothing, no crash

    def test_parse_alpr_rejects_nonfinite_and_bool(self):
        # json.loads parses Infinity/NaN into floats and true/false into bools; neither is a usable coordinate
        body = b'{"elements":[{"lat":1.0,"lon":2.0},{"lat":Infinity,"lon":0},{"lat":NaN,"lon":0},{"lat":true,"lon":false}]}'
        self.assertEqual(se.parse_alpr(body), [(1.0, 2.0)])


class Clusters(Built):
    def test_clusters_stored_with_counts_and_source(self):
        a = "AA:BB:CC:00:00:01"
        p = self.ndjson([loc_row(a, 0), loc_row(a, 20), loc_row(a, 300)])    # two near (<50 m), one 300 m away
        self.build(p)
        d = self.device(a, "wifi")
        clusters = json.loads(d["location_clusters"])
        self.assertEqual(sorted(c["n"] for c in clusters), [1, 2])
        self.assertEqual((d["location_clusters_source"], d["location_clusters_confidence"]), ("greedy_50m", "med"))

    def test_cluster_distance_is_tunable(self):
        a = "AA:BB:CC:00:00:02"
        self.build(self.ndjson([loc_row(a, 0), loc_row(a, 100)]))            # 100 m apart
        self.assertEqual(len(json.loads(self.device(a, "wifi")["location_clusters"])), 2)   # default 50 m -> 2 clusters
        se.derive(self.conn, se.Registry(REG), cluster_distance=200.0)
        d = self.device(a, "wifi")
        self.assertEqual(len(json.loads(d["location_clusters"])), 1)                        # 200 m -> 1 cluster
        self.assertEqual(d["location_clusters_source"], "greedy_200m")                      # source reflects the knob

    def test_no_location_leaves_source_saying_so(self):
        a = "AA:BB:CC:00:00:03"
        self.build(self.ndjson([phone_row(a, "WIFI")]))                      # no lat/lon
        d = self.device(a, "wifi")
        self.assertIsNone(d["location_clusters"])
        self.assertEqual(d["location_clusters_source"], "no_location")
        self.assertEqual((d["followed_flag"], d["followed_flag_source"]), (None, "no_location"))
        self.assertEqual((d["near_alpr"], d["near_alpr_source"]), (None, "no_location"))

    def test_located_device_rebuild_is_deterministic(self):
        a = "AA:BB:CC:00:00:04"
        self.build(self.ndjson([loc_row(a, 0, iso_time="2026-10-30T01:00:00-0400"),
                                loc_row(a, 300, iso_time="2026-10-30T01:10:00-0400")]))
        first = [tuple(r) for r in self.conn.execute("SELECT * FROM devices ORDER BY address, radio")]
        se.derive(self.conn, se.Registry(REG))                              # rebuild from the same sightings
        self.assertEqual([tuple(r) for r in self.conn.execute("SELECT * FROM devices ORDER BY address, radio")], first)


class Followed(Built):
    def test_flag_set_only_when_far_clusters_span_time(self):
        far_slow = "AA:BB:CC:00:00:10"      # 300 m apart, 10 min  -> followed
        same = "AA:BB:CC:00:00:11"          # one spot             -> not
        near = "AA:BB:CC:00:00:12"          # 100 m apart (<200)   -> not
        far_fast = "AA:BB:CC:00:00:13"      # 300 m apart, 60 s    -> not (span too short)
        t10 = "2026-10-30T01:10:00-0400"
        t1 = "2026-10-30T01:01:00-0400"
        self.build(self.ndjson([
            loc_row(far_slow, 0), loc_row(far_slow, 300, iso_time=t10),
            loc_row(same, 0), loc_row(same, 10, iso_time=t10),
            loc_row(near, 0), loc_row(near, 100, iso_time=t10),
            loc_row(far_fast, 0), loc_row(far_fast, 300, iso_time=t1),
        ]))
        self.assertEqual(self.device(far_slow, "wifi")["followed_flag"], 1)
        self.assertEqual(self.device(far_slow, "wifi")["followed_flag_confidence"], "low")
        for a in (same, near, far_fast):
            self.assertEqual(self.device(a, "wifi")["followed_flag"], 0, a)

    def test_span_ignores_locationless_sightings(self):
        # two located sightings 300 m apart only 30 s apart (span 30 s < 300 -> NOT followed); a GPS-less sighting an
        # hour later must not inflate the span and flip the flag (span is measured over located sightings only).
        a = "AA:BB:CC:00:00:14"
        self.build(self.ndjson([
            loc_row(a, 0, iso_time="2026-10-30T01:00:00-0400"),
            loc_row(a, 300, iso_time="2026-10-30T01:00:30-0400"),
            phone_row(a, "WIFI", iso_time="2026-10-30T02:00:00-0400"),       # no lat/lon
        ]))
        self.assertEqual(self.device(a, "wifi")["followed_flag"], 0)

    def test_thresholds_are_strict_and_tunable(self):
        a = "AA:BB:CC:00:00:15"
        sep = se.haversine_m((BASE_LAT, BASE_LON), (BASE_LAT + dlat(300), BASE_LON))   # exact maxsep (two 1-point clusters)
        self.build(self.ndjson([loc_row(a, 0, iso_time="2026-10-30T01:00:00-0400"),
                                loc_row(a, 300, iso_time="2026-10-30T01:05:00-0400")]))  # span exactly 300 s
        self.assertEqual(self.device(a, "wifi")["followed_flag"], 0)        # span == 300 s, strict > -> not followed
        se.derive(self.conn, se.Registry(REG), follow_distance=sep, follow_min_span=1.0)
        self.assertEqual(self.device(a, "wifi")["followed_flag"], 0)        # maxsep == follow_distance, strict > -> not
        se.derive(self.conn, se.Registry(REG), follow_distance=sep - 1.0, follow_min_span=1.0)
        self.assertEqual(self.device(a, "wifi")["followed_flag"], 1)        # just inside both knobs -> followed

    def test_follow_min_span_is_tunable(self):
        a = "AA:BB:CC:00:00:16"
        self.build(self.ndjson([loc_row(a, 0, iso_time="2026-10-30T01:00:00-0400"),
                                loc_row(a, 300, iso_time="2026-10-30T01:02:00-0400")]))   # 300 m, 120 s
        self.assertEqual(self.device(a, "wifi")["followed_flag"], 0)        # default span 300 > 120 -> not followed
        se.derive(self.conn, se.Registry(REG), follow_min_span=60.0)        # 120 > 60 -> followed
        self.assertEqual(self.device(a, "wifi")["followed_flag"], 1)


class NearAlpr(Built):
    def test_nearest_camera_distance_or_degraded_source(self):
        a = "AA:BB:CC:00:00:20"
        self.build(self.ndjson([loc_row(a, 0)]))
        self.assertEqual((self.device(a, "wifi")["near_alpr"], self.device(a, "wifi")["near_alpr_source"]),
                         (None, "no_alpr_dataset"))                          # fixture registry has no osm/alpr.json
        reg = se.Registry(REG)
        reg.alpr = [(BASE_LAT + dlat(100), BASE_LON), (BASE_LAT + dlat(5000), BASE_LON)]   # 100 m and 5 km away
        se.derive(self.conn, reg)
        d = self.device(a, "wifi")
        self.assertAlmostEqual(d["near_alpr"], 100, delta=2)                 # the nearer camera wins
        self.assertEqual((d["near_alpr_source"], d["near_alpr_confidence"]), ("osm_alpr_nearest", "med"))

    def test_min_across_multiple_clusters(self):
        a = "AA:BB:CC:00:00:21"
        self.build(self.ndjson([loc_row(a, 0, iso_time="2026-10-30T01:00:00-0400"),
                                loc_row(a, 300, iso_time="2026-10-30T01:10:00-0400")]))    # two clusters
        reg = se.Registry(REG)
        reg.alpr = [(BASE_LAT + dlat(340), BASE_LON),                       # ~40 m from the 300 m cluster
                    (BASE_LAT - dlat(2000), BASE_LON)]                       # ~2 km from the 0 m cluster
        se.derive(self.conn, reg)
        self.assertAlmostEqual(self.device(a, "wifi")["near_alpr"], 40, delta=3)   # min over BOTH clusters, not just one


class AlprFile(Built):
    def test_corrupt_alpr_file_does_not_crash_registry(self):
        tmpreg = self.path("reg")
        shutil.copytree(REG, tmpreg)
        os.makedirs(os.path.join(tmpreg, "osm"))
        with open(os.path.join(tmpreg, se.ALPR_PATH), "w", encoding="utf-8") as f:
            f.write('{"elements": [trunc')                                  # truncated JSON
        reg = se.Registry(tmpreg)                                           # must not raise
        self.assertEqual(reg.alpr, [])


class GeoJSON(Built):
    def test_clusters_geojson_written_lon_lat_with_properties(self):
        a = "AA:BB:CC:00:00:30"
        self.build(self.ndjson([loc_row(a, 0), loc_row(a, 20)]))            # one cluster, two sightings
        with open(os.path.splitext(self.db)[0] + "_clusters.geojson", encoding="utf-8") as f:
            gj = json.load(f)
        self.assertEqual(gj["type"], "FeatureCollection")
        feats = [ft for ft in gj["features"] if ft["properties"]["address"] == a]
        self.assertEqual(len(feats), 1)
        lon, lat = feats[0]["geometry"]["coordinates"]                       # GeoJSON order is [lon, lat]
        self.assertAlmostEqual(lon, BASE_LON, places=4)                      # all sightings share this longitude
        self.assertLess(se.haversine_m((lat, lon), (BASE_LAT, BASE_LON)), 25)   # centroid of the two near points
        self.assertEqual(feats[0]["properties"]["sightings_here"], 2)
        self.assertIn("followed_flag", feats[0]["properties"])

    def test_summary_text_leaks_no_coordinates_or_raw_distance(self):
        a = "AA:BB:CC:00:00:31"
        self.build(self.ndjson([loc_row(a, 0, iso_time="2026-10-30T01:00:00-0400"),
                                loc_row(a, 300, iso_time="2026-10-30T01:10:00-0400")]))
        reg = se.Registry(REG)
        reg.alpr = [(BASE_LAT + dlat(1373), BASE_LON)]                       # a camera ~1 km off -> a raw near_alpr value
        se.derive(self.conn, reg)
        raw = self.device(a, "wifi")["near_alpr"]
        self.assertIsNotNone(raw)                                           # the feature really ran
        text = se.format_summary(se.summarize(self.conn, [("x", 2)], [], collections.Counter(), reg, "UTC"))
        for needle in (str(BASE_LAT), str(BASE_LON), f"{BASE_LAT:.3f}", f"{BASE_LON:.3f}", str(raw)):
            self.assertNotIn(needle, text)                                  # no centroid, no raw per-device distance


class CLI(Built):
    def test_location_flags_wired_through_argv(self):
        a = "AA:BB:CC:00:00:40"
        p = self.ndjson([loc_row(a, 0, iso_time="2026-10-30T01:00:00-0400"),
                         loc_row(a, 300, iso_time="2026-10-30T01:10:00-0400")])     # 300 m over 10 min
        base = [sys.executable, "-I", os.path.join(os.path.dirname(HERE), "swivel_enhance.py"), "run", p,
                "--registry", REG, "--db", self.db, "--naive-tz", "UTC", "--keep-noise"]   # keep: this device is a randomized client with no vendor
        default = subprocess.run(base, capture_output=True, text=True)
        self.assertEqual(default.returncode, 0, default.stderr)
        self.assertIn("0=no): {1: 1}", default.stdout)                      # default -> the device is flagged followed
        wide = subprocess.run(base + ["--follow-distance", "1000", "--fresh"], capture_output=True, text=True)
        self.assertIn("0=no): {0: 1}", wide.stdout)                         # knob reached derive -> not flagged


class AlprQuery(unittest.TestCase):
    def test_worldwide_vs_bbox(self):
        self.assertNotIn("(", se.alpr_query())                               # worldwide: no bbox parens
        self.assertIn('node["surveillance:type"="ALPR"]', se.alpr_query())
        q = se.alpr_query((45.1, -122.92, 45.2, -122.8))
        self.assertIn("(45.1,-122.92,45.2,-122.8)", q)
        self.assertIn("timeout:180", q)

    def test_parse_bbox(self):
        self.assertIsNone(se.parse_bbox(None))
        self.assertIsNone(se.parse_bbox(""))
        self.assertEqual(se.parse_bbox("45.1,-122.92,45.2,-122.8"), (45.1, -122.92, 45.2, -122.8))
        with self.assertRaises(SystemExit):
            se.parse_bbox("1,2,3")                                           # wrong field count
        with self.assertRaises(SystemExit):
            se.parse_bbox("28,-82,27,-81")                                   # S >= N


if __name__ == "__main__":
    unittest.main()
