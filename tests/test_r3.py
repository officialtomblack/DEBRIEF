"""R3 hard rule: a randomized / locally-administered address NEVER gets an OUI vendor; public OUIs DO resolve.

Run from App/log-enhancer/:
    python3 -m unittest discover -s tests -v                    # default target
    R3_TARGET=legacy python3 -m unittest discover -s tests -v   # the copied old tool

Exits non-zero on any failure. All cases are synthetic (tests/fixtures/r3_cases.json).
"""
import os, tempfile, unittest

import r3_harness as h

TARGET = os.environ.get("R3_TARGET", h.DEFAULT_TARGET)


class R3(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if TARGET not in h.ADAPTERS:                    # a typo must fail, not skip the whole suite and exit 0
            raise RuntimeError(f"unknown R3_TARGET {TARGET!r}; have {sorted(h.ADAPTERS)}")
        print(f"\n[R3 target: {TARGET}]")
        cls.cases = h.load_cases()
        cls._tmp = tempfile.TemporaryDirectory(prefix="r3_")
        cls.out = h.ADAPTERS[TARGET](cls.cases, cls._tmp.name)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def rows_for(self, case):
        rows = self.out.get(case["address"].upper(), [])
        self.assertTrue(rows, f"{case['id']}: no output row for the fixture address (a missing row would pass vacuously)")
        return rows

    def test_randomized_and_unknown_get_no_oui_vendor(self):
        for c in self.cases:
            if c["expect"]["oui_vendor"] is not None:
                continue
            with self.subTest(case=c["id"], rule=c["rule"]):
                for r in self.rows_for(c):
                    self.assertIsNone(r["oui_vendor"],
                                      f"{c['id']} R3 VIOLATION: {r['radio']} row got oui_vendor={r['oui_vendor']!r}")

    def test_public_ouis_resolve(self):
        for c in self.cases:
            want = c["expect"]["oui_vendor"]
            if want is None:
                continue
            with self.subTest(case=c["id"], rule=c["rule"]):
                rows = [r for r in self.rows_for(c) if r["radio"] in c["radios"]]
                self.assertTrue(rows, f"{c['id']}: no row for radio {c['radios']}")
                for r in rows:
                    self.assertEqual(r["oui_vendor"], want, f"{c['id']}: wrong vendor")

    def test_vendor_confidence(self):
        if not h.CONFIDENCE_SUPPORTED.get(TARGET):
            self.skipTest(f"{TARGET} has no confidence column")
        for c in self.cases:
            want = c["expect"].get("oui_vendor_confidence")
            if want is None:
                continue
            with self.subTest(case=c["id"]):
                for r in self.rows_for(c):
                    self.assertEqual(r["oui_vendor_confidence"], want)

    def test_tool_r3_check_exit_code(self):
        if TARGET != "new":
            self.skipTest("only the new tool has an R3 exit code")
        self.assertEqual(h.result_returncode[0], 0, "swivel_enhance exited 2: its own R3 check failed on the fixture")

    def test_classic_and_ble_stay_separate(self):
        for c in self.cases:
            if len(c["radios"]) < 2:
                continue
            with self.subTest(case=c["id"]):
                got = sorted(r["radio"] for r in self.rows_for(c))
                self.assertEqual(got, sorted(c["radios"]), f"{c['id']}: radios merged into one row")


if __name__ == "__main__":
    unittest.main()
