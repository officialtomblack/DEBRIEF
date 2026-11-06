#!/usr/bin/env python3
"""Write a SYNTHETIC demo capture so anyone can try the pipeline without their own data.

A made-up morning walk across three stops (start -> cafe -> office) in a city chosen only because it is generic. Every
MAC, name and coordinate below is invented. Two trackers and a car hotspot tag along between stops; everything else stays
put. Writes demo/demo_walk.ndjson (a SWIVEL phone log) and demo/demo_office.kismet (a minimal Kismet log of the last stop).

    python3 demo/make_demo.py
    python3 swivel_enhance.py run demo/demo_walk.ndjson demo/demo_office.kismet --db out/demo.db --fresh
    python3 swivel_enhance.py report out/demo.db
"""
import datetime as dt, json, os, random, sqlite3

HERE = os.path.dirname(os.path.abspath(__file__))
TZ = dt.timezone(dt.timedelta(hours=-8))
DAY = dt.datetime(2026, 1, 15, tzinfo=TZ)
BASE_UUID_SUFFIX = "00001000800000805F9B34FB"
# (name, lat, lon, arrive, leave) — each stop ~1 km from the last
STOPS = [("start", 45.52310, -122.67650, "08:00", "08:35"),
         ("cafe", 45.52900, -122.68500, "09:10", "09:50"),
         ("office", 45.53550, -122.69200, "10:25", "11:30")]
AP_OUIS = ["A0:40:A0", "50:C7:BF", "E4:F4:C6", "F0:9F:C2", "00:1A:1E", "3C:37:86", "B0:BE:76", "C8:3A:35"]
GADGETS = ["JBL Flip 5", "Pixel Buds Pro", "Fitbit Charge 6", "Bose QC45", "Galaxy Watch5", "Kindle"]

rng = random.Random(2026)


def t(hhmm):
    h, m = map(int, hhmm.split(":"))
    return DAY.replace(hour=h, minute=m)


def mac(prefix=None, random_static=False):
    tail = [rng.randrange(256) for _ in range(6)]
    if random_static:
        tail[0] |= 0xC0                                  # BLE random static address: top two bits set
    s = ":".join(f"{b:02X}" for b in tail)
    return prefix + s[8:] if prefix else s


def apple_find_my():
    return "4C00" + "12" + "19" + "".join(f"{rng.randrange(256):02X}" for _ in range(25))   # TLV 0x12 = offline finding


def sightings(stop, n, **row):
    """n phone rows for one device at one stop, spread over the visit, jittered ~20 m around the stop."""
    _, lat, lon, a, b = stop
    t0, t1 = t(a), t(b)
    out = []
    for _ in range(n):
        ts = t0 + (t1 - t0) * rng.random()
        out.append({"iso_time": ts.strftime("%Y-%m-%dT%H:%M:%S%z"), "session_id": "demo", "source": "PHONE",
                    "address_type": "", "vendor": "", "ssid_or_name": "", "rssi": rng.randint(-88, -45),
                    "lat": round(lat + rng.uniform(-2e-4, 2e-4), 6), "lon": round(lon + rng.uniform(-2e-4, 2e-4), 6),
                    "gps_accuracy_m": rng.choice([4, 6, 8, 12]), **row})
    return out


def build_rows():
    rows, office_aps = [], []
    for stop in STOPS:
        for i in range(22):                                                    # the neighbourhood: fixed access points
            bssid = mac(rng.choice(AP_OUIS))
            ssid = f"{stop[0].title()}-Net-{i:02d}" if i % 4 else ""
            rows += sightings(stop, rng.randint(3, 8), kind="WIFI", mac=bssid, address_type="public",
                              ssid_or_name=ssid, security="[WPA2-PSK-CCMP][ESS]")
            if stop[0] == "office":
                office_aps.append(bssid)
        for name in rng.sample(GADGETS, 3):                                   # named gadgets nearby
            rows += sightings(stop, rng.randint(2, 5), kind="BLE", mac=mac(random_static=True), address_type="random",
                              ssid_or_name=name)
        for _ in range(15):                                                    # anonymous rotating adverts (noise)
            rows += sightings(stop, rng.randint(1, 2), kind="BLE", mac=mac(random_static=True), address_type="random")
    # the tag-alongs: the same address at more than one stop
    tag, tile, car = mac(random_static=True), mac(random_static=True), mac("00:1E:42")
    tag_adv = apple_find_my()
    for stop in STOPS:
        rows += sightings(stop, rng.randint(5, 9), kind="BLE", mac=tag, address_type="random", manufacturer=tag_adv)
    for stop in STOPS[1:]:
        rows += sightings(stop, rng.randint(4, 7), kind="BLE", mac=tile, address_type="random",
                          services=f"0000FEED{BASE_UUID_SUFFIX}")
    for stop in (STOPS[0], STOPS[2]):
        rows += sightings(stop, rng.randint(3, 6), kind="WIFI", mac=car, address_type="public",
                          ssid_or_name="DEMO-CarHotspot", security="[WPA2-PSK-CCMP][ESS]")
    # an evil-twin hint: the cafe guest network, seen WPA2 most of the time and OPEN once
    twin = mac(rng.choice(AP_OUIS))
    rows += sightings(STOPS[1], 6, kind="WIFI", mac=twin, address_type="public", ssid_or_name="Cafe-Guest",
                      security="[WPA2-PSK-CCMP][ESS]")
    rows += sightings(STOPS[1], 1, kind="WIFI", mac=twin, address_type="public", ssid_or_name="Cafe-Guest",
                      security="[ESS]")
    rows.sort(key=lambda r: r["iso_time"])
    return rows, office_aps + [car]


KISMET_DEVICES_DDL = ("CREATE TABLE devices (first_time INT, last_time INT, devkey TEXT, phyname TEXT, devmac TEXT, "
                      "strongest_signal INT, min_lat REAL, min_lon REAL, max_lat REAL, max_lon REAL, avg_lat REAL, "
                      "avg_lon REAL, bytes_data INT, type TEXT, device BLOB, UNIQUE(phyname, devmac) ON CONFLICT REPLACE)")
KISMET_ALERTS_DDL = ("CREATE TABLE alerts (ts_sec INT, ts_usec INT, phyname TEXT, devmac TEXT, lat REAL, lon REAL, "
                     "header TEXT, json BLOB)")


def write_kismet(path, macs):
    """A minimal Kismet log of the office stop: the same APs the phone heard there, plus one IDS alert."""
    _, lat, lon, a, b = STOPS[2]
    t0, t1 = int(t(a).timestamp()), int(t(b).timestamp())
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    try:
        con.execute(KISMET_DEVICES_DDL)
        con.execute(KISMET_ALERTS_DDL)
        for m in macs[::2] + macs[-1:]:                                        # Kismet hears about half of them + the car
            con.execute("INSERT INTO devices (first_time,last_time,devkey,phyname,devmac,strongest_signal,avg_lat,"
                        "avg_lon,bytes_data,type,device) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (t0 + 60, t1 - 60, m, "IEEE802.11", m, rng.randint(-85, -40), lat, lon, 0, "Wi-Fi AP", b"{}"))
        con.execute("INSERT INTO alerts (ts_sec,ts_usec,phyname,devmac,lat,lon,header,json) VALUES (?,?,?,?,?,?,?,?)",
                    (t0 + 900, 0, "IEEE802.11", macs[0], lat, lon, "DEAUTHFLOOD", b"{}"))
        con.commit()
    finally:
        con.close()


def main():
    rows, kismet_macs = build_rows()
    nd = os.path.join(HERE, "demo_walk.ndjson")
    with open(nd, "w", encoding="utf-8") as f:
        f.writelines(json.dumps(r) + "\n" for r in rows)
    km = os.path.join(HERE, "demo_office.kismet")
    write_kismet(km, kismet_macs)
    print(f"wrote {os.path.relpath(nd)} ({len(rows)} sightings) and {os.path.relpath(km)} — all synthetic")


if __name__ == "__main__":
    main()
