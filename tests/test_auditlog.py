"""blindrange-audit: the demo app, tested the way shippers actually talk.

The failure this guards against is not a crash — it is an audit pipeline
that appears to work while dropping or flattening events, which is the one
way an audit log can fail that nobody notices until it matters.
"""
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "examples" / "auditlog"))
from tests.test_e2e import wait_http, wait_peers  # noqa: E402
import audit  # noqa: E402

PORTS = (7821, 7822, 7823)


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close(); return p


class TestNormalise(unittest.TestCase):
    """Pure parsing — no network, so these stay fast and always run."""

    def test_timestamp_units_are_all_understood(self):
        import datetime
        secs = 1755200000
        iso = datetime.datetime.fromtimestamp(
            secs, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for label, raw in [("seconds", secs), ("millis", secs * 1000),
                           ("nanos", secs * 1_000_000_000),
                           ("rfc3339", iso)]:
            got = audit.normalise({"ts": raw, "actor": "a", "action": "b"})["ts"]
            self.assertLess(abs(got - secs), 2, f"{label} misread as {got}")

    def test_field_aliases_from_each_shipper(self):
        for ev, actor, action in [
                ({"user": "u1", "operation": "op"}, "u1", "op"),
                ({"principal": "p1", "event": "ev"}, "p1", "ev"),
                ({"subject": "s1", "message": "msg"}, "s1", "msg")]:
            n = audit.normalise(ev)
            self.assertEqual((n["actor"], n["action"]), (actor, action))

    def test_unknown_fields_survive_in_the_payload(self):
        n = audit.normalise({"actor": "a", "action": "b", "ip": "10.0.0.1",
                             "rows": 42})
        self.assertEqual(n["payload"]["ip"], "10.0.0.1")
        self.assertEqual(n["payload"]["rows"], 42)

    def test_otlp_envelope_becomes_individual_events(self):
        """The quiet killer: a whole OTLP batch stored as one blob looks
        like success and destroys the trail."""
        doc = {"resourceLogs": [{"resource": {"attributes": [
            {"key": "service.name", "value": {"stringValue": "api"}}]},
            "scopeLogs": [{"logRecords": [
                {"timeUnixNano": "1755200000000000000",
                 "attributes": [{"key": "actor", "value": {"stringValue": "c"}},
                                {"key": "action", "value": {"stringValue": "x"}}]},
                {"timeUnixNano": "1755200060000000000",
                 "attributes": [{"key": "actor", "value": {"stringValue": "c"}},
                                {"key": "action", "value": {"stringValue": "y"}},
                                {"key": "n", "value": {"intValue": "3"}}]}]}]}]}
        evs = audit.parse_batch(json.dumps(doc).encode())
        self.assertEqual(len(evs), 2)
        self.assertEqual([e["action"] for e in evs], ["x", "y"])
        self.assertEqual(evs[0]["service.name"], "api")
        self.assertEqual(evs[1]["n"], 3)

    def test_array_and_ndjson_and_single(self):
        self.assertEqual(len(audit.parse_batch(b'[{"a":1},{"a":2}]')), 2)
        self.assertEqual(len(audit.parse_batch(b'{"a":1}\n{"a":2}\n{"a":3}')), 3)
        self.assertEqual(len(audit.parse_batch(b'{"a":1}')), 1)
        self.assertEqual(audit.parse_batch(b'  '), [])

    def test_leaf_width_snaps_and_is_reported_truthfully(self):
        self.assertEqual(audit.snap_leaf(3600), 4096)
        self.assertEqual(audit.snap_leaf(60), 64)
        self.assertEqual(audit.snap_leaf(4096), 4096)
        for v in (1, 7, 100, 5000, 90000):
            leaf = audit.snap_leaf(v)
            self.assertEqual(leaf & (leaf - 1), 0, f"{leaf} not a power of two")


class TestAuditService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="brauditsvc_")
        cls.secret, cls.procs = "auditsvc", []
        for i, port in enumerate(PORTS):
            a = [sys.executable, "-m", "blindrange.node", "--port", str(port),
                 "--data", f"{cls.tmp}/n{port}", "--secret", cls.secret]
            if i:
                a += ["--seed", f"127.0.0.1:{PORTS[0]}"]
            cls.procs.append(subprocess.Popen(
                a, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(ROOT)))
        wait_http(f"127.0.0.1:{PORTS[0]}")
        wait_peers(f"127.0.0.1:{PORTS[0]}", 3, cls.secret)

        cls.port = free_port()
        cls.procs.append(subprocess.Popen(
            [sys.executable, str(ROOT / "examples" / "auditlog" / "audit.py"),
             "--state", f"{cls.tmp}/a.brdb", "--bootstrap", f"127.0.0.1:{PORTS[0]}",
             "--secret", cls.secret, "--port", str(cls.port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(ROOT)))
        for _ in range(120):
            try:
                cls.get("/healthz"); break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError("audit service never came up")

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            if p.poll() is None:
                p.terminate()
            p.wait()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def get(cls, path):
        with urllib.request.urlopen(
                f"http://127.0.0.1:{cls.port}{path}", timeout=60) as r:
            return json.loads(r.read())

    @classmethod
    def post(cls, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{cls.port}/ingest",
                                     data=data, headers={"Content-Type": ctype})
        with urllib.request.urlopen(req, timeout=90) as r:
            return json.loads(r.read())

    def test_01_ingest_and_query_round_trip(self):
        base = 1755200000
        self.assertEqual(self.post([
            {"ts": base, "actor": "alice@corp",
             "action": "login.success", "ip": "10.0.0.4"},
            {"ts": base + 300, "actor": "alice@corp",
             "action": "role.grant", "target": "billing-admin"},
        ])["stored"], 2)
        self.assertEqual(self.post(
            b'\n'.join(json.dumps({"time": (base + 600) * 1000, "user": "bob@corp",
                                   "operation": "record.export", "rows": 100 + i}).encode()
                       for i in range(3)), "application/x-ndjson")["stored"], 3)

        ev = self.get("/events?limit=100")["events"]
        self.assertEqual(len(ev), 5)
        # Newest first by default: an audit UI asks for recent events, and
        # with a limit an ascending walk returns the OLDEST rows in the
        # window — the wrong end, reached the expensive way.
        times = [e["ts"] for e in ev]
        self.assertEqual(times, sorted(times, reverse=True),
                         "events must come back newest first")

        # Reading order is still available for exporting a trail.
        asc = [e["ts"] for e in self.get("/events?limit=100&order=asc")["events"]]
        self.assertEqual(asc, sorted(asc), "?order=asc must ascend")
        self.assertEqual(sorted(asc), sorted(times), "same rows either way")

    def test_02_filters(self):
        self.assertEqual(len(self.get("/events?actor=alice")["events"]), 2)
        self.assertEqual(len(self.get("/events?actor=bob")["events"]), 3)
        both = self.get("/events?actor=bob&action=record")["events"]
        self.assertEqual(len(both), 3)
        self.assertIn("rows", both[0]["payload"])

    def test_03_count_comes_from_index_metadata(self):
        c = self.get("/count")
        self.assertEqual(c["count"], 5)
        self.assertEqual(c["basis"], "exact-to-leaf")

    def test_04_contrast_shows_both_views(self):
        c = self.get("/contrast")
        mine, theirs = " ".join(c["mine"]), " ".join(c["theirs"])
        self.assertIn("@corp", mine, "owner view shows no readable events")
        for secret in ("@corp", "alice", "bob", "login.success",
                       "record.export"):
            self.assertNotIn(secret, theirs,
                             f"plaintext {secret!r} visible to the node")

    def test_05_no_destructive_routes_exist(self):
        for path in ("/delete", "/compact", "/drop"):
            with self.assertRaises(urllib.error.HTTPError) as e:
                urllib.request.urlopen(urllib.request.Request(
                    f"http://127.0.0.1:{self.port}{path}", data=b"{}"), timeout=20)
            self.assertEqual(e.exception.code, 404, f"{path} is reachable")


if __name__ == "__main__":
    unittest.main()


class TestIngestNeverSilentlyMangles(unittest.TestCase):
    """An audit trail that stores the wrong thing and says "ok" is worse
    than one that refuses.

    A batch posted as {"events": [...250 records...]} fell through to
    "treat the whole object as one event": the envelope was stored as a
    single row of nonsense and the caller was answered {"stored": 1}. The
    250 records were gone, and nothing anywhere said so.
    """

    def setUp(self):
        import importlib.util
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location(
            "auditmod", root / "examples" / "auditlog" / "audit.py")
        self.mod = importlib.util.module_from_spec(spec)
        sys.modules["auditmod"] = self.mod
        spec.loader.exec_module(self.mod)

    def test_a_wrapped_batch_is_unwrapped(self):
        evs = [{"ts": 1700000000 + i, "actor": "a", "action": "x"}
               for i in range(250)]
        for key in ("events", "records", "logs", "entries", "items"):
            got = self.mod.parse_batch(json.dumps({key: evs}).encode())
            self.assertEqual(len(got), 250, f"{key} wrapper was not unwrapped")

    def test_an_unusual_wrapper_is_unwrapped_too(self):
        """Keyed on shape, not on a list of blessed names."""
        evs = [{"ts": 1, "actor": "a"}, {"ts": 2, "actor": "b"}]
        got = self.mod.parse_batch(json.dumps({"payload_v2": evs}).encode())
        self.assertEqual(len(got), 2)

    def test_an_event_carrying_a_list_is_still_one_event(self):
        """The guard that keeps unwrapping from eating real events: this
        has a list of objects in it, but it is plainly an event."""
        ev = {"ts": 1700000000, "actor": "a", "action": "x",
              "tags": [{"k": "v"}, {"k": "w"}]}
        got = self.mod.parse_batch(json.dumps(ev).encode())
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["actor"], "a")

    def test_a_custom_single_event_still_works(self):
        """Objects with no field we recognise are still events — a caller
        with its own vocabulary must not be turned away."""
        self.assertEqual(len(self.mod.parse_batch(b'{"a":1}')), 1)

    def test_the_shapes_real_shippers_send_still_work(self):
        m = self.mod
        self.assertEqual(len(m.parse_batch(b'[{"message":"a"},{"message":"b"}]')), 2)
        self.assertEqual(len(m.parse_batch(b'{"message":"one"}')), 1)
        self.assertEqual(len(m.parse_batch(b'{"ts":1700000000,"actor":"a"}')), 1)
        self.assertEqual(
            len(m.parse_batch(b'{"message":"x"}\n{"message":"y"}\n')), 2)
        self.assertEqual(m.parse_batch(b""), [])

    def test_a_bare_message_line_is_still_an_event(self):
        """Plain text lines are a real shipper shape and must not start
        failing now that objects can be refused."""
        got = self.mod.parse_batch(b"just a log line\nand another\n")
        self.assertEqual(len(got), 2)
        self.assertEqual(got[0]["message"], "just a log line")
