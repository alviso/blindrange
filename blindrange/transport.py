"""Pooled keep-alive HTTP transport shared by clients and nodes.

Every request used to open a fresh TCP connection (urllib has no pooling),
paying a handshake round trip per hop — painful when hops traverse relays
across the internet. This pool keeps idle connections per address and reuses
them; a request that fails on a pooled connection (the peer may have closed
it between uses) retries once on a fresh one. Thread-safe; connections are
checked out exclusively, so concurrent requests to one address use parallel
connections.
"""
import http.client
import json
import threading
from collections import defaultdict

MAX_IDLE_PER_ADDR = 8


class Pool:
    def __init__(self):
        self.lock = threading.Lock()
        self.idle = defaultdict(list)

    def _take(self, addr):
        with self.lock:
            conns = self.idle[addr]
            return conns.pop() if conns else None

    def _give(self, addr, conn):
        with self.lock:
            conns = self.idle[addr]
            if len(conns) < MAX_IDLE_PER_ADDR:
                conns.append(conn)
                return
        conn.close()

    def request(self, addr, method, path, body=None, headers=None, timeout=10):
        """Returns (status, raw_bytes). Raises ConnectionError on transport
        failure. Callers decide what non-200 statuses mean."""
        last_err = None
        for attempt in (0, 1):
            conn = None if attempt else self._take(addr)
            fresh = conn is None
            if fresh:
                host, _, port = addr.rpartition(":")
                conn = http.client.HTTPConnection(host, int(port),
                                                 timeout=timeout)
            try:
                if conn.sock is not None:
                    conn.sock.settimeout(timeout)
                conn.request(method, path, body=body, headers=headers or {})
                resp = conn.getresponse()
                data = resp.read()
                if resp.will_close:
                    conn.close()
                else:
                    self._give(addr, conn)
                return resp.status, data
            except (http.client.HTTPException, OSError) as e:
                try:
                    conn.close()
                except OSError:
                    pass
                last_err = e
                if fresh:            # a brand-new connection failed: give up
                    break
        raise ConnectionError(f"request to {addr}{path} failed: {last_err}")

    def post_json(self, addr, path, payload: dict, headers=None, timeout=10):
        body = json.dumps(payload).encode()
        hdrs = {"Content-Type": "application/json", **(headers or {})}
        status, data = self.request(addr, "POST", path, body, hdrs, timeout)
        if status >= 400:
            raise ConnectionError(f"HTTP {status} from {addr}{path}")
        return json.loads(data)

    def get_json(self, addr, path, headers=None, timeout=5):
        status, data = self.request(addr, "GET", path, None, headers, timeout)
        if status >= 400:
            raise ConnectionError(f"HTTP {status} from {addr}{path}")
        return json.loads(data)


POOL = Pool()        # process-wide default pool
