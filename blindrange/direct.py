"""Direct QUIC paths to NAT'd tenants — hole punching, with relay fallback.

Reaching a relay tenant over HTTP costs four internet crossings (client ->
relay -> tenant's long-poll -> relay -> client). This module lets a client
talk to a tenant DIRECTLY over a punched UDP path:

  * Every node runs QUIC on a UDP socket bound to its own port. That socket
    also answers a tiny discovery protocol (datagrams prefixed BRP1):
    "ping" -> "pong {your public ip:port}" (STUN-lite) and "punch" bursts.
  * A tenant learns its public UDP endpoint by pinging its relay, advertises
    it in its signed heartbeat, and re-pings periodically to keep the NAT
    mapping warm.
  * A client dialing a tenant STUNs first on a SCRATCH socket, then binds the
    QUIC dial to that same local port — reusing the NAT mapping. Discovery
    traffic must never share the connection's socket: a peer's QUIC server
    answers stray datagrams with QUIC packets of its own, which poison an
    in-flight handshake ("Packet contains no CRYPTO frame"). The client then
    transmits its Initials (aioquic leaves the first send to us when
    wait_connected=False — exactly what punching needs) and concurrently asks
    the tenant, over the reliable relay path, to fire a punch burst back.
    The handshake completes on a retransmission once both NATs are open.
    ~80-90% of NAT pairs punch; the rest keep using the relay, which never
    goes away.

Trust is unchanged: QUIC's TLS uses throwaway self-signed certs (transport
identity was never part of the model); every request still carries the
network-secret HMAC, endpoint-to-node binding comes from identity-signed
heartbeats, and payloads are ciphertext end to end regardless.

Set BR_NO_QUIC=1 to disable (nodes: no QUIC listener; clients: never dial).
"""
import asyncio
import json
import os
import socket
import ssl
import threading
from base64 import b64decode, b64encode
from datetime import datetime, timedelta, timezone

from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

MAGIC = b"BRP1"
ALPN = ["blindrange/1"]
DISABLED = os.environ.get("BR_NO_QUIC", "") == "1"


def _self_signed(common_name):
    """Throwaway TLS identity for QUIC's mandatory handshake."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    return cert, key


def _addr_tuple(addr: str):
    host, _, port = addr.rpartition(":")
    return host, int(port)


# ------------------------------------------------------------- protocols

class _Brp1Mixin:
    """Handles BRP1 discovery datagrams arriving on a QUIC socket."""

    def _brp1_init(self):
        self._pong_waiters = []

    def brp1_received(self, data, addr, transport):
        try:
            msg = json.loads(data[len(MAGIC):])
        except ValueError:
            return
        if msg.get("t") == "ping":
            reply = MAGIC + json.dumps(
                {"t": "pong", "you": f"{addr[0]}:{addr[1]}"}).encode()
            transport.sendto(reply, addr)
        elif msg.get("t") == "pong":
            for fut in self._pong_waiters:
                if not fut.done():
                    fut.set_result(msg.get("you", ""))
            self._pong_waiters.clear()
        # "punch" datagrams need no handling: their arrival did the work


class _ServeProtocol(QuicConnectionProtocol):
    """One inbound QUIC connection; each stream is one request/response."""
    service = None                     # set by NodeQuic factory

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._bufs = {}

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            buf = self._bufs.setdefault(event.stream_id, bytearray())
            buf += event.data
            if event.end_stream:
                data = bytes(self._bufs.pop(event.stream_id))
                asyncio.ensure_future(self._respond(event.stream_id, data))

    async def _respond(self, stream_id, data):
        loop = asyncio.get_event_loop()
        resp = await loop.run_in_executor(None, self.service, data)
        self._quic.send_stream_data(stream_id, resp, end_stream=True)
        self.transmit()


class _DialProtocol(QuicConnectionProtocol, _Brp1Mixin):
    """One outbound QUIC connection; also fields BRP1 pongs on its socket."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._brp1_init()
        self._resp = {}

    def datagram_received(self, data, addr):
        if data.startswith(MAGIC):
            self.brp1_received(data, addr, self._transport)
            return
        super().datagram_received(data, addr)

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived) and event.stream_id in self._resp:
            fut, buf = self._resp[event.stream_id]
            buf += event.data
            if event.end_stream:
                del self._resp[event.stream_id]
                if not fut.done():
                    fut.set_result(bytes(buf))

    async def request(self, payload: bytes, timeout: float) -> bytes:
        stream_id = self._quic.get_next_available_stream_id()
        fut = asyncio.get_event_loop().create_future()
        self._resp[stream_id] = (fut, bytearray())
        self._quic.send_stream_data(stream_id, payload, end_stream=True)
        self.transmit()
        return await asyncio.wait_for(fut, timeout)


# --------------------------------------------------------------- node side

class NodeQuic:
    """A node's QUIC endpoint: serves direct requests, answers STUN-lite
    pings, fires punch bursts, and discovers its own public endpoint."""

    def __init__(self, host, port, node_id, service):
        self.host, self.port = host, port
        self.node_id = node_id
        self.service = service              # bytes -> bytes, run in executor
        self.observed = ""                  # public "ip:port" once known
        self._loop = asyncio.new_event_loop()
        self._server = None
        self._ready = threading.Event()
        self._pong_waiters = []
        threading.Thread(target=self._run, daemon=True).start()
        self._ready.wait(5)

    def _run(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._start())
        self._ready.set()
        self._loop.run_forever()

    async def _start(self):
        cfg = QuicConfiguration(is_client=False, alpn_protocols=ALPN)
        cert, key = _self_signed(self.node_id)
        cfg.certificate = cert
        cfg.private_key = key

        def factory(*a, **kw):
            proto = _ServeProtocol(*a, **kw)
            proto.service = self.service
            return proto

        self._server = await serve(self.host, self.port, configuration=cfg,
                                   create_protocol=factory)
        orig = self._server.datagram_received
        mixin = _Brp1Mixin()
        mixin._pong_waiters = self._pong_waiters   # shared: stun() futures
        self._mixin = mixin

        def demux(data, addr):
            if data.startswith(MAGIC):
                mixin.brp1_received(data, addr, self._server._transport)
            else:
                orig(data, addr)
        self._server.datagram_received = demux

    def stun(self, peer_udp: str, tries=3, timeout=1.0) -> str:
        """Learn this socket's public ip:port by pinging a peer's UDP."""
        target = _addr_tuple(peer_udp)
        ping = MAGIC + json.dumps({"t": "ping"}).encode()

        async def _stun():
            for _ in range(tries):
                fut = self._loop.create_future()
                self._pong_waiters.append(fut)
                self._server._transport.sendto(ping, target)
                try:
                    return await asyncio.wait_for(fut, timeout)
                except asyncio.TimeoutError:
                    continue
            return ""
        got = asyncio.run_coroutine_threadsafe(_stun(), self._loop).result(
            tries * timeout + 2)
        if got:
            self.observed = got
        return got

    def punch(self, target_udp: str, count=8, gap=0.15):
        """Fire a burst of hole-opening datagrams at a peer's endpoint."""
        target = _addr_tuple(target_udp)
        burst = MAGIC + json.dumps({"t": "punch", "from": self.node_id}).encode()

        async def _punch():
            for _ in range(count):
                self._server._transport.sendto(burst, target)
                await asyncio.sleep(gap)
        asyncio.run_coroutine_threadsafe(_punch(), self._loop)


# -------------------------------------------------------------- client side

class DirectPath:
    """A live punched QUIC connection to one tenant (sync facade)."""

    def __init__(self, dialer, cm, proto):
        self._dialer = dialer
        self._cm = cm
        self._proto = proto

    def request(self, payload: bytes, timeout=10) -> bytes:
        return asyncio.run_coroutine_threadsafe(
            self._proto.request(payload, timeout),
            self._dialer._loop).result(timeout + 2)

    def close(self):
        async def _close():
            try:
                await self._cm.__aexit__(None, None, None)
            except Exception:
                pass
        asyncio.run_coroutine_threadsafe(_close(), self._dialer._loop)


class Dialer:
    """Client-side manager: one asyncio thread, many punched connections."""

    def __init__(self):
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()
        self._ready.wait(5)

    def _run(self):
        asyncio.set_event_loop(self._loop)
        self._ready.set()
        self._loop.run_forever()

    def dial(self, tenant_udp: str, stun_udp: str, request_punch,
             timeout=5.0) -> DirectPath:
        """Punch and connect. `request_punch(observed_endpoint)` must ask the
        tenant — over the relay — to fire a burst at us; it runs in a worker
        thread. Raises on failure (caller falls back to the relay)."""
        return asyncio.run_coroutine_threadsafe(
            self._dial(tenant_udp, stun_udp, request_punch, timeout),
            self._loop).result(timeout + 5)

    async def _dial(self, tenant_udp, stun_udp, request_punch, timeout):
        """STUN first on a scratch socket, then bind the QUIC dial to that
        same local port. Discovery traffic must never share the connection's
        socket: peers' QUIC servers answer stray datagrams with their own
        packets, which would poison an in-flight handshake."""
        host, port = _addr_tuple(tenant_udp)
        observed, local_port = await self._stun(stun_udp)

        cfg = QuicConfiguration(is_client=True, alpn_protocols=ALPN)
        cfg.verify_mode = ssl.CERT_NONE
        cm = connect(host, port, configuration=cfg,
                     create_protocol=_DialProtocol, wait_connected=False,
                     local_port=local_port)
        proto = await cm.__aenter__()
        # with wait_connected=False aioquic queues the ClientHello but leaves
        # first transmission to us (by design, for exactly this punch case)
        proto.transmit()
        try:
            # ask the tenant, over the reliable relay path, to punch at us —
            # fired CONCURRENTLY: our Initials keep retransmitting meanwhile,
            # and on an already-open path the handshake may complete first
            if observed:
                asyncio.get_event_loop().run_in_executor(
                    None, request_punch, observed)
            await asyncio.wait_for(proto.wait_connected(), timeout)
            return DirectPath(self, cm, proto)
        except Exception:
            try:
                await cm.__aexit__(None, None, None)
            except Exception:
                pass
            raise

    async def _stun(self, stun_udp, tries=3, wait=1.0):
        """Learn our public endpoint on a scratch UDP socket; return
        (observed, local_port) so the QUIC dial can reuse the mapping."""
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind(("0.0.0.0", 0))
        local_port = sock.getsockname()[1]
        ping = MAGIC + json.dumps({"t": "ping"}).encode()
        observed = ""
        try:
            for _ in range(tries):
                await loop.sock_sendto(sock, ping, _addr_tuple(stun_udp))
                try:
                    data, _addr = await asyncio.wait_for(
                        loop.sock_recvfrom(sock, 2048), wait)
                except asyncio.TimeoutError:
                    continue
                if data.startswith(MAGIC):
                    try:
                        msg = json.loads(data[len(MAGIC):])
                    except ValueError:
                        continue
                    if msg.get("t") == "pong":
                        observed = msg.get("you", "")
                        break
        finally:
            sock.close()          # freed immediately; QUIC rebinds the port
        return observed, local_port
