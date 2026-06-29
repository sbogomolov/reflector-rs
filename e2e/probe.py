#!/usr/bin/env python3
#
# In-container UDP prober for the reflector Wake-on-LAN e2e tests. run.py drives two of these in
# separate helper containers: a `receive` prober binds the receive port (and, for IPv6, joins the
# all-nodes group on its pinned interface) and asserts what it sees, while a `send` prober emits the
# magic packet (broadcast for IPv4, all-nodes multicast for IPv6) toward the reflector. The receiver's
# process exit code is the verdict run.py waits on: 0 = expectation held, non-zero = failed.
#
# The send/receive verbs cover WoL and the verbatim-relay protocols (mDNS, one-way SSDP). The
# respond/search verbs drive the SSDP M-SEARCH round trip: a `respond` device unicasts a 200 OK back to
# whoever searched, and a `search` searcher awaits that reply proxied across segments by the reflector.
# The DIAL probe verbs (dial-device/dial-client) from the C++ harness are intentionally absent: DIAL is
# unimplemented in this project.

from __future__ import annotations

import argparse
import binascii
import http.server
import socket
import struct
import sys
import threading
import time


def parse_mac(value: str) -> bytes:
    parts = value.split(":")
    if len(parts) != 6:
        raise argparse.ArgumentTypeError(f"invalid MAC address: {value}")

    try:
        octets = bytes(int(part, 16) for part in parts)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid MAC address: {value}") from exc

    if any(len(part) != 2 for part in parts):
        raise argparse.ArgumentTypeError(f"invalid MAC address: {value}")

    return octets


def magic_packet(mac: str) -> bytes:
    mac_bytes = parse_mac(mac)
    return b"\xff" * 6 + mac_bytes * 16


def parse_payload_hex(value: str) -> bytes:
    try:
        return binascii.unhexlify(value)
    except (binascii.Error, ValueError) as exc:
        raise argparse.ArgumentTypeError(f"invalid hex payload: {value}") from exc


def packet_hex(payload: bytes) -> str:
    return binascii.hexlify(payload).decode("ascii")


def is_ipv6(address: str) -> bool:
    return ":" in address


def is_ipv4_multicast(address: str) -> bool:
    return 224 <= int(address.split(".")[0]) <= 239


def join_group(sock: socket.socket, family: int, group: str, interface: str) -> None:
    ifindex = socket.if_nametoindex(interface)
    if family == socket.AF_INET6:
        mreq = socket.inet_pton(socket.AF_INET6, group) + struct.pack("@I", ifindex)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    else:
        mreq = struct.pack("@4s4si", socket.inet_aton(group), b"\x00\x00\x00\x00", ifindex)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)


def send(args: argparse.Namespace) -> int:
    payload = args.payload_hex if args.payload_hex is not None else magic_packet(args.mac)

    if is_ipv6(args.address):
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            scope_id = 0
            if args.interface:
                scope_id = socket.if_nametoindex(args.interface)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, scope_id)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
            # The scope id in the address tuple disambiguates the link-local destination.
            sock.sendto(payload, (args.address, args.port, 0, scope_id))
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            if is_ipv4_multicast(args.address):
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                if args.interface:
                    ifindex = socket.if_nametoindex(args.interface)
                    mreqn = struct.pack("@4s4si", b"\x00\x00\x00\x00", b"\x00\x00\x00\x00", ifindex)
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
            else:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(payload, (args.address, args.port))

    print(f"sent {len(payload)} bytes to {args.address}:{args.port}: {packet_hex(payload)}", flush=True)
    return 0


def expected_payload(args: argparse.Namespace) -> bytes | None:
    if args.expect_none:
        return None
    if args.expect_payload_hex is not None:
        return args.expect_payload_hex
    return magic_packet(args.expect_mac)


def receive(args: argparse.Namespace) -> int:
    expected = expected_payload(args)
    deadline = time.monotonic() + args.timeout

    family = socket.AF_INET6 if args.family == 6 else socket.AF_INET
    bind_address = "::" if family == socket.AF_INET6 else "0.0.0.0"

    with socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_address, args.port))
        if args.join_group is not None:
            # Multicast is only delivered to sockets that joined the group on the receiving
            # interface; broadcast/all-nodes (the WoL IPv4 path) needs no join.
            join_group(sock, family, args.join_group, args.interface)
        print(f"receiver ready: UDP socket bound on port {args.port}", flush=True)

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            sock.settimeout(remaining)
            try:
                payload, peer = sock.recvfrom(4096)
            except TimeoutError:
                break

            print(f"received {len(payload)} bytes from {peer[0]}:{peer[1]}: {packet_hex(payload)}", flush=True)

            if args.expect_none:
                print("expected no packets, but one was received", file=sys.stderr, flush=True)
                return 1

            if payload == expected:
                return 0

            print("received payload does not match expected magic packet", file=sys.stderr, flush=True)
            return 1

    if args.expect_none:
        print(f"received no packets for {args.timeout:.3f}s", flush=True)
        return 0

    print(f"timed out waiting for expected packet after {args.timeout:.3f}s", file=sys.stderr, flush=True)
    return 1


def respond(args: argparse.Namespace) -> int:
    # The SSDP round-trip "device": wait for one (relayed) M-SEARCH on the group, then unicast a 200 OK
    # straight back to its sender. The sender is the reflector's reserved port on the target segment,
    # which proxies the reply back to the searcher on the source segment.
    family = socket.AF_INET6 if args.family == 6 else socket.AF_INET
    bind_address = "::" if family == socket.AF_INET6 else "0.0.0.0"

    with socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_address, args.port))
        if args.join_group is not None:
            join_group(sock, family, args.join_group, args.interface)
        # Readiness marker so run.py can sequence the searcher after the responder is listening.
        print(f"responder ready: UDP socket bound on port {args.port}", flush=True)

        sock.settimeout(args.timeout)
        try:
            payload, peer = sock.recvfrom(4096)
        except TimeoutError:
            print(f"responder: no datagram for {args.timeout:.3f}s", file=sys.stderr, flush=True)
            return 1

        print(f"responder received {len(payload)} bytes from {peer[0]}:{peer[1]}", flush=True)
        # Reply straight back to the sender (the reflector's target_if:P); it proxies to the searcher.
        # peer is the full tuple recvfrom returned (4-tuple for IPv6), preserving the link-local scope.
        sock.sendto(args.reply_hex, peer)
        print(f"responder replied {len(args.reply_hex)} bytes to {peer[0]}:{peer[1]}", flush=True)
        return 0


def search(args: argparse.Namespace) -> int:
    # The SSDP round-trip "searcher": send an M-SEARCH to the group from a known source port, then await
    # the proxied unicast 200 OK the reflector relays back from the device on the target segment.
    family = socket.AF_INET6 if args.family == 6 else socket.AF_INET
    bind_address = "::" if family == socket.AF_INET6 else "0.0.0.0"

    with socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_address, args.source_port))  # the searcher's known source port

        scope_id = 0
        if family == socket.AF_INET6:
            if args.interface:
                scope_id = socket.if_nametoindex(args.interface)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, scope_id)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
            dest = (args.address, args.port, 0, scope_id)
        else:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            if args.interface:
                ifindex = socket.if_nametoindex(args.interface)
                mreqn = struct.pack("@4s4si", b"\x00\x00\x00\x00", b"\x00\x00\x00\x00", ifindex)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
            dest = (args.address, args.port)

        print(f"searcher ready: bound source port {args.source_port}", flush=True)
        sock.sendto(args.payload_hex, dest)
        print(f"searcher sent {len(args.payload_hex)} bytes to {args.address}:{args.port}", flush=True)

        sock.settimeout(args.timeout)
        try:
            payload, peer = sock.recvfrom(4096)
        except TimeoutError:
            if args.expect_none:
                print(f"searcher: no reply for {args.timeout:.3f}s (as expected)", flush=True)
                return 0
            print(f"searcher: no reply for {args.timeout:.3f}s", file=sys.stderr, flush=True)
            return 1

        print(f"searcher received {len(payload)} bytes from {peer[0]}:{peer[1]}: {packet_hex(payload)}", flush=True)
        if args.expect_none:
            print("searcher: expected no reply, but one was received", file=sys.stderr, flush=True)
            return 1
        if payload == args.expect_payload_hex:
            return 0
        print("searcher: reply payload does not match expected 200 OK", file=sys.stderr, flush=True)
        return 1


DIAL_SERVICE_TYPE = "urn:dial-multiscreen-org:service:dial:1"


def _own_address(interface: str, family: int) -> str:
    # This container's address on the interface facing the reflector -- the address the reflector's
    # egress-pinned upstream connect() lands on, and the host we advertise in LOCATION / Application-URL.
    # A dummy connect + getsockname resolves it without parsing `ip addr`. The DIAL device is single-homed
    # (target network only), so the route -- and hence the source address -- is unambiguous.
    fam = socket.AF_INET6 if family == 6 else socket.AF_INET
    with socket.socket(fam, socket.SOCK_DGRAM) as probe:
        if family == 6:
            probe.connect(("ff02::1", 9, 0, socket.if_nametoindex(interface)))
        else:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            probe.connect(("255.255.255.255", 9))
        return probe.getsockname()[0]


def dial_device(args: argparse.Namespace) -> int:
    # Emulate a DIAL device: answer the proxied M-SEARCH with a 200 OK whose LOCATION points at our own
    # (target-side) HTTP description endpoint, and serve the description + REST endpoints over TCP. We
    # record the peer address of every accepted HTTP connection: with the device single-homed on the
    # target network, the only client that can reach these endpoints is the reflector's upstream connect,
    # so the recorded peer must be the reflector's target_if address (run.py asserts this).
    own = _own_address(args.interface, args.family)
    peers: set[str] = set()
    host_errors: list[str] = []
    state_lock = threading.Lock()

    def note(peer_ip: str, host, expected: str) -> None:
        # Record the upstream peer (must be the reflector's target_if address) and verify the request's Host
        # was rewritten to this device's own authority -- the device must never see the reflector's authority.
        with state_lock:
            peers.add(peer_ip)
            if host != expected:
                host_errors.append(f"got {host!r}, expected {expected!r}")

    # A relative-only body, so the proxy never has to rewrite a body byte; every rewritable URL is a header.
    desc_body = (
        '<?xml version="1.0"?>\r\n'
        "<root><device><friendlyName>e2e-dial</friendlyName>"
        "<X_DIALEX_AppsListURL>/apps</X_DIALEX_AppsListURL></device></root>\r\n"
    ).encode()

    class DescHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # noqa: ANN002 - silence the default stderr access log
            pass

        def do_GET(self):  # noqa: N802 - stdlib handler name
            note(self.client_address[0], self.headers.get("Host"), f"{own}:{desc_port}")
            # Application-URL is an absolute header on the REST port: the proxy must rewrite it.
            self.send_response(200)
            self.send_header("Content-Type", "text/xml; charset=utf-8")
            self.send_header("Application-URL", f"http://{own}:{rest_port}/apps")
            self.send_header("Content-Length", str(len(desc_body)))
            self.end_headers()
            self.wfile.write(desc_body)

    class RestHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # noqa: ANN002
            pass

        def _drain_body(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length:
                self.rfile.read(length)

        def _chunked(self, status, body, extra=None):
            # Chunked, like the captured LG TV REST stream: the proxy forwards chunk data verbatim and
            # only parses chunk-size lines to find the terminating 0-chunk.
            self.send_response(status)
            self.send_header("Content-Type", "text/xml; charset=utf-8")
            self.send_header("Transfer-Encoding", "chunked")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if body:
                self.wfile.write(f"{len(body):x}\r\n".encode() + body + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")

        def do_GET(self):  # noqa: N802
            note(self.client_address[0], self.headers.get("Host"), f"{own}:{rest_port}")
            self._drain_body()
            self._chunked(200, b"<service><state>stopped</state></service>")

        def do_POST(self):  # noqa: N802 - app launch
            note(self.client_address[0], self.headers.get("Host"), f"{own}:{rest_port}")
            self._drain_body()
            # 201 Created with an ABSOLUTE Location on the REST port -- the proxy rewrites this header too.
            self._chunked(201, b"", {"Location": f"http://{own}:{rest_port}{self.path}/run"})

        def do_DELETE(self):  # noqa: N802 - app stop
            note(self.client_address[0], self.headers.get("Host"), f"{own}:{rest_port}")
            self._drain_body()
            self._chunked(200, b"")

    # Bind the HTTP servers on ephemeral ports (the description port is "dynamic" by design). In
    # --unreachable mode no server is started: the advertised port is one we bind-then-close, so the
    # reflector's upstream connect is refused -- exercising the connect-failure path.
    bind_host = "::" if args.family == 6 else "0.0.0.0"
    if args.unreachable:
        with socket.socket(socket.AF_INET6 if args.family == 6 else socket.AF_INET, socket.SOCK_STREAM) as dead:
            dead.bind((bind_host, 0))
            desc_port = dead.getsockname()[1]
        rest_port = desc_port  # unused: nothing is served in this mode
    else:
        server_cls = http.server.ThreadingHTTPServer
        if args.family == 6:
            server_cls = type("V6Server", (http.server.ThreadingHTTPServer,), {"address_family": socket.AF_INET6})
        desc_server = server_cls((bind_host, 0), DescHandler)
        rest_server = server_cls((bind_host, 0), RestHandler)
        desc_port = desc_server.server_address[1]
        rest_port = rest_server.server_address[1]
        threading.Thread(target=desc_server.serve_forever, daemon=True).start()
        threading.Thread(target=rest_server.serve_forever, daemon=True).start()

    family = socket.AF_INET6 if args.family == 6 else socket.AF_INET
    udp_bind = "::" if family == socket.AF_INET6 else "0.0.0.0"
    location = f"http://{own}:{desc_port}/dd.xml"
    with socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((udp_bind, args.port))
        join_group(sock, family, args.join_group, args.interface)
        print(f"dial-device ready: desc {own}:{desc_port} rest {own}:{rest_port} ssdp :{args.port}", flush=True)

        if args.notify:
            # Passive discovery: advertise an unsolicited NOTIFY ssdp:alive periodically (as real devices
            # do), so the later-listening client catches one; the reflector relays each and rewrites LOCATION.
            notify = (
                "NOTIFY * HTTP/1.1\r\n"
                f"HOST: {args.join_group}:{args.port}\r\n"
                "CACHE-CONTROL: max-age=1800\r\n"
                f"LOCATION: {location}\r\n"
                f"NT: {DIAL_SERVICE_TYPE}\r\n"
                "NTS: ssdp:alive\r\n"
                f"USN: uuid:e2e-dial::{DIAL_SERVICE_TYPE}\r\n\r\n"
            ).encode()
            if family == socket.AF_INET6:
                scope = socket.if_nametoindex(args.interface)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, scope)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 2)
                dest = (args.join_group, args.port, 0, scope)
            else:
                ifindex = socket.if_nametoindex(args.interface)
                mreqn = struct.pack("@4s4si", b"\x00\x00\x00\x00", b"\x00\x00\x00\x00", ifindex)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
                dest = (args.join_group, args.port)
            print(f"dial-device advertising NOTIFY (LOCATION {location}) to {args.join_group}:{args.port}", flush=True)
            deadline = time.monotonic() + args.serve_seconds
            while time.monotonic() < deadline:
                sock.sendto(notify, dest)
                time.sleep(0.5)
        else:
            # Active discovery: answer the one proxied M-SEARCH with a 200 OK carrying our LOCATION.
            ok = (
                "HTTP/1.1 200 OK\r\n"
                "CACHE-CONTROL: max-age=1800\r\n"
                f"ST: {DIAL_SERVICE_TYPE}\r\n"
                f"USN: uuid:e2e-dial::{DIAL_SERVICE_TYPE}\r\n"
                f"LOCATION: {location}\r\n\r\n"
            ).encode()
            sock.settimeout(args.timeout)
            try:
                payload, peer = sock.recvfrom(4096)
            except TimeoutError:
                print(f"dial-device: no M-SEARCH for {args.timeout:.3f}s", file=sys.stderr, flush=True)
                return 1
            print(f"dial-device received {len(payload)} bytes from {peer[0]}:{peer[1]}", flush=True)
            sock.sendto(ok, peer)
            print(f"dial-device replied 200 OK (LOCATION {location}) to {peer[0]}:{peer[1]}", flush=True)
            time.sleep(args.serve_seconds)  # keep the HTTP endpoints up for the client's GET/POST/DELETE

    print(f"dial-device upstream peers seen: {sorted(peers)}", flush=True)
    if host_errors:
        print(f"dial-device request Host NOT rewritten to this device: {host_errors}", file=sys.stderr, flush=True)
        return 1
    print("dial-device request Host rewritten to this device on every request", flush=True)
    return 0


def _http_request(host, port, method, path, family, body=b""):
    fam = socket.AF_INET6 if family == 6 else socket.AF_INET
    with socket.socket(fam, socket.SOCK_STREAM) as sock:
        sock.settimeout(8.0)
        sock.connect((host, port) if family == 4 else (host, port, 0, 0))
        req = (f"{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
        sock.sendall(req)
        # Read the full header block first.
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        if b"\r\n\r\n" not in buf:
            raise ConnectionError("no complete HTTP response (upstream aborted)")
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        status = int(lines[0].split(" ")[1])
        headers = {}
        for line in lines[1:]:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
        # Read the body per its framing rather than waiting for the connection close: the reflector
        # defers the client-side close to its eviction timer, so an EOF-driven read would block on that.
        if headers.get("transfer-encoding", "").lower() == "chunked":
            while not rest.endswith(b"0\r\n\r\n"):
                chunk = sock.recv(4096)
                if not chunk:
                    break
                rest += chunk
        elif "content-length" in headers:
            need = int(headers["content-length"])
            while len(rest) < need:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                rest += chunk
    return status, headers, rest


def _authority(url: str) -> str:
    # Strip scheme + path: http://host:port/p -> host:port (IPv6 literals keep their brackets).
    return url.split("://", 1)[1].split("/", 1)[0]


def _dial_discover(args):
    # Return the (reflector-rewritten) SSDP response carrying the device LOCATION, or None on timeout. Active
    # discovery sends an M-SEARCH and reads the unicast 200 OK; passive discovery joins the group and waits
    # for the relayed NOTIFY ssdp:alive.
    family = socket.AF_INET6 if args.family == 6 else socket.AF_INET
    udp_bind = "::" if family == socket.AF_INET6 else "0.0.0.0"
    with socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if args.passive:
            sock.bind((udp_bind, args.port))                       # bind 1900 + join the group to hear NOTIFYs
            join_group(sock, family, args.address, args.interface)
            print(f"dial-client listening for a DIAL NOTIFY on {args.address}:{args.port}", flush=True)
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                sock.settimeout(max(0.1, deadline - time.monotonic()))
                try:
                    payload, peer = sock.recvfrom(4096)
                except TimeoutError:
                    break
                text = payload.decode("latin-1")
                if text.upper().startswith("NOTIFY") and DIAL_SERVICE_TYPE in text \
                        and any(ln.lower().startswith("location:") for ln in text.split("\r\n")):
                    print(f"dial-client received NOTIFY from {peer[0]}:{peer[1]}:\n{text}", flush=True)
                    return text
            print(f"dial-client: no DIAL NOTIFY for {args.timeout:.3f}s", file=sys.stderr, flush=True)
            return None
        # Active discovery: send the M-SEARCH from a bound source port, await the proxied unicast 200 OK.
        sock.bind((udp_bind, args.source_port))
        if family == socket.AF_INET6:
            scope = socket.if_nametoindex(args.interface)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, scope)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
            dest = (args.address, args.port, 0, scope)
        else:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            ifindex = socket.if_nametoindex(args.interface)
            mreqn = struct.pack("@4s4si", b"\x00\x00\x00\x00", b"\x00\x00\x00\x00", ifindex)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
            dest = (args.address, args.port)
        sock.sendto(args.payload_hex, dest)
        print(f"dial-client sent M-SEARCH to {args.address}:{args.port}", flush=True)
        sock.settimeout(args.timeout)
        try:
            payload, peer = sock.recvfrom(4096)
        except TimeoutError:
            print(f"dial-client: no 200 OK for {args.timeout:.3f}s", file=sys.stderr, flush=True)
            return None
        text = payload.decode("latin-1")
        print(f"dial-client received 200 OK from {peer[0]}:{peer[1]}:\n{text}", flush=True)
        return text


def dial_client(args: argparse.Namespace) -> int:
    # Run the full DIAL flow through the reflector and assert each rewritable authority was rewritten to
    # the reflector's source-side address (and never leaks the device's true target-side address). The
    # device is unreachable from this (source) network except via the reflector, so a missing rewrite
    # makes the HTTP step connect to an unroutable address and fail.
    refl = args.reflector_authority   # the reflector's source_if address (host only; LOCATION ports are dynamic)
    device = args.device_authority    # the device's TRUE target-side host, asserted absent from rewrites

    text = _dial_discover(args)
    if text is None:
        return 1
    location = next((ln.split(":", 1)[1].strip() for ln in text.split("\r\n")
                     if ln.lower().startswith("location:")), None)
    if location is None:
        print("dial-client: 200 OK had no LOCATION", file=sys.stderr, flush=True)
        return 1
    loc_host = _authority(location).rsplit(":", 1)[0]
    if loc_host != refl:
        print(f"dial-client: LOCATION host {loc_host!r} is not the reflector authority {refl!r} "
              f"(rewrite missing); full LOCATION {location!r}", file=sys.stderr, flush=True)
        return 1
    if device in _authority(location):
        print(f"dial-client: LOCATION still names the device {device!r}: {location!r}", file=sys.stderr, flush=True)
        return 1
    desc_host, _, desc_port_s = _authority(location).rpartition(":")
    desc_port = int(desc_port_s)
    desc_path = "/" + location.split("://", 1)[1].split("/", 1)[1]
    print(f"dial-client: LOCATION rewritten to reflector authority {desc_host}:{desc_port}", flush=True)

    if args.expect_fetch_failure:
        # The LOCATION was rewritten (the listener was minted), but the device's upstream is dead, so the
        # proxied fetch must fail -- and fail PROMPTLY. The reflector must FIN the client when the upstream
        # connect is refused, not leave it hanging until the eviction timer (~5s). A 2s budget cleanly
        # separates the prompt close from that stall.
        start = time.monotonic()
        try:
            _http_request(desc_host, desc_port, "GET", desc_path, args.family)
        except Exception as exc:  # noqa: BLE001 - any failure (refused / reset / EOF / timeout) is the point
            elapsed = time.monotonic() - start
            if elapsed > 2.0:
                print(f"dial-client: fetch failed but only after {elapsed:.1f}s (> 2s) -- the reflector did "
                      f"not close the client promptly on upstream failure", file=sys.stderr, flush=True)
                return 1
            print(f"dial-client: description fetch failed promptly after {elapsed:.1f}s "
                  f"({type(exc).__name__}: {exc}) -- upstream unreachable, client closed promptly", flush=True)
            return 0
        print("dial-client: description fetch unexpectedly SUCCEEDED (upstream should be unreachable)",
              file=sys.stderr, flush=True)
        return 1

    status, headers, _ = _http_request(desc_host, desc_port, "GET", desc_path, args.family)
    if status != 200:
        print(f"dial-client: GET description -> {status}", file=sys.stderr, flush=True)
        return 1
    app_url = headers.get("application-url")
    if app_url is None:
        print("dial-client: description had no Application-URL", file=sys.stderr, flush=True)
        return 1
    app_host = _authority(app_url).rsplit(":", 1)[0]
    if app_host != refl or device in _authority(app_url):
        print(f"dial-client: Application-URL {app_url!r} not rewritten to reflector authority {refl!r}",
              file=sys.stderr, flush=True)
        return 1
    rest_host, _, rest_port_s = _authority(app_url).rpartition(":")
    rest_port = int(rest_port_s)
    apps_path = "/" + app_url.split("://", 1)[1].split("/", 1)[1]
    print(f"dial-client: Application-URL rewritten to {rest_host}:{rest_port}", flush=True)

    status, headers, _ = _http_request(rest_host, rest_port, "POST", f"{apps_path}/YouTube", args.family,
                                       body=b"pairingCode=e2e")
    if status != 201:
        print(f"dial-client: launch POST -> {status} (expected 201)", file=sys.stderr, flush=True)
        return 1
    run_loc = headers.get("location")
    if run_loc is None:
        print("dial-client: 201 had no LOCATION", file=sys.stderr, flush=True)
        return 1
    run_host = _authority(run_loc).rsplit(":", 1)[0]
    if run_host != refl or device in _authority(run_loc):
        print(f"dial-client: 201 LOCATION {run_loc!r} not rewritten to reflector authority {refl!r}",
              file=sys.stderr, flush=True)
        return 1
    print(f"dial-client: 201 LOCATION rewritten to {_authority(run_loc)}", flush=True)

    run_path = "/" + run_loc.split("://", 1)[1].split("/", 1)[1]
    status, _, _ = _http_request(rest_host, rest_port, "DELETE", run_path, args.family)
    if status not in (200, 204):
        print(f"dial-client: stop DELETE -> {status}", file=sys.stderr, flush=True)
        return 1
    print("dial-client: stop DELETE ok", flush=True)
    print("dial-client: all rewrites confirmed (LOCATION, Application-URL, 201 Location)", flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="UDP probe used by reflector Docker e2e tests")
    subparsers = parser.add_subparsers(dest="command", required=True)

    send_parser = subparsers.add_parser("send", help="send a Wake-on-LAN magic packet")
    payload = send_parser.add_mutually_exclusive_group(required=True)
    payload.add_argument("--mac", help="target MAC address")
    payload.add_argument("--payload-hex", type=parse_payload_hex, help="raw UDP payload encoded as hex")
    send_parser.add_argument("--port", required=True, type=int, help="destination UDP port")
    send_parser.add_argument("--address", default="255.255.255.255", help="destination IP address")
    send_parser.add_argument("--interface", help="egress interface (IPv6 link-local scope)")
    send_parser.set_defaults(func=send)

    receive_parser = subparsers.add_parser("receive", help="receive or reject UDP packets")
    receive_parser.add_argument("--port", required=True, type=int, help="UDP port to bind")
    receive_parser.add_argument("--timeout", required=True, type=float, help="seconds to wait")
    receive_parser.add_argument("--family", default=4, type=int, choices=(4, 6), help="IP version to bind")
    receive_parser.add_argument("--join-group", help="multicast group to join on --interface")
    receive_parser.add_argument("--interface", help="interface to join the multicast group on")

    expectation = receive_parser.add_mutually_exclusive_group(required=True)
    expectation.add_argument("--expect-mac", help="MAC address whose magic packet must be received")
    expectation.add_argument("--expect-payload-hex", type=parse_payload_hex, help="exact UDP payload that must be received")
    expectation.add_argument("--expect-none", action="store_true", help="fail if any UDP packet is received")
    receive_parser.set_defaults(func=receive)

    respond_parser = subparsers.add_parser("respond", help="receive one datagram, then unicast a reply to its sender")
    respond_parser.add_argument("--port", required=True, type=int, help="UDP port to bind")
    respond_parser.add_argument("--timeout", required=True, type=float, help="seconds to wait for the datagram")
    respond_parser.add_argument("--family", default=4, type=int, choices=(4, 6), help="IP version to bind")
    respond_parser.add_argument("--join-group", help="multicast group to join on --interface")
    respond_parser.add_argument("--interface", help="interface to join the multicast group on")
    respond_parser.add_argument("--reply-hex", required=True, type=parse_payload_hex, help="UDP payload to unicast back")
    respond_parser.set_defaults(func=respond)

    search_parser = subparsers.add_parser("search", help="send an M-SEARCH from a bound port, then await the proxied reply")
    search_parser.add_argument("--source-port", required=True, type=int, help="UDP port to bind and send from")
    search_parser.add_argument("--port", required=True, type=int, help="destination UDP port (1900)")
    search_parser.add_argument("--address", required=True, help="multicast group to send to")
    search_parser.add_argument("--interface", help="egress interface for multicast")
    search_parser.add_argument("--family", default=4, type=int, choices=(4, 6), help="IP version")
    search_parser.add_argument("--payload-hex", required=True, type=parse_payload_hex, help="M-SEARCH payload")
    search_parser.add_argument("--timeout", required=True, type=float, help="seconds to await the reply")
    search_expectation = search_parser.add_mutually_exclusive_group(required=True)
    search_expectation.add_argument("--expect-payload-hex", type=parse_payload_hex, help="expected 200 OK payload")
    search_expectation.add_argument("--expect-none", action="store_true", help="fail if any reply is received")
    search_parser.set_defaults(func=search)

    device_parser = subparsers.add_parser(
        "dial-device", help="emulate a DIAL device: SSDP 200 OK + description + REST HTTP endpoints")
    device_parser.add_argument("--port", required=True, type=int, help="SSDP UDP port to bind (1900)")
    device_parser.add_argument("--join-group", required=True, help="SSDP multicast group to join")
    device_parser.add_argument("--interface", required=True, help="interface facing the reflector")
    device_parser.add_argument("--family", default=4, type=int, choices=(4, 6), help="IP version")
    device_parser.add_argument("--timeout", required=True, type=float, help="seconds to await the M-SEARCH")
    device_parser.add_argument("--serve-seconds", required=True, type=float,
                               help="seconds to keep the HTTP endpoints up after answering discovery")
    device_parser.add_argument("--notify", action="store_true",
                               help="passive discovery: advertise periodic NOTIFY instead of awaiting an M-SEARCH")
    device_parser.add_argument("--unreachable", action="store_true",
                               help="advertise a dead HTTP port (no server) so the reflector's upstream is refused")
    device_parser.set_defaults(func=dial_device)

    client_parser = subparsers.add_parser(
        "dial-client", help="run the DIAL flow through the reflector and assert the rewrites")
    client_parser.add_argument("--source-port", type=int, help="M-SEARCH source port (active discovery only)")
    client_parser.add_argument("--port", required=True, type=int, help="SSDP destination/group port (1900)")
    client_parser.add_argument("--address", required=True, help="SSDP multicast group")
    client_parser.add_argument("--interface", required=True, help="egress interface for multicast")
    client_parser.add_argument("--family", default=4, type=int, choices=(4, 6), help="IP version")
    client_parser.add_argument("--payload-hex", type=parse_payload_hex, help="M-SEARCH payload (active only)")
    client_parser.add_argument("--timeout", required=True, type=float, help="seconds to await discovery")
    client_parser.add_argument("--passive", action="store_true",
                               help="passive discovery: listen for a NOTIFY instead of sending an M-SEARCH")
    client_parser.add_argument("--expect-fetch-failure", action="store_true",
                               help="expect the proxied description fetch to fail (upstream unreachable)")
    client_parser.add_argument("--reflector-authority", required=True,
                               help="reflector source_if address (host only; LOCATION ports are dynamic)")
    client_parser.add_argument("--device-authority", required=True,
                               help="device's true target-side host, asserted absent from the rewrites")
    client_parser.set_defaults(func=dial_client)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
