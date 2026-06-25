#!/usr/bin/env python3
#
# In-container UDP prober for the reflector Wake-on-LAN e2e tests. run.py drives two of these in
# separate helper containers: a `receive` prober binds the receive port (and, for IPv6, joins the
# all-nodes group on its pinned interface) and asserts what it sees, while a `send` prober emits the
# magic packet (broadcast for IPv4, all-nodes multicast for IPv6) toward the reflector. The receiver's
# process exit code is the verdict run.py waits on: 0 = expectation held, non-zero = failed.
#
# This file is WoL-only. The mDNS/SSDP/DIAL probe verbs (respond/search/dial-device/dial-client) from
# the C++ harness are intentionally absent; the send/receive core and the magic-packet + multicast-join
# helpers below are exactly what re-adding those protocols would build on.

from __future__ import annotations

import argparse
import binascii
import socket
import struct
import sys
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

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
