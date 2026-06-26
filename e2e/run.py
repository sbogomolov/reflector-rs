#!/usr/bin/env python3
#
# Docker-backed Wake-on-LAN end-to-end tests for the (Rust) reflector.
#
# Each case stands up two dual-stack Docker bridge networks (a source segment and a target segment),
# runs the reflector container straddling both with its in-container interface names pinned to wol_src /
# wol_dst, then runs a sender prober on one segment and a receiver prober on the other and asserts the
# magic packet is (or is not) reflected across. The reflector image is built from this repo's
# ./Dockerfile (a fully static scratch image; binary at /usr/local/bin/reflector).
#
# The reflector container needs CAP_NET_RAW to open its AF_PACKET capture/inject sockets; this script
# grants it on that container only. The prober containers send and receive plain UDP (broadcast /
# multicast group membership), so they run unprivileged. Run the suite with Docker reachable, e.g.:
#
#   python3 e2e/run.py
#   python3 e2e/run.py --case reflects_matching_magic_packet
#   python3 e2e/run.py --skip-build --image reflector:e2e

from __future__ import annotations

import argparse
import dataclasses
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
E2E_DIR = Path(__file__).resolve().parent

DEFAULT_REFLECTOR_IMAGE = "reflector:e2e"
DEFAULT_HELPER_IMAGE = "python:3.13-alpine"
CONFIGURED_MAC = "02:42:ac:11:00:09"
WRONG_MAC = "02:42:ac:11:00:0a"
CONFIGURED_PORT = 40009
UNCONFIGURED_PORT = 40010
ANY_MAC_PORT = 40011
MALFORMED_MAGIC_PAYLOAD_HEX = "ff" * 6 + "0242ac11000a" * 15 + "0242ac11000b"
# --- mDNS (RFC 6762): multicast group 224.0.0.251 / ff02::fb on UDP 5353. ---
MDNS_GROUP_V4 = "224.0.0.251"
MDNS_GROUP_V6 = "ff02::fb"
MDNS_PORT = 5353
MDNS_WRONG_PORT = 5354
# A 12-byte DNS header + "test". The query has QR=0 (flags 0x0000); the response sets QR+AA
# (flags 0x8400). The reflector classifies on the QR bit alone.
MDNS_QUERY_HEX = "00000000000100000000000074657374"
MDNS_RESPONSE_HEX = "00008400000100010000000074657374"
# 8 bytes: below the 12-byte DNS-header minimum, so classify() returns None and drops it.
MDNS_SHORT_QUERY_HEX = "0000000000010000"
# --- Address-change cases: knock out one (interface, family) source on the reflector, prove
# reflection of that family stops, then restore it and prove it resumes. The reflector reacts on
# its own event loop after the netlink notification, so each check polls across that async window.
ADDR_CHANGE_REFLECTED_WINDOW = 4.0
ADDR_CHANGE_SILENCE_WINDOW = 2.5
ADDR_CHANGE_SILENCE_CONSECUTIVE = 2
ADDR_CHANGE_POLL_DEADLINE = 60.0
# A substring of the line the daemon logs immediately before entering its event loop.
REFLECTOR_READY_LOG = "running; press Ctrl-C or send SIGTERM to stop"
RECEIVER_READY_LOG = "receiver ready: UDP socket bound"
CONTAINER_READY_TIMEOUT_SECONDS = 15.0
REFLECTOR_SOURCE_IFNAME = "wol_src"
REFLECTOR_TARGET_IFNAME = "wol_dst"
RECEIVER_IFNAME = "probe0"

IPV6_ALL_NODES = "ff02::1"


class CommandError(RuntimeError):
    def __init__(self, command: list[str], result: subprocess.CompletedProcess[str]) -> None:
        self.command = command
        self.result = result
        super().__init__(f"command failed with exit code {result.returncode}: {format_command(command)}")


@dataclasses.dataclass(frozen=True)
class TestCase:
    name: str
    send_port: int
    receive_port: int
    expect_mac: str | None
    timeout_seconds: float
    send_mac: str | None = None
    send_payload_hex: str | None = None
    # IP version exercised end to end. The reflector runs both pipelines from one config; each case
    # drives just one of them.
    family: int = 4
    # Reflection direction. "forward" sends from the source network and receives on the target (WoL);
    # "reverse" swaps them. Carried so non-WoL protocols (mDNS responses, etc.) re-add as small diffs.
    direction: str = "forward"
    # Multicast group to send to and join on the receiver. None keeps the WoL broadcast / all-nodes path.
    group: str | None = None
    # Exact payload the receiver must see, for protocols relayed verbatim. None falls back to the
    # magic-packet / expect-none expectation.
    expect_payload_hex: str | None = None

    @property
    def send_address(self) -> str:
        if self.group is not None:
            return self.group
        return IPV6_ALL_NODES if self.family == 6 else "255.255.255.255"


TEST_CASES = [
    TestCase(
        name="reflects_matching_magic_packet",
        send_port=CONFIGURED_PORT,
        receive_port=CONFIGURED_PORT,
        expect_mac=CONFIGURED_MAC,
        timeout_seconds=5.0,
        send_mac=CONFIGURED_MAC,
    ),
    TestCase(
        name="reflects_matching_magic_packet_ipv6",
        send_port=CONFIGURED_PORT,
        receive_port=CONFIGURED_PORT,
        expect_mac=CONFIGURED_MAC,
        timeout_seconds=5.0,
        send_mac=CONFIGURED_MAC,
        family=6,
    ),
    TestCase(
        name="ignores_wrong_mac",
        send_port=CONFIGURED_PORT,
        receive_port=CONFIGURED_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_mac=WRONG_MAC,
    ),
    TestCase(
        name="ignores_unconfigured_port",
        send_port=UNCONFIGURED_PORT,
        receive_port=UNCONFIGURED_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_mac=CONFIGURED_MAC,
    ),
    TestCase(
        name="reflects_magic_packet_without_configured_mac",
        send_port=ANY_MAC_PORT,
        receive_port=ANY_MAC_PORT,
        expect_mac=WRONG_MAC,
        timeout_seconds=5.0,
        send_mac=WRONG_MAC,
    ),
    TestCase(
        name="ignores_malformed_packet_without_configured_mac",
        send_port=ANY_MAC_PORT,
        receive_port=ANY_MAC_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=MALFORMED_MAGIC_PAYLOAD_HEX,
    ),
]

# mDNS reflection is directional: queries relay source->target ("forward"), responses
# target->source ("reverse"). Both are relayed verbatim, so the receiver asserts the exact bytes
# it sent. The drop cases assert nothing arrives (the wrong direction, a too-short payload, or a
# port the dispatcher filter never passes).
MDNS_CASES = [
    TestCase(
        name="reflects_mdns_query",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=MDNS_QUERY_HEX,
        expect_payload_hex=MDNS_QUERY_HEX,
        group=MDNS_GROUP_V4,
        direction="forward",
    ),
    TestCase(
        name="reflects_mdns_response",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=MDNS_RESPONSE_HEX,
        expect_payload_hex=MDNS_RESPONSE_HEX,
        group=MDNS_GROUP_V4,
        direction="reverse",
    ),
    TestCase(
        name="reflects_mdns_query_ipv6",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=MDNS_QUERY_HEX,
        expect_payload_hex=MDNS_QUERY_HEX,
        group=MDNS_GROUP_V6,
        family=6,
        direction="forward",
    ),
    TestCase(
        name="reflects_mdns_response_ipv6",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=MDNS_RESPONSE_HEX,
        expect_payload_hex=MDNS_RESPONSE_HEX,
        group=MDNS_GROUP_V6,
        family=6,
        direction="reverse",
    ),
    # A query sent target->source hits the target's response-only handler and is dropped.
    TestCase(
        name="ignores_mdns_query_in_response_direction",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=MDNS_QUERY_HEX,
        group=MDNS_GROUP_V4,
        direction="reverse",
    ),
    # A response sent source->target hits the source's query-only handler and is dropped.
    TestCase(
        name="ignores_mdns_response_in_query_direction",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=MDNS_RESPONSE_HEX,
        group=MDNS_GROUP_V4,
        direction="forward",
    ),
    # 8 bytes < the 12-byte DNS header, so classify() returns None and drops it.
    TestCase(
        name="ignores_mdns_too_short_query",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=MDNS_SHORT_QUERY_HEX,
        group=MDNS_GROUP_V4,
        direction="forward",
    ),
    # The dispatcher filter pins dst_port=5353, so a 5354 datagram never reaches a handler.
    TestCase(
        name="ignores_mdns_wrong_port",
        send_port=MDNS_WRONG_PORT,
        receive_port=MDNS_WRONG_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=MDNS_QUERY_HEX,
        group=MDNS_GROUP_V4,
        direction="forward",
    ),
]

# Per-protocol probe parameters for the address-change phases: wol sends a magic packet (no payload
# or group); mdns sends a query to its family's group, relayed verbatim.
PROBE_SPECS = {
    "wol": {"port": CONFIGURED_PORT, "payload": None, "group_v4": None, "group_v6": None},
    "mdns": {
        "port": MDNS_PORT,
        "payload": MDNS_QUERY_HEX,
        "group_v4": MDNS_GROUP_V4,
        "group_v6": MDNS_GROUP_V6,
    },
}


@dataclasses.dataclass(frozen=True)
class Phase:
    # One knock-out within an address-change case: take down a single (interface, family) source
    # address on the reflector, prove reflection of `protocol`/`family` stops, then restore it and
    # prove reflection resumes -- all via real traffic.
    label: str
    protocol: str  # "wol" | "mdns" -> PROBE_SPECS
    family: int  # 4 | 6
    interface: str  # "source" (wol_src) | "target" (wol_dst): which reflector interface to toggle


@dataclasses.dataclass(frozen=True)
class AddressChangeCase:
    name: str
    config: str  # config file (relative to e2e/), defining a dual-family reflector set
    phases: tuple[Phase, ...]


ADDRESS_CHANGE_CASES = [
    AddressChangeCase(
        name="mdns_address_change",
        config="config-addrchange.toml",
        phases=(
            # source IPv4: knocking out the source's v4 invalidates its kernel multicast membership,
            # so the source capture stops seeing v4 queries -- reflection stops at the ingress; the
            # monitor rejoins on restore. target IPv6: the target is the egress, so the per-packet
            # source-address gate drops the v6 re-emit; the monitor refreshes egress addrs on restore.
            Phase(label="source IPv4", protocol="mdns", family=4, interface="source"),
            Phase(label="target IPv6", protocol="mdns", family=6, interface="target"),
        ),
    ),
]

ALL_CASES: list[TestCase | AddressChangeCase] = [*TEST_CASES, *MDNS_CASES, *ADDRESS_CHANGE_CASES]


def format_command(command: list[str]) -> str:
    return " ".join(command)


def run_command(
    command: list[str],
    *,
    cwd: Path = REPO_ROOT,
    check: bool = True,
    capture: bool = True,
    echo: bool = True,
) -> subprocess.CompletedProcess[str]:
    if echo:
        print(f"+ {format_command(command)}", flush=True)
    stdout = subprocess.PIPE if capture else None
    stderr = subprocess.PIPE if capture else None
    result = subprocess.run(command, cwd=cwd, text=True, stdout=stdout, stderr=stderr, check=False)
    if check and result.returncode != 0:
        raise CommandError(command, result)
    return result


def docker(
    args: list[str],
    *,
    check: bool = True,
    capture: bool = True,
    echo: bool = True,
) -> subprocess.CompletedProcess[str]:
    return run_command(["docker", *args], check=check, capture=capture, echo=echo)


def require_command(command: str) -> None:
    if shutil.which(command) is None:
        raise RuntimeError(f"required command not found: {command}")


def magic_packet_hex(mac: str) -> str:
    octets = bytes(int(part, 16) for part in mac.split(":"))
    return (b"\xff" * 6 + octets * 16).hex()


class DockerE2E:
    def __init__(self, args: argparse.Namespace, case: TestCase) -> None:
        self.args = args
        self.case = case
        self.prefix = f"reflector-e2e-{case.name.replace('_', '-')}-{uuid.uuid4().hex[:8]}"
        self.source_network = f"{self.prefix}-source"
        self.target_network = f"{self.prefix}-target"
        self.reflector_container = f"{self.prefix}-reflector"
        self.receiver_container = f"{self.prefix}-receiver"
        self.sender_container = f"{self.prefix}-sender"
        self.containers = [self.sender_container, self.receiver_container, self.reflector_container]
        self.networks = [self.source_network, self.target_network]
        self.config_path = E2E_DIR / "config.toml"

        self._select_direction(case.direction)

    def _select_direction(self, direction: str) -> None:
        # The sender lives on the network the traffic originates from and the receiver on the other;
        # "reverse" swaps which is which. The receiver's interface is pinned so the probe can join the
        # multicast group on it. The address-change runner re-selects per phase (its phases differ in
        # direction), so this stays a method rather than inline __init__ code.
        if direction == "reverse":
            self.sender_network, self.sender_ifname = self.target_network, REFLECTOR_TARGET_IFNAME
            self.receiver_network = self.source_network
        else:
            self.sender_network, self.sender_ifname = self.source_network, REFLECTOR_SOURCE_IFNAME
            self.receiver_network = self.target_network
        self.receiver_ifname = RECEIVER_IFNAME

    def __enter__(self) -> DockerE2E:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        if exc_type is not None:
            self.print_diagnostics()

        if exc_type is not None and self.args.keep_on_failure:
            print(f"keeping Docker resources for failed case {self.case.name}: {self.prefix}", flush=True)
            return False

        self.cleanup()
        return False

    def cleanup(self) -> None:
        for container in self.containers:
            docker(["rm", "-f", container], check=False)
        for network in self.networks:
            docker(["network", "rm", network], check=False)

    def setup_networks(self) -> None:
        # Both networks are dual-stack: IPv4 cases are unaffected, and IPv6 cases need the bridges to
        # carry IPv6 so the reflector can listen on / emit to ff02::1.
        docker(["network", "create", "--driver", "bridge", "--ipv6", self.source_network])
        docker(["network", "create", "--driver", "bridge", "--ipv6", self.target_network])

    def start_reflector(self) -> None:
        # Pin in-container interface names per network. Without this, Docker's interface naming at start
        # time is non-deterministic when multiple endpoints are attached, which made the reflector's
        # SO_BINDTODEVICE land on the wrong bridge ~16% of runs. Using a non-"eth" prefix avoids the
        # prefix-collision caveat in moby/moby#49155. Requires Docker 28.0+ (the
        # com.docker.network.endpoint.ifname driver-opt).
        docker(
            [
                "create",
                "--name",
                self.reflector_container,
                "--network",
                f"name={self.source_network},driver-opt=com.docker.network.endpoint.ifname={REFLECTOR_SOURCE_IFNAME}",
                "--network",
                f"name={self.target_network},driver-opt=com.docker.network.endpoint.ifname={REFLECTOR_TARGET_IFNAME}",
                "--cap-add",
                "NET_RAW",
                "--mount",
                f"type=bind,source={self.config_path},target=/etc/reflector/config.toml,readonly",
                self.args.image,
                "/etc/reflector/config.toml",
            ]
        )
        docker(["start", self.reflector_container])
        self.wait_for_reflector()

    def wait_for_container_log(self, container: str, marker: str, description: str) -> None:
        deadline = time.monotonic() + CONTAINER_READY_TIMEOUT_SECONDS
        last_state = "unknown"
        while time.monotonic() < deadline:
            logs = docker(["logs", container], check=False, echo=False)
            if marker in f"{logs.stdout}{logs.stderr}":
                return

            result = docker(
                ["inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", container],
                check=False,
                echo=False,
            )
            if result.returncode == 0:
                last_state = result.stdout.strip()
                if last_state.startswith("false "):
                    raise RuntimeError(f"{description} exited before becoming ready: {last_state}")

            time.sleep(0.1)

        raise RuntimeError(f"timed out waiting for {description} readiness marker ({marker}); last state: {last_state}")

    def wait_for_reflector(self) -> None:
        self.wait_for_container_log(self.reflector_container, REFLECTOR_READY_LOG, "reflector")

    def start_receiver(self, case: TestCase | None = None) -> None:
        case = case or self.case
        command = [
            "run",
            "-d",
            "--name",
            self.receiver_container,
            "--network",
            f"name={self.receiver_network},driver-opt=com.docker.network.endpoint.ifname={self.receiver_ifname}",
            "--mount",
            f"type=bind,source={E2E_DIR},target=/e2e,readonly",
            self.args.helper_image,
            "python3",
            "/e2e/probe.py",
            "receive",
            "--port",
            str(case.receive_port),
            "--timeout",
            str(case.timeout_seconds),
        ]
        if case.expect_payload_hex is not None:
            command.extend(["--expect-payload-hex", case.expect_payload_hex])
        elif case.expect_mac is not None:
            command.extend(["--expect-mac", case.expect_mac])
        else:
            command.append("--expect-none")

        command.extend(["--family", str(case.family)])
        if case.group is not None:
            command.extend(["--join-group", case.group, "--interface", self.receiver_ifname])

        docker(command)
        self.wait_for_receiver()

    def wait_for_receiver(self) -> None:
        self.wait_for_container_log(self.receiver_container, RECEIVER_READY_LOG, "receiver")

    def run_sender(self, case: TestCase | None = None) -> None:
        case = case or self.case
        if case.send_payload_hex is not None:
            payload_args = ["--payload-hex", case.send_payload_hex]
        elif case.send_mac is not None:
            payload_args = ["--mac", case.send_mac]
        else:
            raise RuntimeError(f"case {case.name} has no send payload")

        docker(
            [
                "run",
                "--name",
                self.sender_container,
                # Pin the sender's interface name so the probe can scope multicast egress to it
                # deterministically (see start_reflector for the rationale).
                "--network",
                f"name={self.sender_network},driver-opt=com.docker.network.endpoint.ifname={self.sender_ifname}",
                "--mount",
                f"type=bind,source={E2E_DIR},target=/e2e,readonly",
                self.args.helper_image,
                "python3",
                "/e2e/probe.py",
                "send",
                *payload_args,
                "--port",
                str(case.send_port),
                "--address",
                case.send_address,
                "--interface",
                self.sender_ifname,
            ]
        )

    def wait_for_result(self) -> None:
        result = docker(["wait", self.receiver_container])
        exit_code = result.stdout.strip()
        logs = docker(["logs", self.receiver_container], check=False)
        if logs.stdout:
            print(logs.stdout, end="", flush=True)
        if logs.stderr:
            print(logs.stderr, end="", file=sys.stderr, flush=True)

        if exit_code != "0":
            raise RuntimeError(f"receiver failed with exit code {exit_code}")

    def print_reflector_logs(self) -> None:
        logs = docker(["logs", self.reflector_container], check=False)
        print(f"--- reflector logs: {self.case.name} ---", flush=True)
        if logs.stdout:
            print(logs.stdout, end="", flush=True)
        if logs.stderr:
            print(logs.stderr, end="", file=sys.stderr, flush=True)
        if not logs.stdout and not logs.stderr:
            print("<empty>", flush=True)

    def print_diagnostics(self) -> None:
        print(f"\n--- diagnostics for {self.case.name} ({self.prefix}) ---", file=sys.stderr, flush=True)
        for container in self.containers:
            inspect = docker(["inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", container], check=False)
            if inspect.returncode == 0:
                print(f"{container}: {inspect.stdout.strip()}", file=sys.stderr, flush=True)

            logs = docker(["logs", container], check=False)
            if logs.stdout or logs.stderr:
                print(f"--- logs: {container} ---", file=sys.stderr, flush=True)
                if logs.stdout:
                    print(logs.stdout, end="", file=sys.stderr, flush=True)
                if logs.stderr:
                    print(logs.stderr, end="", file=sys.stderr, flush=True)

        for network in self.networks:
            inspect = docker(["network", "inspect", network], check=False)
            if inspect.returncode == 0 and inspect.stdout:
                print(f"--- network: {network} ---", file=sys.stderr, flush=True)
                print(inspect.stdout, end="", file=sys.stderr, flush=True)

    def run(self) -> None:
        print(f"\n=== {self.case.name} ===", flush=True)
        self.setup_networks()
        self.start_reflector()
        self.start_receiver()
        self.run_sender()
        self.wait_for_result()
        print(f"PASS {self.case.name}", flush=True)
        if self.args.show_reflector_logs:
            time.sleep(0.5)
            self.print_reflector_logs()


class DockerAddressChange(DockerE2E):
    # Proves the dynamic family bring-up/teardown end to end: with a dual-family reflector running,
    # knock out one (interface, family) source address at a time and verify -- with real traffic, not
    # logs -- that reflection of exactly that family stops, then resumes once the address returns. The
    # reflector reacts on its own event loop after the netlink notification, so every check polls
    # across that async window. All phases probe forward (source -> target).
    def __init__(self, args: argparse.Namespace, case: AddressChangeCase) -> None:
        shim = TestCase(
            name=case.name,
            send_port=MDNS_PORT,
            receive_port=MDNS_PORT,
            expect_mac=None,
            timeout_seconds=ADDR_CHANGE_REFLECTED_WINDOW,
            direction="forward",
        )
        super().__init__(args, shim)
        self.ac = case
        self.config_path = E2E_DIR / case.config

    def _phase_case(self, phase: Phase, *, expect: bool, timeout: float) -> TestCase:
        spec = PROBE_SPECS[phase.protocol]
        is_wol = phase.protocol == "wol"
        # A direction stops when its re-emit (egress) interface loses the family -- the reliable,
        # guaranteed mechanism (the per-packet egress send-gate). The target is the egress for forward
        # queries (source->target); the source is the egress for reverse responses (target->source).
        # So probe the direction whose egress is the knocked-out interface. (The ingress-membership
        # path can't be exercised here: our raw AF_PACKET capture taps below the IP membership filter
        # and the Docker bridge floods multicast, so losing the ingress membership never blinds it.)
        reverse = not is_wol and phase.interface == "source"
        direction = "reverse" if reverse else "forward"
        group = None if is_wol else (spec["group_v6"] if phase.family == 6 else spec["group_v4"])
        # mDNS queries flow forward, responses reverse: send the kind the probed direction relays.
        payload = None if is_wol else (MDNS_RESPONSE_HEX if reverse else spec["payload"])
        return TestCase(
            name=self.ac.name,
            send_port=spec["port"],
            receive_port=spec["port"],
            expect_mac=(CONFIGURED_MAC if (expect and is_wol) else None),
            timeout_seconds=timeout,
            send_mac=(CONFIGURED_MAC if is_wol else None),
            send_payload_hex=payload,
            family=phase.family,
            direction=direction,
            group=group,
            expect_payload_hex=(payload if (expect and not is_wol) else None),
        )

    def _probe(self, phase: Phase, *, expect: bool, timeout: float) -> bool:
        # One round trip: (re)start a fresh receiver and sender for the phase's family/group, then
        # report whether the receiver saw the expected packet within `timeout`.
        docker(["rm", "-f", self.receiver_container, self.sender_container], check=False, echo=False)
        case = self._phase_case(phase, expect=expect, timeout=timeout)
        self._select_direction(case.direction)
        self.start_receiver(case)
        self.run_sender(case)
        return docker(["wait", self.receiver_container]).stdout.strip() == "0"

    def _poll_reflected(self, phase: Phase) -> bool:
        deadline = time.monotonic() + ADDR_CHANGE_POLL_DEADLINE
        while time.monotonic() < deadline:
            if self._probe(phase, expect=True, timeout=ADDR_CHANGE_REFLECTED_WINDOW):
                return True
        return False

    def _poll_not_reflected(self, phase: Phase) -> bool:
        # Require consecutive silent windows: while reflection is still up the probe returns quickly
        # (the reflected packet arrives, failing --expect-none), resetting the streak; only a genuine
        # teardown yields an unbroken run of silences before the deadline.
        deadline = time.monotonic() + ADDR_CHANGE_POLL_DEADLINE
        consecutive = 0
        while time.monotonic() < deadline:
            if self._probe(phase, expect=False, timeout=ADDR_CHANGE_SILENCE_WINDOW):
                consecutive += 1
                if consecutive >= ADDR_CHANGE_SILENCE_CONSECUTIVE:
                    return True
            else:
                consecutive = 0
        return False

    def _sidecar(self, script: str, *, capture: bool = False) -> str:
        # Address changes need CAP_NET_ADMIN and a writable /proc/sys, which the reflector container
        # (scratch image, NET_RAW only) has by neither. Run a throwaway privileged container in the
        # reflector's network namespace, so `ip addr` / the disable_ipv6 sysctl act on the very
        # interfaces the reflector watches -- without widening the reflector's own privileges.
        result = docker([
            "run", "--rm", "--privileged", "--network", f"container:{self.reflector_container}",
            self.args.helper_image, "sh", "-ec", script,
        ])
        return result.stdout.strip() if capture else ""

    def _set_address(
        self, interface: str, family: int, *, up: bool, cidr: str | None = None
    ) -> str | None:
        # Bring one (interface, family) source address down or back up. IPv6 toggles the disable_ipv6
        # sysctl (which drops every v6 address and, on re-enable, lets the kernel regenerate a usable
        # link-local); v4 has no equivalent, so it deletes and later re-adds the exact CIDR. Returns
        # the removed v4 CIDR so the caller can restore it.
        ifname = REFLECTOR_SOURCE_IFNAME if interface == "source" else REFLECTOR_TARGET_IFNAME
        if family == 6:
            self._sidecar(f"echo {0 if up else 1} > /proc/sys/net/ipv6/conf/{ifname}/disable_ipv6")
            return None
        if up:
            if cidr is None:
                raise RuntimeError("restoring an IPv4 address requires the CIDR captured on removal")
            self._sidecar(f"ip addr add {cidr} dev {ifname}")
            return cidr
        captured = self._sidecar(
            f"ip -o -4 addr show dev {ifname} | awk '/inet /{{print $4; exit}}'", capture=True
        )
        if not captured:
            raise RuntimeError(f"no IPv4 address on {ifname} to remove")
        self._sidecar(f"ip addr del {captured} dev {ifname}")
        return captured

    def _run_phase(self, phase: Phase) -> None:
        desc = f"{self.ac.name} / {phase.label}"
        print(f"--- phase: {desc} ({phase.protocol} IPv{phase.family}) ---", flush=True)

        if not self._poll_reflected(phase):
            raise RuntimeError(f"{desc}: no baseline reflection before the change")
        print(f"{desc}: baseline reflected", flush=True)

        cidr = self._set_address(phase.interface, phase.family, up=False)
        if not self._poll_not_reflected(phase):
            raise RuntimeError(
                f"{desc}: reflection continued after the {phase.interface} IPv{phase.family} "
                f"address was removed"
            )
        print(f"{desc}: reflection stopped after address removal", flush=True)

        self._set_address(phase.interface, phase.family, up=True, cidr=cidr)
        if not self._poll_reflected(phase):
            raise RuntimeError(
                f"{desc}: reflection did not resume after the {phase.interface} IPv{phase.family} "
                f"address was restored"
            )
        print(f"{desc}: reflection resumed after address restore", flush=True)

    def _assert_address_changes_logged(self) -> None:
        # Full-parity log check (the Rust equivalent of the C++'s capability-down assertion): every
        # phase removed then restored a source address, so the reflector's AddressMonitor must have
        # logged both transitions -- with the monitor off it logs neither. And no reflect-failure WARN
        # may appear: a send attempted on an addressless egress would mean the per-packet gate failed
        # to catch the drop.
        logs = docker(["logs", self.reflector_container], check=False)
        text = f"{logs.stdout}\n{logs.stderr}"
        for phase in self.ac.phases:
            ifname = REFLECTOR_SOURCE_IFNAME if phase.interface == "source" else REFLECTOR_TARGET_IFNAME
            family = f"IPv{phase.family}"
            for verb in ("lost", "gained"):
                needle = f"interface {ifname}: {verb} {family}"
                if needle not in text:
                    raise RuntimeError(
                        f"{self.ac.name}: reflector never logged \"{needle}\" -- the address monitor "
                        f"did not observe the change"
                    )
        if "cannot reflect" in text:
            raise RuntimeError(
                f"{self.ac.name}: reflector logged a reflect failure -- a send was attempted on an "
                f"addressless egress (the gate did not catch the drop)"
            )

    def run(self) -> None:
        print(f"\n=== {self.ac.name} ===", flush=True)
        self.setup_networks()
        self.start_reflector()
        for phase in self.ac.phases:
            self._run_phase(phase)
        self._assert_address_changes_logged()
        print(f"PASS {self.ac.name}", flush=True)
        if self.args.show_reflector_logs:
            time.sleep(0.5)
            self.print_reflector_logs()


def make_runner(args: argparse.Namespace, case: TestCase | AddressChangeCase) -> DockerE2E:
    if isinstance(case, AddressChangeCase):
        return DockerAddressChange(args, case)
    return DockerE2E(args, case)


def build_reflector_image(image: str) -> None:
    docker(["build", "-t", image, "."], capture=False)


def select_cases(case_names: list[str]) -> list[TestCase | AddressChangeCase]:
    if not case_names:
        return ALL_CASES

    cases_by_name = {case.name: case for case in ALL_CASES}
    unknown = sorted(set(case_names) - set(cases_by_name))
    if unknown:
        available = ", ".join(sorted(cases_by_name))
        raise RuntimeError(f"unknown e2e case(s): {', '.join(unknown)}. Available cases: {available}")

    return [cases_by_name[name] for name in case_names]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Docker-backed reflector WoL e2e tests")
    parser.add_argument("--image", default=DEFAULT_REFLECTOR_IMAGE,
        help="reflector image tag to run (default: reflector:e2e)")
    parser.add_argument("--skip-build", action="store_true", help="use --image without building it first")
    parser.add_argument("--helper-image", default=DEFAULT_HELPER_IMAGE, help="Python image used for UDP probes")
    parser.add_argument("--keep-on-failure", action="store_true", help="leave Docker resources behind after a failure")
    parser.add_argument("--show-reflector-logs", action="store_true", help="print reflector container logs after each passing case")
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        choices=[case.name for case in ALL_CASES],
        help="e2e case to run; may be passed more than once",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    require_command("docker")

    cases = select_cases(args.case)
    print(f"expected magic payload: {magic_packet_hex(CONFIGURED_MAC)}", flush=True)

    if not args.skip_build:
        build_reflector_image(args.image)

    for case in cases:
        with make_runner(args, case) as runner:
            runner.run()

    print(f"\nPASS {len(cases)} e2e case(s)", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CommandError as exc:
        print(str(exc), file=sys.stderr)
        if exc.result.stdout:
            print(exc.result.stdout, end="", file=sys.stderr)
        if exc.result.stderr:
            print(exc.result.stderr, end="", file=sys.stderr)
        raise SystemExit(1)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
