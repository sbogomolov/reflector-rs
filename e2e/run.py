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

ALL_CASES: list[TestCase] = [*TEST_CASES]


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

        # The sender lives on the network the traffic originates from and the receiver on the other;
        # "reverse" cases swap which is which. The receiver's interface is pinned so the probe can join
        # the multicast group on it.
        if case.direction == "reverse":
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


def make_runner(args: argparse.Namespace, case: TestCase) -> DockerE2E:
    return DockerE2E(args, case)


def build_reflector_image(image: str) -> None:
    docker(["build", "-t", image, "."], capture=False)


def select_cases(case_names: list[str]) -> list[TestCase]:
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
