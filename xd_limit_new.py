#!/usr/bin/env python3
"""Raise RAM-aware live limits for an OpenVPN/stunnel server.

This version intentionally changes runtime state only. It does not create a
systemd service, edit stunnel/OpenVPN configuration, or write persistent sysctl
files. PM2 can start it after boot; use --once for a manual apply-and-exit run.
"""

import argparse
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, NamedTuple, Sequence, Tuple


GIB = 1024 ** 3
BASELINE_MEMORY_GIB = 2


class CapacityProfile(NamedTuple):
    name: str
    memory_bytes: int
    memory_gib: int
    scale: float
    system_file_max: int
    kernel_nr_open: int
    process_nofile: int
    process_nproc: int
    service_tasks_max: int
    kernel_threads_max: int
    vm_max_map_count: int
    conntrack_max: int
    conntrack_hashsize: int
    netdev_backlog: int
    netdev_budget: int
    syn_backlog: int
    tw_buckets: int
    tcp_max_orphans: int
    socket_buffer_max: int


def detect_total_memory_bytes() -> int:
    """Return usable host/VM memory without requiring an external package."""
    candidates: List[int] = []
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            if line.startswith("MemTotal:"):
                candidates.append(int(line.split()[1]) * 1024)
                break
    except (OSError, ValueError, IndexError):
        pass

    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        if pages > 0 and page_size > 0:
            candidates.append(int(pages) * int(page_size))
    except (OSError, ValueError):
        pass

    # Respect a finite cgroup limit when the script runs inside a container.
    for path in (
        Path("/sys/fs/cgroup/memory.max"),
        Path("/sys/fs/cgroup/memory/memory.limit_in_bytes"),
    ):
        try:
            raw = path.read_text(encoding="ascii").strip()
            value = int(raw)
            if 256 * 1024 ** 2 <= value < 1 << 60:
                candidates.append(value)
        except (OSError, ValueError):
            pass

    return min(candidates) if candidates else 4 * GIB


def lower_power_of_two(value: int) -> int:
    if value < 1:
        return 1
    return 1 << (value.bit_length() - 1)


def scale_from_baseline(
    base: int,
    memory_gib: int,
    maximum: int,
    minimum: int = 0,
) -> int:
    """Scale the original 2 GiB profile linearly, with a safety ceiling."""
    floor = minimum if minimum > 0 else max(1, base // 4)
    return min(
        maximum,
        max(floor, (base * memory_gib) // BASELINE_MEMORY_GIB),
    )


def build_capacity_profile(memory_bytes: int) -> CapacityProfile:
    # VPS providers advertise rounded GiB values while Linux reports slightly
    # less, so use nearest-GiB sizing rather than truncating a 4 GiB VPS to 3.
    memory_gib = max(1, int((memory_bytes + GIB // 2) // GIB))

    if memory_gib <= 2:
        name = "small"
    elif memory_gib <= 4:
        name = "standard"
    elif memory_gib <= 8:
        name = "medium"
    elif memory_gib <= 16:
        name = "large"
    elif memory_gib <= 32:
        name = "high-capacity"
    else:
        name = "dedicated"

    # These first three baselines are the exact values from the user's original
    # 2 GiB script. Missing network limits use conservative 2 GiB baselines.
    system_file_max = scale_from_baseline(2_097_152, memory_gib, 67_108_864)
    process_nofile = scale_from_baseline(1_048_576, memory_gib, 8_388_608)
    process_nproc = scale_from_baseline(262_144, memory_gib, 2_097_152)
    service_tasks_max = scale_from_baseline(16_384, memory_gib, 131_072)
    kernel_threads_max = scale_from_baseline(131_072, memory_gib, 1_048_576)
    vm_max_map_count = scale_from_baseline(262_144, memory_gib, 1_048_576)
    conntrack_raw = scale_from_baseline(262_144, memory_gib, 4_194_304)
    conntrack_max = conntrack_raw
    netdev_backlog = scale_from_baseline(65_536, memory_gib, 500_000)
    netdev_budget = scale_from_baseline(600, memory_gib, 2_400)
    syn_backlog = scale_from_baseline(8_192, memory_gib, 131_072)
    tw_buckets = scale_from_baseline(262_144, memory_gib, 2_000_000)
    tcp_max_orphans = scale_from_baseline(262_144, memory_gib, 2_000_000)
    socket_buffer_max = scale_from_baseline(
        32 * 1024 ** 2,
        memory_gib,
        128 * 1024 ** 2,
    )

    return CapacityProfile(
        name=name,
        memory_bytes=memory_bytes,
        memory_gib=memory_gib,
        scale=memory_gib / float(BASELINE_MEMORY_GIB),
        system_file_max=system_file_max,
        kernel_nr_open=process_nofile,
        process_nofile=process_nofile,
        process_nproc=process_nproc,
        service_tasks_max=service_tasks_max,
        kernel_threads_max=kernel_threads_max,
        vm_max_map_count=vm_max_map_count,
        conntrack_max=conntrack_max,
        conntrack_hashsize=lower_power_of_two(conntrack_max // 4),
        netdev_backlog=netdev_backlog,
        netdev_budget=netdev_budget,
        syn_backlog=syn_backlog,
        tw_buckets=tw_buckets,
        tcp_max_orphans=tcp_max_orphans,
        socket_buffer_max=socket_buffer_max,
    )


PROFILE = build_capacity_profile(detect_total_memory_bytes())
SYSTEM_FILE_MAX = PROFILE.system_file_max
PROCESS_NOFILE = PROFILE.process_nofile
PROCESS_NPROC = PROFILE.process_nproc
SERVICE_TASKS_MAX = PROFILE.service_tasks_max
CONNTRACK_MAX = PROFILE.conntrack_max
CONNTRACK_HASHSIZE = PROFILE.conntrack_hashsize

PROCESS_NAMES = (
    "stunnel",
    "stunnel4",
    "openvpn",
    "ss-server",
    "tun2socks",
)

STATIC_SERVICE_UNITS = (
    "stunnel.service",
    "stunnel4.service",
    "openvpn.service",
    "openvpn-server.service",
    "tun2socks.service",
    "dnsmasq.service",
    "pm2-root.service",
    "shadowsocks-libev.service",
    "ss-server.service",
)

STATIC_TEMPLATE_UNITS = (
    "openvpn@.service",
    "openvpn-server@.service",
)

SYSCTLS: Dict[str, str] = {
    "fs.file-max": str(SYSTEM_FILE_MAX),
    "fs.nr_open": str(PROFILE.kernel_nr_open),
    "kernel.pid_max": "4194304",
    "kernel.threads-max": str(PROFILE.kernel_threads_max),
    "vm.max_map_count": str(PROFILE.vm_max_map_count),
    "net.core.somaxconn": "65535",
    "net.core.netdev_budget": str(PROFILE.netdev_budget),
    "net.core.netdev_budget_usecs": "8000",
    "net.core.netdev_max_backlog": str(PROFILE.netdev_backlog),
    "net.core.optmem_max": "4194304",
    "net.core.rmem_max": str(PROFILE.socket_buffer_max),
    "net.core.wmem_max": str(PROFILE.socket_buffer_max),
    "net.ipv4.ip_forward": "1",
    "net.ipv4.ip_local_port_range": "1024 65535",
    "net.ipv4.tcp_fin_timeout": "15",
    "net.ipv4.tcp_keepalive_time": "600",
    "net.ipv4.tcp_keepalive_intvl": "30",
    "net.ipv4.tcp_keepalive_probes": "5",
    "net.ipv4.tcp_max_syn_backlog": str(PROFILE.syn_backlog),
    "net.ipv4.tcp_max_orphans": str(PROFILE.tcp_max_orphans),
    "net.ipv4.tcp_max_tw_buckets": str(PROFILE.tw_buckets),
    "net.ipv4.tcp_mtu_probing": "1",
    "net.ipv4.tcp_rmem": f"4096 87380 {PROFILE.socket_buffer_max}",
    "net.ipv4.tcp_slow_start_after_idle": "0",
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.tcp_tw_reuse": "1",
    "net.ipv4.tcp_wmem": f"4096 65536 {PROFILE.socket_buffer_max}",
    "net.netfilter.nf_conntrack_max": str(CONNTRACK_MAX),
    "net.netfilter.nf_conntrack_tcp_timeout_close_wait": "60",
    "net.netfilter.nf_conntrack_tcp_timeout_established": "7200",
    "net.netfilter.nf_conntrack_tcp_timeout_fin_wait": "60",
    "net.netfilter.nf_conntrack_tcp_timeout_time_wait": "30",
    "net.netfilter.nf_conntrack_udp_timeout": "30",
    "net.netfilter.nf_conntrack_udp_timeout_stream": "120",
}

STOP_REQUESTED = False


def log(message: str) -> None:
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] {message}", flush=True)


def run(command: Sequence[str], timeout: int = 30) -> subprocess.CompletedProcess:
    args = list(command)
    try:
        return subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        detail = f"command timed out after {timeout}s"
        stderr = f"{stderr.rstrip()}\n{detail}".strip()
        return subprocess.CompletedProcess(args, 124, stdout, stderr)
    except OSError as exc:
        return subprocess.CompletedProcess(args, 127, "", str(exc))


def require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("Run this script as root")


def load_conntrack() -> Tuple[bool, str]:
    result = run(["modprobe", "nf_conntrack"])
    if result.returncode != 0:
        return False, result.stderr.strip() or "modprobe nf_conntrack failed"
    return True, "loaded"


def set_conntrack_hashsize() -> Tuple[bool, str]:
    path = Path("/sys/module/nf_conntrack/parameters/hashsize")
    if not path.exists():
        return False, f"{path} does not exist"
    desired = str(CONNTRACK_HASHSIZE)
    try:
        before = path.read_text(encoding="ascii").strip()
        if before != desired:
            path.write_text(desired, encoding="ascii")
        after = path.read_text(encoding="ascii").strip()
    except OSError as exc:
        return False, str(exc)
    return after == desired, f"{before} -> {after}"


def apply_sysctls() -> Tuple[int, List[str]]:
    success = 0
    errors: List[str] = []
    for key, value in SYSCTLS.items():
        result = run(["sysctl", "-q", "-w", f"{key}={value}"])
        if result.returncode == 0:
            success += 1
        else:
            detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
            errors.append(f"{key}: {detail}")
    return success, errors


def list_running_units() -> List[str]:
    result = run(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--plain",
        ]
    )
    if result.returncode != 0:
        return []
    units: List[str] = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if fields and fields[0].endswith(".service"):
            units.append(fields[0])
    return units


def target_units() -> List[str]:
    running = list_running_units()
    selected = set()
    for unit in running:
        if unit in STATIC_SERVICE_UNITS or unit.startswith("openvpn"):
            selected.add(unit)
    return sorted(selected)


def list_installed_service_units() -> List[str]:
    result = run(
        [
            "systemctl",
            "list-unit-files",
            "--type=service",
            "--no-legend",
            "--plain",
        ]
    )
    if result.returncode != 0:
        return []
    return [
        line.split()[0]
        for line in result.stdout.splitlines()
        if line.split() and line.split()[0].endswith(".service")
    ]


def configured_units(running_units: Iterable[str]) -> List[str]:
    installed = set(list_installed_service_units())
    selected = set(running_units)
    selected.update(unit for unit in STATIC_SERVICE_UNITS if unit in installed)
    selected.update(unit for unit in STATIC_TEMPLATE_UNITS if unit in installed)
    return sorted(selected)


def write_runtime_service_drop_in(unit: str) -> None:
    drop_in_dir = Path("/run/systemd/system") / f"{unit}.d"
    drop_in_dir.mkdir(parents=True, exist_ok=True)
    destination = drop_in_dir / "40-xd-runtime-limits.conf"
    temporary = drop_in_dir / ".40-xd-runtime-limits.conf.tmp"
    content = (
        "[Service]\n"
        f"LimitNOFILE={PROCESS_NOFILE}\n"
        f"LimitNPROC={PROCESS_NPROC}\n"
        f"TasksMax={SERVICE_TASKS_MAX}\n"
    )
    temporary.write_text(content, encoding="ascii")
    os.chmod(temporary, 0o644)
    os.replace(temporary, destination)


def apply_runtime_task_limits() -> Tuple[int, List[str]]:
    success = 0
    errors: List[str] = []
    running_units = target_units()
    units = configured_units(running_units)
    for unit in units:
        try:
            write_runtime_service_drop_in(unit)
        except OSError as exc:
            errors.append(f"{unit} runtime drop-in: {exc}")

    if units:
        reload_result = run(["systemctl", "daemon-reload"])
        if reload_result.returncode != 0:
            detail = reload_result.stderr.strip() or reload_result.stdout.strip()
            errors.append(f"systemd daemon-reload: {detail}")

    for unit in running_units:
        result = run(
            [
                "systemctl",
                "set-property",
                "--runtime",
                unit,
                f"TasksMax={SERVICE_TASKS_MAX}",
            ]
        )
        if result.returncode == 0:
            success += 1
        else:
            detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
            errors.append(f"{unit}: {detail}")
    return success, errors


def physical_interfaces() -> List[str]:
    interfaces: List[str] = []
    net_root = Path("/sys/class/net")
    try:
        candidates = sorted(net_root.iterdir(), key=lambda item: item.name)
    except OSError:
        return interfaces

    for candidate in candidates:
        try:
            if not (candidate / "device").exists():
                continue
            if (candidate / "operstate").read_text(encoding="ascii").strip() != "up":
                continue
            interfaces.append(candidate.name)
        except OSError:
            continue
    return interfaces


def parse_ring_parameters(output: str) -> Dict[str, Dict[str, int]]:
    values: Dict[str, Dict[str, int]] = {"maximum": {}, "current": {}}
    section = ""
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line == "Pre-set maximums:":
            section = "maximum"
            continue
        if line == "Current hardware settings:":
            section = "current"
            continue
        if section not in values or ":" not in line:
            continue
        key, raw_value = (part.strip() for part in line.split(":", 1))
        if key not in {"RX", "TX"} or not raw_value.isdigit():
            continue
        values[section][key.lower()] = int(raw_value)
    return values


def tune_network_interfaces() -> Tuple[int, List[str]]:
    """Apply live queue tuning without restarting or reloading an interface."""
    success = 0
    errors: List[str] = []
    ethtool = shutil.which("ethtool")

    for interface in physical_interfaces():
        qlen = run(["ip", "link", "set", "dev", interface, "txqueuelen", "10000"])
        if qlen.returncode == 0:
            success += 1
        else:
            errors.append(f"{interface} txqueuelen: {qlen.stderr.strip() or qlen.stdout.strip()}")

        if not ethtool:
            errors.append(f"{interface} ring: ethtool is not installed")
            continue

        ring = run([ethtool, "-g", interface])
        if ring.returncode != 0:
            errors.append(f"{interface} ring read: {ring.stderr.strip() or ring.stdout.strip()}")
            continue
        parameters = parse_ring_parameters(ring.stdout)
        maximum = parameters["maximum"]
        current = parameters["current"]
        requested: List[str] = []
        for direction in ("rx", "tx"):
            target = maximum.get(direction, 0)
            if target > current.get(direction, 0):
                requested.extend([direction, str(target)])
        if requested:
            changed = run([ethtool, "-G", interface] + requested)
            if changed.returncode != 0:
                errors.append(
                    f"{interface} ring write: {changed.stderr.strip() or changed.stdout.strip()}"
                )
            else:
                success += 1

        speed = run([ethtool, interface])
        speed_match = re.search(r"^\s*Speed:\s*(\d+)Mb/s", speed.stdout, re.MULTILINE)
        if speed.returncode == 0 and speed_match and int(speed_match.group(1)) >= 10_000:
            coalesce = run([ethtool, "-C", interface, "rx-usecs", "8"])
            if coalesce.returncode == 0:
                success += 1
            else:
                errors.append(
                    f"{interface} interrupt coalescing: "
                    f"{coalesce.stderr.strip() or coalesce.stdout.strip()}"
                )

    ip_result = run(["ip", "-o", "link", "show"])
    if ip_result.returncode == 0:
        tun_names = sorted(
            set(
                re.findall(
                    r"^\d+:\s+((?:tun\d+|xd_tun2socks)):",
                    ip_result.stdout,
                    re.MULTILINE,
                )
            )
        )
        for interface in tun_names:
            qlen = run(["ip", "link", "set", "dev", interface, "txqueuelen", "4096"])
            if qlen.returncode == 0:
                success += 1
            else:
                errors.append(
                    f"{interface} txqueuelen: {qlen.stderr.strip() or qlen.stdout.strip()}"
                )
    else:
        errors.append(f"tun discovery: {ip_result.stderr.strip() or ip_result.stdout.strip()}")

    return success, errors


def process_pids(names: Iterable[str]) -> List[int]:
    found = set()
    for name in names:
        result = run(["pgrep", "-x", name])
        if result.returncode not in (0, 1):
            continue
        for value in result.stdout.split():
            try:
                found.add(int(value))
            except ValueError:
                pass
    return sorted(found)


def apply_process_limits() -> Tuple[int, List[str]]:
    if shutil.which("prlimit") is None:
        return 0, ["prlimit command is not installed"]

    success = 0
    errors: List[str] = []
    for pid in process_pids(PROCESS_NAMES):
        result = run(
            [
                "prlimit",
                "--pid",
                str(pid),
                f"--nofile={PROCESS_NOFILE}:{PROCESS_NOFILE}",
                f"--nproc={PROCESS_NPROC}:{PROCESS_NPROC}",
            ]
        )
        if result.returncode == 0:
            success += 1
        else:
            detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
            errors.append(f"pid {pid}: {detail}")
    return success, errors


def apply_own_limits() -> List[str]:
    errors: List[str] = []
    requested = (
        (resource.RLIMIT_NOFILE, PROCESS_NOFILE, "RLIMIT_NOFILE"),
        (resource.RLIMIT_NPROC, PROCESS_NPROC, "RLIMIT_NPROC"),
    )
    for limit, value, name in requested:
        try:
            _soft, hard = resource.getrlimit(limit)
            effective = value if hard == resource.RLIM_INFINITY else min(value, hard)
            resource.setrlimit(limit, (effective, hard))
        except (OSError, ValueError) as exc:
            errors.append(f"{name}: {exc}")
    return errors


def sysctl_value(key: str) -> str:
    result = run(["sysctl", "-n", key])
    if result.returncode != 0:
        return "unavailable"
    return result.stdout.strip()


def task_limit(unit: str) -> str:
    result = run(["systemctl", "show", unit, "--property=TasksMax", "--value"])
    if result.returncode != 0:
        return "unavailable"
    return result.stdout.strip()


def apply_limits() -> int:
    require_root()
    log(
        f"profile={PROFILE.name} memory={PROFILE.memory_bytes / GIB:.1f}GiB "
        f"scale={PROFILE.scale:.2f}x-from-{BASELINE_MEMORY_GIB}GiB "
        f"conntrack={CONNTRACK_MAX} tasks={SERVICE_TASKS_MAX} "
        f"nofile={PROCESS_NOFILE}"
    )
    log("loading nf_conntrack")
    conntrack_loaded, conntrack_detail = load_conntrack()

    hash_ok, hash_detail = set_conntrack_hashsize()
    sysctl_ok, sysctl_errors = apply_sysctls()
    service_ok, service_errors = apply_runtime_task_limits()
    process_ok, process_errors = apply_process_limits()
    network_ok, network_errors = tune_network_interfaces()
    own_errors = apply_own_limits()

    errors = (
        sysctl_errors
        + service_errors
        + process_errors
        + network_errors
        + own_errors
    )
    if not conntrack_loaded:
        errors.insert(0, f"nf_conntrack: {conntrack_detail}")
    log(
        "applied "
        f"sysctl={sysctl_ok}/{len(SYSCTLS)} "
        f"services={service_ok} processes={process_ok} network={network_ok} "
        f"hashsize={'ok' if hash_ok else 'warning'} ({hash_detail})"
    )
    log(
        "runtime "
        f"conntrack={sysctl_value('net.netfilter.nf_conntrack_count')}/"
        f"{sysctl_value('net.netfilter.nf_conntrack_max')} "
        f"stunnel_tasks_max={task_limit('stunnel4.service')}"
    )

    for error in errors:
        log(f"WARN {error}")
    if errors:
        log(f"completed with {len(errors)} warning(s)")
        return 1

    log("all live limits were applied successfully")
    return 0


def request_stop(signum: int, _frame: object) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True
    log(f"received signal {signum}; stopping")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--once",
        action="store_true",
        help="apply limits and exit instead of staying idle for PM2",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    result = apply_limits()
    if args.once:
        return result

    if result != 0:
        log("one or more settings failed; staying idle to avoid a PM2 restart loop")
    log("idle under PM2; limits will be applied again when PM2 starts after reboot")
    while not STOP_REQUESTED:
        time.sleep(1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
