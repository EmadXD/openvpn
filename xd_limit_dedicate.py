#!/usr/bin/env python3
"""Apply RAM-aware runtime capacity tuning for OpenVPN/stunnel servers.

The script is safe to run under PM2: it applies the complete profile at start,
then refreshes only live process and network settings. It never changes routes,
IP addresses, firewall rules, OpenVPN configuration, or stunnel configuration.
Use --once for a manual apply-and-exit run. Shared kernel ceilings are
persisted with the same raise-only policy as the Nginx installer.

Measured in audit.json on 2026-09-10: 314376/4194304 conntrack entries
and 503.37 GiB host RAM. The proposed conntrack ceiling uses at most 1/16
of effective RAM, estimating 1 KiB per flow plus hash resize overlap. This
is a planning allowance, not measured per-flow memory or certified capacity.
Shared Nginx ceilings are unified; the per-process NOFILE cap and
the conntrack RAM budget remain unchanged.
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
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple


"""Shared ceiling policy embedded in both standalone tuners and Nginx installer."""

SHARED_CAPACITY_V1 = True
SHARED_CAPACITY_FLOORS = {
    'fs.file-max': 67108864,
    'fs.nr_open': 8388608,
    'net.core.somaxconn': 262144,
    'net.core.netdev_max_backlog': 1000000,
    'net.ipv4.tcp_max_syn_backlog': 262144,
    'net.ipv4.tcp_max_tw_buckets': 4000000,
}


def apply_shared_capacity(run_command=None, config_path=None, lock_path=None):
    """Only raise ceilings, verify writes, and persist the same values for boot.

    Neither writer owns TCP timeouts here. They remain in the RAM-aware tuner.
    The legacy filename is retained so an old Nginx boot file cannot override us.
    """
    import fcntl
    import os
    from pathlib import Path
    import subprocess
    import tempfile

    if run_command is None:
        def run_command(args):
            return subprocess.run(args, capture_output=True, text=True, timeout=30)
    destination = Path(config_path or '/etc/sysctl.d/99-nginx-high-capacity.conf')
    lockfile = Path(lock_path or '/run/xd-shared-capacity.lock')
    errors, actual = [], {}
    with lockfile.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        previous = destination.read_text() if destination.exists() else ''
        retained = []
        legacy_timeouts = {
            'net.ipv4.tcp_fin_timeout', 'net.ipv4.tcp_tw_reuse', 'net.ipv4.tcp_syncookies',
            'net.ipv4.tcp_keepalive_time', 'net.ipv4.tcp_keepalive_intvl',
            'net.ipv4.tcp_keepalive_probes',
        }
        persisted = {}
        for line in previous.splitlines():
            key, sep, value = line.partition('=')
            key = key.strip()
            if key in SHARED_CAPACITY_FLOORS and sep:
                try:
                    persisted[key] = max(persisted.get(key, 0), int(value.split('#')[0].strip()))
                except ValueError:
                    errors.append(key + ': invalid persisted capacity')
            elif key not in legacy_timeouts and line.strip() and not line.lstrip().startswith('#'):
                retained.append(line)
        if errors:
            return 0, errors
        for key, floor in SHARED_CAPACITY_FLOORS.items():
            try:
                before = run_command(['sysctl', '-n', key])
                if before.returncode:
                    raise ValueError('read failed')
                current = int(before.stdout.strip())
                desired = max(current, floor, persisted.get(key, 0))
                if current < desired:
                    written = run_command(['sysctl', '-q', '-w', key + '=' + str(desired)])
                    if written.returncode:
                        raise ValueError('write failed: ' + written.stderr.strip())
                after = run_command(['sysctl', '-n', key])
                if after.returncode or int(after.stdout.strip()) < desired:
                    raise ValueError('readback below requested capacity')
                actual[key] = int(after.stdout.strip())
            except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                errors.append(key + ': ' + str(exc))
        # Never persist a partially verified policy, or lower a ceiling on rollback.
        if not errors:
            content = '# Shared XD capacity V1; Nginx and xd_limit use the same floors.\n'
            content += ''.join(key + ' = ' + str(value) + '\n' for key, value in actual.items())
            content += ''.join(line + '\n' for line in retained)
            if content != previous:
                destination.parent.mkdir(parents=True, exist_ok=True)
                fd, temporary = tempfile.mkstemp(prefix='.xd-shared-', dir=str(destination.parent))
                try:
                    with os.fdopen(fd, 'w') as stream:
                        stream.write(content)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.chmod(temporary, 0o644)
                    os.replace(temporary, destination)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
    return len(actual), errors


GIB = 1024 ** 3
BASELINE_MEMORY_GIB = 2
DEDICATED_MULTI_COMPATIBLE = True
DEDICATED_CONNTRACK_RAM_V2 = True
CONNTRACK_RAM_DIVISOR = 16
CONNTRACK_FLOW_BYTES = 1024
CONNTRACK_BUCKET_BYTES = 16
CONNTRACK_ENTRY_QUANTUM = 1024
# Conservative signed-int envelope for Linux sysctl/module interfaces.
CONNTRACK_NATIVE_MAX = (1 << 31) - 1
# nf_ct_alloc_hashtable checks UINT_MAX / sizeof(hlist_nulls_head).
# Use the 64-bit head size (8 bytes), also conservative on 32-bit systems.
CONNTRACK_HASH_NATIVE_MAX = ((1 << 32) - 1) // 8
CONNTRACK_HASH_PATH = Path("/sys/module/nf_conntrack/parameters/hashsize")
CONNTRACK_MAX_KEY = "net.netfilter.nf_conntrack_max"
CONNTRACK_COUNT_KEY = "net.netfilter.nf_conntrack_count"


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


def cgroup_memory_limit_paths() -> List[Path]:
    """Locate our v1/v2 memory controller and every visible ancestor limit."""
    paths = {Path("/sys/fs/cgroup/memory.max"),
             Path("/sys/fs/cgroup/memory/memory.limit_in_bytes")}
    try:
        membership = Path("/proc/self/cgroup").read_text(encoding="ascii")
        mounts = Path("/proc/self/mountinfo").read_text(encoding="ascii")
    except FileNotFoundError:
        return sorted(paths)

    groups = {}
    for line in membership.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            raise ValueError("Malformed /proc/self/cgroup")
        for controller in parts[1].split(","):
            if controller in ("", "memory"):
                group = PurePosixPath(parts[2])
                if not group.is_absolute() or ".." in group.parts:
                    raise ValueError("Invalid cgroup membership path")
                groups[controller] = group

    mounted, mapped = set(), set()
    for line in mounts.splitlines():
        before, separator, after = line.partition(" - ")
        fields, filesystem = before.split(), after.split()
        if not separator or len(fields) < 6 or len(filesystem) < 3:
            raise ValueError("Malformed /proc/self/mountinfo")
        if filesystem[0] == "cgroup2":
            controller, filename = "", "memory.max"
        elif filesystem[0] == "cgroup" and "memory" in filesystem[2].split(","):
            controller, filename = "memory", "memory.limit_in_bytes"
        else:
            continue
        if controller not in groups:
            continue
        mounted.add(controller)
        def unescape(value):
            return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)
        root = PurePosixPath(unescape(fields[3]))
        mount = Path(unescape(fields[4]))
        if not root.is_absolute() or not mount.is_absolute() or ".." in root.parts + mount.parts:
            raise ValueError("Invalid cgroup mount path")
        group = groups[controller]
        try:
            relative = group.relative_to(root)
        except ValueError:
            if group != PurePosixPath("/"):
                continue
            # A cgroup namespace may expose its own root as '/' in membership.
            relative = PurePosixPath(".")
        mapped.add(controller)
        current = mount / relative
        while True:
            paths.add(current / filename)
            if current == mount:
                break
            current = current.parent
    if mounted - mapped:
        raise ValueError("Cannot resolve current cgroup memory hierarchy; refusing to guess")
    return sorted(paths)


def parse_memory_limit(raw: str, label: str) -> Optional[int]:
    value = raw.strip()
    if value == "max":
        return None
    if not re.fullmatch(r"[0-9]{1,20}", value) or int(value) <= 0:
        raise ValueError(f"Invalid memory ceiling at {label}; refusing to guess")
    number = int(value)
    if number > (1 << 63) - 1:
        raise ValueError(f"Memory ceiling out of range at {label}")
    # v1 represents an unlimited ceiling with a page-aligned LONG_MAX.
    return None if number >= 1 << 60 else number


def detect_total_memory_bytes() -> int:
    """Return host RAM clamped by finite cgroup limits, never MemAvailable."""
    candidates: List[int] = []
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            match = re.fullmatch(r"MemTotal:\s+([0-9]+) kB", line.strip())
            if match and int(match[1]) > 0:
                candidates.append(int(match[1]) * 1024)
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

    if not candidates:
        candidates.append(4 * GIB)
    for path in cgroup_memory_limit_paths():
        try:
            raw = path.read_text(encoding="ascii").strip()
        except FileNotFoundError:
            continue
        value = parse_memory_limit(raw, str(path))
        if value is not None:
            candidates.append(value)

    return min(candidates)


def lower_power_of_two(value: int) -> int:
    if value < 1:
        return 1
    return 1 << (value.bit_length() - 1)


def conntrack_hashsize(entries: int) -> int:
    buckets = max(1024, (entries + 3) // 4)
    return 1 << (buckets - 1).bit_length()


def conntrack_memory_cost(entries: int, buckets: int, old_buckets: int = 0) -> int:
    # Reserve two tables for resize; an existing larger table must also fit.
    return (entries * CONNTRACK_FLOW_BYTES +
            (buckets + max(buckets, old_buckets)) * CONNTRACK_BUCKET_BYTES)


def build_conntrack_capacity(memory_bytes: int) -> Tuple[int, int]:
    if type(memory_bytes) is not int or memory_bytes <= 0:
        raise ValueError("Effective RAM must be a positive integer byte count")
    budget = memory_bytes // CONNTRACK_RAM_DIVISOR
    low = 0
    high = min(CONNTRACK_NATIVE_MAX, budget // CONNTRACK_FLOW_BYTES) // CONNTRACK_ENTRY_QUANTUM
    while low < high:
        middle = (low + high + 1) // 2
        entries = middle * CONNTRACK_ENTRY_QUANTUM
        buckets = conntrack_hashsize(entries)
        if buckets <= CONNTRACK_HASH_NATIVE_MAX and conntrack_memory_cost(entries, buckets) <= budget:
            low = middle
        else:
            high = middle - 1
    if not low:
        raise ValueError("Effective RAM is too small for the conntrack budget")
    entries = low * CONNTRACK_ENTRY_QUANTUM
    return entries, conntrack_hashsize(entries)


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
    conntrack_max, hashsize = build_conntrack_capacity(memory_bytes)
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
        system_file_max=max(system_file_max, SHARED_CAPACITY_FLOORS['fs.file-max']),
        kernel_nr_open=max(process_nofile, SHARED_CAPACITY_FLOORS['fs.nr_open']),
        process_nofile=process_nofile,
        process_nproc=process_nproc,
        service_tasks_max=service_tasks_max,
        kernel_threads_max=kernel_threads_max,
        vm_max_map_count=vm_max_map_count,
        conntrack_max=conntrack_max,
        conntrack_hashsize=hashsize,
        netdev_backlog=max(netdev_backlog, SHARED_CAPACITY_FLOORS['net.core.netdev_max_backlog']),
        netdev_budget=netdev_budget,
        syn_backlog=max(syn_backlog, SHARED_CAPACITY_FLOORS['net.ipv4.tcp_max_syn_backlog']),
        tw_buckets=max(tw_buckets, SHARED_CAPACITY_FLOORS['net.ipv4.tcp_max_tw_buckets']),
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
DEFAULT_REFRESH_SECONDS = 300

PROCESS_NAMES = (
    "nginx",
    "stunnel",
    "stunnel4",
    "openvpn",
    "tun2socks",
    "dnsmasq",
)

STATIC_SERVICE_UNITS = (
    "nginx.service",
    "stunnel.service",
    "stunnel4.service",
    "openvpn.service",
    "openvpn-server.service",
    "tun2socks.service",
    "dnsmasq.service",
    "pm2-root.service",
)

STATIC_TEMPLATE_UNITS = (
    "openvpn@.service",
    "openvpn-server@.service",
    "xd-stunnel-pool@.service",
)

SERVICE_UNIT_PREFIXES = (
    "openvpn",
    "xd-stunnel-pool@",
    "xd-tun2socks-",
    "xd-dnsmasq-",
)

SYSCTLS: Dict[str, str] = {
    "fs.file-max": str(SYSTEM_FILE_MAX),
    "fs.nr_open": str(PROFILE.kernel_nr_open),
    "kernel.pid_max": "4194304",
    "kernel.threads-max": str(PROFILE.kernel_threads_max),
    "vm.max_map_count": str(PROFILE.vm_max_map_count),
    "net.core.default_qdisc": "fq",
    "net.core.somaxconn": "262144",
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


def native_conntrack_value(raw: str, label: str, minimum: int = 1,
                           maximum: int = CONNTRACK_NATIVE_MAX) -> int:
    if not re.fullmatch(r"[0-9]{1,10}", raw.strip()):
        raise ValueError(f"Invalid {label} readback")
    value = int(raw)
    if not minimum <= value <= maximum:
        raise ValueError(f"{label} outside native integer bounds")
    return value


def read_conntrack_value(key: str, minimum: int = 1) -> int:
    result = run(["sysctl", "-n", key])
    if result.returncode:
        raise ValueError(f"Cannot read {key}: {result.stderr.strip() or result.returncode}")
    return native_conntrack_value(result.stdout, key, minimum)


def read_conntrack_hashsize() -> int:
    return native_conntrack_value(CONNTRACK_HASH_PATH.read_text(encoding="ascii"),
                                  "hashsize", maximum=CONNTRACK_HASH_NATIVE_MAX)


def check_conntrack_occupancy() -> int:
    count = read_conntrack_value(CONNTRACK_COUNT_KEY, 0)
    if count > CONNTRACK_MAX:
        raise ValueError(f"Resize deferred: measured count {count} exceeds proposed {CONNTRACK_MAX}")
    return count


def set_conntrack_hashsize(expected_before: Optional[int] = None) -> Tuple[bool, str]:
    try:
        native_conntrack_value(str(CONNTRACK_HASHSIZE), "proposed hashsize",
                              maximum=CONNTRACK_HASH_NATIVE_MAX)
        before = read_conntrack_hashsize()
        if expected_before is not None and before != expected_before:
            raise ValueError("Hashsize changed concurrently; resize deferred")
        if before != CONNTRACK_HASHSIZE:
            if before > CONNTRACK_HASHSIZE:
                check_conntrack_occupancy()
            if conntrack_memory_cost(CONNTRACK_MAX, CONNTRACK_HASHSIZE, before) > PROFILE.memory_bytes // CONNTRACK_RAM_DIVISOR:
                raise ValueError("Existing hash resize overlap exceeds RAM budget; resize deferred")
            CONNTRACK_HASH_PATH.write_text(str(CONNTRACK_HASHSIZE), encoding="ascii")
        after = read_conntrack_hashsize()
    except (OSError, ValueError) as exc:
        return False, str(exc)
    return after == CONNTRACK_HASHSIZE, f"hashsize {before} -> {after}, proposed={CONNTRACK_HASHSIZE}"


def set_conntrack_max(expected_before: int) -> None:
    before = read_conntrack_value(CONNTRACK_MAX_KEY)
    if before != expected_before:
        raise ValueError("Conntrack maximum changed concurrently; resize deferred")
    if before != CONNTRACK_MAX:
        if before > CONNTRACK_MAX:
            check_conntrack_occupancy()
        result = run(["sysctl", "-q", "-w", f"{CONNTRACK_MAX_KEY}={CONNTRACK_MAX}"])
        if result.returncode:
            raise ValueError(f"Conntrack maximum write failed: {result.stderr.strip() or result.returncode}")
    after = read_conntrack_value(CONNTRACK_MAX_KEY)
    if after != CONNTRACK_MAX:
        raise ValueError(f"Conntrack maximum readback {after} != proposed {CONNTRACK_MAX}")


def apply_conntrack_capacity() -> Tuple[bool, str]:
    """Grow the hash before admission; lower admission before shrinking the hash.

    Refuse unsafe downward changes without flushing established flows. These
    read/verify guards detect races but cannot atomically freeze live traffic.
    A partial failure keeps the successfully verified stage and reports failure;
    no blind rollback may shrink a table now needed by newly admitted flows.
    """
    try:
        native_conntrack_value(str(CONNTRACK_MAX), "proposed conntrack maximum")
        native_conntrack_value(str(CONNTRACK_HASHSIZE), "proposed hashsize",
                              maximum=CONNTRACK_HASH_NATIVE_MAX)
        if CONNTRACK_HASHSIZE != conntrack_hashsize(CONNTRACK_MAX):
            raise ValueError("Proposed hashsize does not match conntrack capacity")
        count = check_conntrack_occupancy()
        before = read_conntrack_value(CONNTRACK_MAX_KEY)
        old_hash = read_conntrack_hashsize()
        cost = conntrack_memory_cost(CONNTRACK_MAX, CONNTRACK_HASHSIZE, old_hash)
        if cost > PROFILE.memory_bytes // CONNTRACK_RAM_DIVISOR:
            raise ValueError("Proposed flows plus existing hash resize overlap exceed RAM budget")
        log(f"conntrack measured={count}/{before} hashsize={old_hash}; "
            f"proposed={CONNTRACK_MAX} hashsize={CONNTRACK_HASHSIZE} "
            f"estimated_peak_bytes={cost} budget_bytes={PROFILE.memory_bytes // CONNTRACK_RAM_DIVISOR}")
        if before > CONNTRACK_MAX:
            set_conntrack_max(before)
        hash_ok, detail = set_conntrack_hashsize(expected_before=old_hash)
        if not hash_ok:
            raise ValueError(f"Conntrack hash verification failed: {detail}")
        if before <= CONNTRACK_MAX:
            set_conntrack_max(before)
        actual_max = read_conntrack_value(CONNTRACK_MAX_KEY)
        actual_hash = read_conntrack_hashsize()
        readback = (f"desired_max={CONNTRACK_MAX} effective_max={actual_max} "
                    f"desired_hashsize={CONNTRACK_HASHSIZE} effective_hashsize={actual_hash}")
        if actual_max != CONNTRACK_MAX or actual_hash != CONNTRACK_HASHSIZE:
            raise ValueError(f"Conntrack final readback differs: {readback}")
        count = check_conntrack_occupancy()
        return True, f"{readback} measured_count={count}"
    except (OSError, ValueError) as exc:
        return False, str(exc)


def apply_sysctls() -> Tuple[int, List[str]]:
    success = 0
    errors: List[str] = []
    shared_ok, shared_errors = apply_shared_capacity(run)
    success += shared_ok
    errors.extend(shared_errors)
    for key, value in SYSCTLS.items():
        if key in SHARED_CAPACITY_FLOORS:
            continue
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
        if unit in STATIC_SERVICE_UNITS or unit.startswith(SERVICE_UNIT_PREFIXES):
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


def service_task_limit(unit: str) -> str:
    # Keep the dedicated installer's per-worker cgroups unbounded. RAM-aware
    # kernel/FD limits remain finite; this does not reserve memory or spawn tasks.
    if unit == 'nginx.service':
        return 'infinity'
    if unit.startswith(('xd-stunnel-pool@', 'openvpn@', 'openvpn-server@')):
        return 'infinity'
    return str(SERVICE_TASKS_MAX)


def write_runtime_service_drop_in(unit: str) -> None:
    drop_in_dir = Path("/run/systemd/system") / f"{unit}.d"
    drop_in_dir.mkdir(parents=True, exist_ok=True)
    destination = drop_in_dir / "40-xd-runtime-limits.conf"
    temporary = drop_in_dir / ".40-xd-runtime-limits.conf.tmp"
    content = (
        "[Service]\n"
        f"LimitNOFILE={max(PROCESS_NOFILE, 2097152) if unit == 'nginx.service' else PROCESS_NOFILE}\n"
        f"LimitNPROC={'infinity' if unit == 'nginx.service' else PROCESS_NPROC}\n"
        f"TasksMax={service_task_limit(unit)}\n"
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
                f"TasksMax={service_task_limit(unit)}",
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


def tune_cpu_governor() -> Tuple[int, List[str]]:
    """Select the performance governor where the host exposes CPU frequency control."""
    success = 0
    errors: List[str] = []
    governor_paths = sorted(
        Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_governor")
    )
    for governor_path in governor_paths:
        available_path = governor_path.with_name("scaling_available_governors")
        try:
            available = available_path.read_text(encoding="ascii").split()
            if available and "performance" not in available:
                continue
            if governor_path.read_text(encoding="ascii").strip() != "performance":
                governor_path.write_text("performance", encoding="ascii")
            success += 1
        except OSError as exc:
            errors.append(f"{governor_path}: {exc}")
    return success, errors


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


def cpu_mask(cpu_count: int) -> str:
    """Return a Linux cpumask covering every online logical CPU."""
    bits = (1 << max(1, cpu_count)) - 1
    groups: List[str] = []
    while bits:
        groups.append(f"{bits & 0xFFFFFFFF:08x}")
        bits >>= 32
    groups[-1] = groups[-1].lstrip("0") or "0"
    return ",".join(reversed(groups))


def tune_receive_flow_steering(interface: str) -> Tuple[int, List[str]]:
    """Spread 10 Gbps receive processing across otherwise idle CPUs."""
    cpu_count = os.cpu_count() or 1
    if cpu_count < 16:
        return 0, []

    queue_paths = sorted(Path(f"/sys/class/net/{interface}/queues").glob("rx-*"))
    if not queue_paths:
        return 0, []

    errors: List[str] = []
    success = 0
    table_size = 1_048_576
    per_queue = max(4_096, min(32_768, table_size // len(queue_paths)))
    global_table = run(
        ["sysctl", "-w", f"net.core.rps_sock_flow_entries={table_size}"]
    )
    if global_table.returncode != 0:
        errors.append(
            f"{interface} RFS table: "
            f"{global_table.stderr.strip() or global_table.stdout.strip()}"
        )
        return success, errors

    mask = cpu_mask(cpu_count)
    for queue_path in queue_paths:
        try:
            (queue_path / "rps_cpus").write_text(mask, encoding="ascii")
            (queue_path / "rps_flow_cnt").write_text(str(per_queue), encoding="ascii")
            success += 1
        except OSError as exc:
            errors.append(f"{queue_path.name} RFS: {exc}")
    return success, errors


def tune_network_interfaces() -> Tuple[int, List[str]]:
    """Apply idempotent live queue tuning without touching interface addresses."""
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

        speed = run([ethtool, interface])
        speed_match = re.search(r"^\s*Speed:\s*(\d+)Mb/s", speed.stdout, re.MULTILINE)
        speed_mbps = int(speed_match.group(1)) if speed.returncode == 0 and speed_match else 0
        if speed_mbps >= 10_000:
            rfs_success, rfs_errors = tune_receive_flow_steering(interface)
            success += rfs_success
            errors.extend(rfs_errors)

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

        if speed_mbps >= 10_000:
            coalesce = run([ethtool, "-C", interface, "rx-usecs", "1"])
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
                    r"^\d+:\s+((?:tun\d+|xd_tun2socks|xd_t2s\d+)):",
                    ip_result.stdout,
                    re.MULTILINE,
                )
            )
        )
        for interface in tun_names:
            qlen = run(["ip", "link", "set", "dev", interface, "txqueuelen", "8192"])
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
        try:
            if Path(f"/proc/{pid}/comm").read_text().strip() == "nginx":
                soft, hard = resource.prlimit(pid, resource.RLIMIT_NOFILE)
                requested = max(PROCESS_NOFILE, 2097152, soft)
                resource.prlimit(pid, resource.RLIMIT_NOFILE, (requested, max(hard, requested)))
                resource.prlimit(pid, resource.RLIMIT_NPROC, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
                success += 1
                continue
        except (OSError, ValueError) as exc:
            errors.append(f"pid {pid}: {exc}")
            continue
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

    if conntrack_loaded:
        conntrack_ok, conntrack_detail = apply_conntrack_capacity()
    else:
        conntrack_ok = False
    sysctl_ok, sysctl_errors = apply_sysctls()
    service_ok, service_errors = apply_runtime_task_limits()
    process_ok, process_errors = apply_process_limits()
    cpu_ok, cpu_errors = tune_cpu_governor()
    network_ok, network_errors = tune_network_interfaces()
    own_errors = apply_own_limits()

    errors = (
        sysctl_errors
        + service_errors
        + process_errors
        + cpu_errors
        + network_errors
        + own_errors
    )
    if not conntrack_ok:
        errors.insert(0, f"nf_conntrack: {conntrack_detail}")
    log(
        "applied "
        f"sysctl={sysctl_ok}/{len(SYSCTLS)} "
        f"services={service_ok} processes={process_ok} cpu={cpu_ok} "
        f"network={network_ok} "
        f"conntrack={'ok' if conntrack_ok else 'warning'} ({conntrack_detail})"
    )
    log(
        "runtime "
        f"conntrack={sysctl_value('net.netfilter.nf_conntrack_count')}/"
        f"{sysctl_value('net.netfilter.nf_conntrack_max')} "
        f"stunnel_pool_tasks_max={task_limit('xd-stunnel-pool@0.service')}"
    )

    for error in errors:
        log(f"WARN {error}")
    if errors:
        log(f"completed with {len(errors)} warning(s)")
        return 1

    log("all live limits were applied successfully")
    return 0


def refresh_live_tuning() -> None:
    """Recover settings that can be reset by a process or interface restart."""
    process_ok, process_errors = apply_process_limits()
    cpu_ok, cpu_errors = tune_cpu_governor()
    network_ok, network_errors = tune_network_interfaces()
    errors = process_errors + cpu_errors + network_errors
    if errors:
        for error in errors:
            log(f"REFRESH WARN {error}")
        return
    log(
        f"refreshed processes={process_ok} cpu={cpu_ok} network={network_ok}"
    )


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
    parser.add_argument(
        "--refresh-seconds",
        type=int,
        default=DEFAULT_REFRESH_SECONDS,
        help=(
            "refresh live process/NIC/TUN settings at this interval under PM2; "
            "use 0 to disable (default: 300)"
        ),
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
    if args.refresh_seconds < 0 or 0 < args.refresh_seconds < 30:
        raise SystemExit("--refresh-seconds must be 0 or at least 30")
    if args.refresh_seconds == 0:
        log("idle under PM2; live refresh is disabled")
    else:
        log(f"idle under PM2; refreshing live tuning every {args.refresh_seconds}s")
    next_refresh = time.monotonic() + args.refresh_seconds
    while not STOP_REQUESTED:
        time.sleep(1)
        if args.refresh_seconds and time.monotonic() >= next_refresh:
            refresh_live_tuning()
            next_refresh = time.monotonic() + args.refresh_seconds
    return 0


if __name__ == "__main__":
    sys.exit(main())
