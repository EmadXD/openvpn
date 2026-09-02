#!/usr/bin/env python3
import glob
import ipaddress
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlencode, urlsplit

# ---------------- تنظیمات ----------------
IPSET_NAME = "proxylist"
LEGACY_VPN_SUBNET = "10.8.0.0/14"
PROXY_TABLE = "100"
TUN_DEV = "xd_tun2socks"
TUN_ADDR = "192.168.255.1/24"
SOCKS_PROXY = "socks5://127.0.0.1:1080"
MARK_CHAIN = "XD_T2S_MARK"
FORWARD_CHAIN = "XD_T2S_FWD"
NAT_CHAIN = "XD_T2S_NAT"
HEALTH_INTERVAL_SECONDS = 60
PROXY_API_URL = "https://aparatvpn.com/XDvpn/api_v1/ads_proxy.php?api_key=XXX"
FLOAT_IP_API_URL = "https://aparatvpn.com/XDvpn/api_v1/dedicated_float_pool.php?api_key=XXX"
TUN2SOCKS_BINARY_URL = "https://aparatvpn.com/tun2socks"
FLOAT_STATE_DIR = Path("/etc/xd-dedicated-float")
FLOAT_SERVICE_PREFIX = "xd-dedicated-float-"
FLOAT_SYNC_SCRIPT_PATH = Path("/usr/local/sbin/xd-dedicated-float-sync")
FLOAT_UNIT_DIR = Path("/etc/systemd/system")
MAX_FLOAT_IPS = 65536
use_dnstt = False

DOMAINS = [
    "1e100.net",
    "1e100.com",
    "1e100.org",
    "2mdn-cn.net",
    "2mdn.net",
    "ad.doubleclick.net",
    "adclick.g.doubleclick.net",
    "admob-api.google.com",
    "admob-cn.com",
    "admob.com",
    "admob.google.com",
    "admob.googleapis.com",
    "adservice.google.com",
    "adservices.google.com",
    "adsense.com",
    "analytics.google.com",
    "app-measurement-cn.com",
    "app-measurement.com",
    "apps.admob.com",
    "clients.google.com",
    "dartsearch.net",
    "developers.google.com",
    "doubleclick-cn.net",
    "doubleclick.net",
    "doubleclick.com",
    "firebase.google.com",
    "g.doubleclick.net",
    "google-analytics.com",
    "googleadservices.com",
    "googleads.com",
    "googleapis.com",
    "googlesyndication.com",
    "googletagmanager.com",
    "googletagservices.com",
    "gstatic.com",
    "pagead2.googlesyndication.com",
    "play.googleapis.com",
    "pubads.g.doubleclick.net",
    "securepubads.g.doubleclick.net",
    "support.google.com",
    "tpc.googlesyndication.com",
    "partner.googleadservices.com",
    "stats.g.doubleclick.net",
    "pagead.l.doubleclick.net",
    "googleusercontent.com",
    "ssl.google-analytics.com",

    "browserleaks.com", "aparatvpn.com",

    "stun.l.google.com",
    "stun1.l.google.com",
    "stun2.l.google.com",
    "stun3.l.google.com",
    "stun4.l.google.com",
]

FULL_ROUTE_TO_PROXY = True
block_udp = True


# ---------------- Helpers ----------------
def run_cmd(cmd, check=False, timeout=300):
    print(f"[+] Running: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, check=True,
                                capture_output=True, text=True, timeout=timeout)
        if result.stdout:
            print(result.stdout.strip())
        return result
    except subprocess.CalledProcessError as e:
        print(f"[!] Error: {cmd}")
        if e.stderr:
            print(e.stderr.strip())
        if check:
            raise
        return e
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout after {timeout}s: {cmd}")
        if check:
            raise
        return None


def run_cmd_return(cmd):
    print(f"[+] Running: {cmd}")
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            check=True,
            capture_output=True,
            text=True
        )
        output = result.stdout if result.stdout else ""
        print(output, end="")  # نشان دادن در ترمینال
        return output  # برگرداندن همان خروجی

    except subprocess.CalledProcessError as e:
        error = e.stderr if e.stderr else ""
        print(error, end="")  # چاپ مثل ترمینال
        return error  # برگرداندن همان متن خطا


def write_text_if_changed(path, content, mode=0o644):
    target = Path(path)
    if target.exists() and target.read_text() == content:
        os.chmod(target, mode)
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp")
    temporary.write_text(content)
    os.chmod(temporary, mode)
    os.replace(temporary, target)
    return True


def load_managed_float_states(state_dir=FLOAT_STATE_DIR):
    """Load the floating IPs already supplied by the dedicated host manager."""
    states = {}
    try:
        state_files = sorted(state_dir.glob("host-*.ips"))
    except OSError as exc:
        print(f"[!] Could not inspect floating-IP state: {exc}")
        return states

    for state_file in state_files:
        match = re.fullmatch(r"host-(\d+)\.ips", state_file.name)
        if not match:
            continue
        try:
            lines = state_file.read_text(encoding="ascii").splitlines()
        except OSError as exc:
            print(f"[!] Could not read {state_file}: {exc}")
            continue

        addresses = set()
        for line in lines:
            raw_address = line.split("#", 1)[0].strip()
            if not raw_address:
                continue
            try:
                address = ipaddress.ip_address(raw_address.split("/", 1)[0])
            except ValueError:
                print(f"[!] Ignoring invalid floating IP in {state_file}: {raw_address}")
                continue
            if isinstance(address, ipaddress.IPv4Address):
                addresses.add(str(address))
        if addresses:
            states[match.group(1)] = addresses
    return states


def primary_source_ipv4():
    """Return the IPv4 address the host uses for ordinary Internet traffic."""
    result = subprocess.run(
        ["ip", "-4", "route", "get", "1.1.1.1"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "could not determine primary IPv4")
    match = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)\b", result.stdout)
    if not match:
        raise RuntimeError("primary IPv4 was not present in the route result")
    address = ipaddress.ip_address(match.group(1))
    if not isinstance(address, ipaddress.IPv4Address):
        raise RuntimeError("primary address is not IPv4")
    return str(address)


def split_pool_tokens(raw_value):
    return [
        token.strip().strip("\\")
        for token in re.split(r"[,;\s]+", str(raw_value or ""))
        if token.strip().strip("\\")
    ]


def expand_ip_token(token, max_addresses=MAX_FLOAT_IPS):
    token = token.strip()
    if not token:
        return []

    if "-" in token and "/" not in token:
        start_raw, end_raw = token.split("-", 1)
        start = ipaddress.ip_address(start_raw.strip())
        end = ipaddress.ip_address(end_raw.strip())
        if not isinstance(start, ipaddress.IPv4Address) or not isinstance(end, ipaddress.IPv4Address):
            raise ValueError("only IPv4 ranges are supported")
        count = int(end) - int(start) + 1
        if count <= 0 or count > max_addresses:
            raise ValueError(f"invalid or oversized IPv4 range: {token}")
        return [str(ipaddress.ip_address(value)) for value in range(int(start), int(end) + 1)]

    if "/" in token:
        network = ipaddress.ip_network(token, strict=False)
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("only IPv4 networks are supported")
        if network.num_addresses > max_addresses + 2:
            raise ValueError(f"oversized IPv4 network: {token}")
        return [str(address) for address in network.hosts()]

    address = ipaddress.ip_address(token)
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("only IPv4 addresses are supported")
    return [str(address)]


def expand_ip_pool(raw_value):
    addresses = []
    seen = set()
    for token in split_pool_tokens(raw_value):
        try:
            expanded = expand_ip_token(token, MAX_FLOAT_IPS - len(addresses))
        except ValueError as exc:
            print(f"[!] Ignoring invalid floating-IP pool token {token!r}: {exc}")
            continue
        for address in expanded:
            if address not in seen:
                seen.add(address)
                addresses.append(address)
                if len(addresses) >= MAX_FLOAT_IPS:
                    return addresses
    return addresses


def split_subnet_definitions(raw_value):
    return [
        item.strip().strip("\\")
        for item in re.split(r"[,;\n]+", str(raw_value or ""))
        if item.strip().strip("\\")
    ]


def expand_subnet_definitions(raw_value):
    addresses = []
    seen = set()
    for definition in split_subnet_definitions(raw_value):
        parts = [part.strip() for part in definition.split(":")]
        interface_raw = parts[0]
        gateway_raw = parts[1] if len(parts) > 1 else ""
        try:
            interface = ipaddress.ip_interface(interface_raw)
            if not isinstance(interface, ipaddress.IPv4Interface):
                raise ValueError("only IPv4 subnets are supported")
            gateway = ipaddress.ip_address(gateway_raw) if gateway_raw else None
            if gateway is not None and not isinstance(gateway, ipaddress.IPv4Address):
                raise ValueError("gateway is not IPv4")
            if interface.network.num_addresses > MAX_FLOAT_IPS + 2:
                raise ValueError("subnet is too large")
        except ValueError as exc:
            print(f"[!] Ignoring invalid floating subnet {definition!r}: {exc}")
            continue

        first_allowed = int(interface.ip)
        for address in interface.network.hosts():
            if int(address) < first_allowed or address == gateway:
                continue
            value = str(address)
            if value not in seen:
                seen.add(value)
                addresses.append(value)
                if len(addresses) >= MAX_FLOAT_IPS:
                    return addresses
    return addresses


def fetch_managed_float_profile():
    """Fetch this host's current floating-IP pool from the central database."""
    host_ip = primary_source_ipv4()
    separator = "&" if "?" in FLOAT_IP_API_URL else "?"
    url = FLOAT_IP_API_URL + separator + urlencode({"host_ip": host_ip})
    request = urllib.request.Request(url, headers={"User-Agent": "XD-route-ads/3"})

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload_raw = response.read(2 * 1024 * 1024 + 1)
            if len(payload_raw) > 2 * 1024 * 1024:
                raise RuntimeError("floating-IP API response is too large")
            payload = json.loads(payload_raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise RuntimeError(f"floating-IP API returned HTTP {exc.code}") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"floating-IP API request failed: {exc}") from exc

    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise RuntimeError("floating-IP API returned an invalid payload")

    try:
        host_id = int(payload["host_id"])
        returned_host_ip = str(ipaddress.ip_address(str(payload["host_ip"])))
        public_interface = str(payload["public_interface"]).strip()
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("floating-IP API response is missing required fields") from exc

    creator = str(payload.get("creator", "")).strip().lower()
    if host_id <= 0 or returned_host_ip != host_ip:
        raise RuntimeError("floating-IP API returned a mismatched host")
    if creator not in {"float", "floating", "floating_ip", "float_ip"}:
        raise RuntimeError("floating-IP API returned a non-floating host")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", public_interface):
        raise RuntimeError("floating-IP API returned an invalid interface")

    addresses = expand_ip_pool(payload.get("ip_pool_csv", ""))
    if not addresses:
        addresses = expand_subnet_definitions(payload.get("subnet_definitions", ""))
    addresses = [address for address in addresses if address != host_ip]
    if not addresses:
        raise RuntimeError("floating-IP database pool is empty")

    return {
        "host_id": host_id,
        "host_ip": host_ip,
        "public_interface": public_interface,
        "addresses": addresses,
        "pool_sha256": str(payload.get("pool_sha256", "")),
    }


def ensure_float_sync_service(profile):
    host_id = profile["host_id"]
    interface = profile["public_interface"]
    addresses = sorted(set(profile["addresses"]), key=lambda value: int(ipaddress.ip_address(value)))
    FLOAT_STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(FLOAT_STATE_DIR, 0o700)

    sync_script = """#!/bin/sh
set -eu
host_id="$1"
interface="$2"
state="/etc/xd-dedicated-float/host-${host_id}.ips"
test -s "$state"
ip link show "$interface" >/dev/null
ip link set "$interface" up
while IFS= read -r address; do
    test -n "$address" || continue
    ip addr replace "${address}/32" dev "$interface"
done < "$state"
"""
    script_changed = write_text_if_changed(FLOAT_SYNC_SCRIPT_PATH, sync_script, mode=0o700)

    state_path = FLOAT_STATE_DIR / f"host-{host_id}.ips"
    state_changed = write_text_if_changed(
        state_path,
        "".join(f"{address}\n" for address in addresses),
        mode=0o600,
    )

    unit = f"{FLOAT_SERVICE_PREFIX}{host_id}.service"
    unit_path = FLOAT_UNIT_DIR / unit
    unit_content = f"""[Unit]
Description=Direct floating IPs for dedicated host {host_id}
After=network-online.target stunnel4.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={FLOAT_SYNC_SCRIPT_PATH} {host_id} {interface}

[Install]
WantedBy=multi-user.target
"""
    unit_changed = write_text_if_changed(unit_path, unit_content, mode=0o644)
    if script_changed or unit_changed:
        run_cmd("systemctl daemon-reload", check=True)
    run_cmd(f"systemctl enable {shlex.quote(unit)}", check=True)

    if state_changed:
        print(
            f"[+] Floating-IP state updated from DB: host={host_id}, "
            f"addresses={len(addresses)}, hash={profile['pool_sha256'][:12] or 'n/a'}"
        )
    return state_changed


def sync_managed_floating_ips_from_database():
    """Sync DB state, then restore only missing addresses; never remove live IPs."""
    try:
        profile = fetch_managed_float_profile()
        if profile is not None:
            ensure_float_sync_service(profile)
    except Exception as exc:
        print(f"[!] Floating-IP DB sync failed; preserving cached state: {exc}")
    return refresh_managed_floating_ips()


def current_global_ipv4_addresses():
    result = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "scope", "global"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "could not list global IPv4 addresses")
    return set(re.findall(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/\d+", result.stdout))


def refresh_managed_floating_ips():
    """Restore missing managed IPs without deleting any address from the host."""
    states = load_managed_float_states()
    if not states:
        return True

    try:
        current = current_global_ipv4_addresses()
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        print(f"[!] Floating-IP check failed: {exc}")
        return False

    missing_by_host = {
        host_id: addresses - current
        for host_id, addresses in states.items()
        if addresses - current
    }
    if not missing_by_host:
        return True

    missing_count = sum(len(addresses) for addresses in missing_by_host.values())
    print(f"[!] Restoring {missing_count} missing managed floating IP(s).")
    for host_id in sorted(missing_by_host, key=int):
        unit = f"{FLOAT_SERVICE_PREFIX}{host_id}.service"
        result = run_cmd(f"systemctl restart {shlex.quote(unit)}")
        if result is None or result.returncode != 0:
            print(f"[!] Could not refresh floating IPs through {unit}.")

    try:
        current = current_global_ipv4_addresses()
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        print(f"[!] Floating-IP verification failed: {exc}")
        return False

    expected = set().union(*states.values())
    remaining = expected - current
    if remaining:
        print(f"[!] {len(remaining)} managed floating IP(s) are still missing.")
        return False
    print(f"[+] Restored all {missing_count} missing managed floating IP(s).")
    return True


def ensure_required_packages():
    command_packages = {
        "curl": "curl",
        "dnsmasq": "dnsmasq",
        "ipset": "ipset",
        "iptables": "iptables",
    }
    missing = sorted({package for command, package in command_packages.items()
                      if shutil.which(command) is None})
    if not missing:
        return
    run_cmd("DEBIAN_FRONTEND=noninteractive apt-get update", check=True, timeout=600)
    packages = " ".join(shlex.quote(package) for package in missing)
    run_cmd(f"DEBIAN_FRONTEND=noninteractive apt-get install -y {packages}",
            check=True, timeout=900)


def valid_tun2socks_binary(path):
    try:
        candidate = Path(path)
        if candidate.stat().st_size < 5 * 1024 * 1024:
            return False
        with candidate.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


def download_file(url, destination, timeout=180):
    result = subprocess.run(
        ["curl", "-fL", "--connect-timeout", "15", "--max-time", str(timeout),
         "--retry", "2", "--retry-delay", "2", "-o", str(destination), url],
        capture_output=True,
        text=True,
        timeout=timeout + 15,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"download failed for {url}: {detail[-400:]}")


# ---------------- Install Packages ----------------
def setup_install_packages():
    tun2socks_path = Path("/opt/tun2socks")
    if valid_tun2socks_binary(tun2socks_path):
        print("[+] Existing tun2socks binary is valid.")
        return

    architecture = platform.machine().lower()
    asset_arch = {
        "amd64": "amd64",
        "x86_64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(architecture)
    if not asset_arch:
        raise RuntimeError(f"unsupported architecture for tun2socks: {architecture}")

    errors = []
    with tempfile.TemporaryDirectory(prefix="tun2socks-install-") as temp_dir:
        temp_dir = Path(temp_dir)
        candidate = temp_dir / "tun2socks"

        archive_url = (
            "https://github.com/xjasonlyu/tun2socks/releases/latest/download/"
            f"tun2socks-linux-{asset_arch}.zip"
        )
        try:
            archive = temp_dir / "tun2socks.zip"
            download_file(archive_url, archive)
            with zipfile.ZipFile(archive) as zipped:
                members = [name for name in zipped.namelist()
                           if Path(name).name == f"tun2socks-linux-{asset_arch}"]
                if not members:
                    raise RuntimeError("tun2socks executable is missing from release archive")
                candidate.write_bytes(zipped.read(members[0]))
        except Exception as exc:
            errors.append(str(exc))

        if not valid_tun2socks_binary(candidate):
            try:
                candidate.unlink(missing_ok=True)
                download_file(TUN2SOCKS_BINARY_URL, candidate)
            except Exception as exc:
                errors.append(str(exc))

        if not valid_tun2socks_binary(candidate):
            raise RuntimeError("unable to install a valid tun2socks binary: " + " | ".join(errors))

        Path("/opt").mkdir(parents=True, exist_ok=True)
        install_candidate = Path("/opt/.tun2socks.new")
        shutil.copyfile(candidate, install_candidate)
        os.chmod(install_candidate, 0o755)
        os.replace(install_candidate, tun2socks_path)
        print(f"[+] Installed tun2socks ({tun2socks_path.stat().st_size} bytes).")


def discover_vpn_subnets():
    networks = set()
    config_paths = set(glob.glob("/etc/openvpn/server*.conf"))
    config_paths.update(glob.glob("/etc/openvpn/server/*.conf"))

    for config_path in sorted(config_paths):
        try:
            for raw_line in Path(config_path).read_text(errors="ignore").splitlines():
                line = raw_line.split("#", 1)[0].split(";", 1)[0].strip()
                match = re.match(r"^server\s+(\S+)\s+(\S+)$", line)
                if not match:
                    continue
                networks.add(ipaddress.ip_network(
                    f"{match.group(1)}/{match.group(2)}", strict=False
                ))
        except OSError as exc:
            print(f"[!] Could not read {config_path}: {exc}")

    try:
        output = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        ).stdout
        for line in output.splitlines():
            match = re.search(r"\d+:\s+(tun\d+)\s+.*?\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
            if match:
                networks.add(ipaddress.ip_interface(match.group(2)).network)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"[!] Could not inspect active OpenVPN interfaces: {exc}")

    networks = {network for network in networks
                if isinstance(network, ipaddress.IPv4Network)}
    if not networks:
        networks.add(ipaddress.ip_network(LEGACY_VPN_SUBNET))

    # Collapse only exactly adjacent/overlapping networks. On a multi-instance
    # host this turns 10.8/16..10.23/16 into two exact /13 rules instead of
    # making every packet walk sixteen equivalent iptables rules.
    result = sorted(
        ipaddress.collapse_addresses(networks),
        key=lambda item: (int(item.network_address), item.prefixlen),
    )
    print("[+] OpenVPN subnets: " + ", ".join(str(item) for item in result))
    return [str(item) for item in result]


# ---------------- ipset ----------------
def setup_ipset():
    result = run_cmd(
        f"ipset create {shlex.quote(IPSET_NAME)} hash:ip "
        "family inet hashsize 4096 maxelem 1048576 -exist",
    )
    if result is not None and result.returncode == 0:
        return

    existing = subprocess.run(
        ["ipset", "list", IPSET_NAME],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if existing.returncode == 0 and re.search(r"^Type:\s+hash:ip\s*$", existing.stdout, re.MULTILINE):
        print("[!] Preserving the existing compatible proxylist ipset parameters.")
        return
    raise RuntimeError(f"unable to create or reuse the {IPSET_NAME} ipset")


# ---------------- dnsmasq ----------------
def setup_dnsmasq():
    dnsmasq_main = """port=53
listen-address=127.0.0.1,10.8.0.1
bind-dynamic
conf-dir=/etc/dnsmasq.d/,*.conf
dns-forward-max=999999
"""
    ipset_config = "".join(
        f"ipset=/{domain}/{IPSET_NAME}\n" for domain in DOMAINS
    )
    dns_openvpn = """server=1.1.1.1
server=1.0.0.1
"""

    write_text_if_changed("/etc/dnsmasq.conf", dnsmasq_main)
    write_text_if_changed("/etc/dnsmasq.d/ipset.conf", ipset_config)
    write_text_if_changed("/etc/dnsmasq.d/openvpn_dns.conf", dns_openvpn)
    run_cmd("dnsmasq --test", check=True)
    run_cmd("systemctl enable dnsmasq", check=True)
    run_cmd("systemctl restart dnsmasq", check=True)


# ---------------- tun2socks interface ----------------
def setup_tun2socks_interface():
    run_cmd(f"ip link show {TUN_DEV} >/dev/null 2>&1 || ip tuntap add dev {TUN_DEV} mode tun")
    run_cmd(f"ip addr show dev {TUN_DEV} | grep -q '{TUN_ADDR.split('/')[0]}' || ip addr add {TUN_ADDR} dev {TUN_DEV}")
    run_cmd(f"ip link set {TUN_DEV} up")


# ---------------- iptables ----------------
def iptables_call(table, arguments, check=False):
    command = ["iptables", "-w", "10"]
    if table != "filter":
        command.extend(["-t", table])
    command.extend(arguments)
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"iptables command failed: {' '.join(command)}: {result.stderr.strip()}"
        )
    return result


def ensure_chain(table, chain):
    result = iptables_call(table, ["-N", chain])
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip())
    iptables_call(table, ["-F", chain], check=True)


def ensure_jump(table, parent, child):
    rule = ["-j", child]
    if iptables_call(table, ["-C", parent] + rule).returncode != 0:
        iptables_call(table, ["-I", parent, "1"] + rule, check=True)


def remove_rule_all(table, chain, rule):
    while iptables_call(table, ["-C", chain] + rule).returncode == 0:
        iptables_call(table, ["-D", chain] + rule, check=True)


def remove_legacy_rules():
    legacy_mark = [
        "-s", LEGACY_VPN_SUBNET,
        "-m", "set", "--match-set", IPSET_NAME, "dst",
        "-j", "MARK", "--set-mark", "1",
    ]
    legacy_mark_ports = [
        "-s", LEGACY_VPN_SUBNET, "-p", "tcp",
        "-m", "multiport", "--dports", "80,443,8080,8443",
        "-m", "set", "--match-set", IPSET_NAME, "dst",
        "-j", "MARK", "--set-mark", "1",
    ]
    legacy_udp = [
        "-s", LEGACY_VPN_SUBNET, "-p", "udp",
        "-m", "mark", "--mark", "1", "-j", "DROP",
    ]
    for rule in (legacy_mark, legacy_mark_ports, legacy_udp):
        remove_rule_all("mangle", "PREROUTING", rule)

    remove_rule_all("mangle", "PREROUTING", ["-j", "TUN2SOCKS"])


def setup_vpn_forwarding(vpn_subnets):
    ensure_chain("filter", FORWARD_CHAIN)
    ensure_jump("filter", "FORWARD", FORWARD_CHAIN)
    ensure_chain("nat", NAT_CHAIN)
    ensure_jump("nat", "POSTROUTING", NAT_CHAIN)

    for subnet in vpn_subnets:
        iptables_call("filter", [
            "-A", FORWARD_CHAIN, "-s", subnet, "-o", TUN_DEV, "-j", "ACCEPT"
        ], check=True)
        iptables_call("filter", [
            "-A", FORWARD_CHAIN, "-d", subnet, "-i", TUN_DEV,
            "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"
        ], check=True)
        iptables_call("nat", [
            "-A", NAT_CHAIN, "-s", subnet, "-o", TUN_DEV, "-j", "MASQUERADE"
        ], check=True)


def setup_iptables_fwmark(vpn_subnets):
    remove_legacy_rules()
    ensure_chain("mangle", MARK_CHAIN)
    ensure_jump("mangle", "PREROUTING", MARK_CHAIN)

    for subnet in vpn_subnets:
        mark_rule = ["-A", MARK_CHAIN, "-s", subnet]
        if not FULL_ROUTE_TO_PROXY:
            mark_rule.extend([
                "-p", "tcp", "-m", "multiport",
                "--dports", "80,443,8080,8443",
            ])
        mark_rule.extend([
            "-m", "set", "--match-set", IPSET_NAME, "dst",
            "-j", "MARK", "--set-xmark", "0x1/0x1",
        ])
        iptables_call("mangle", mark_rule, check=True)

        if block_udp:
            iptables_call("mangle", [
                "-A", MARK_CHAIN, "-s", subnet, "-p", "udp",
                "-m", "mark", "--mark", "0x1/0x1", "-j", "DROP",
            ], check=True)


def setup_iptables_dnstt(DNSTT_PORT):
    import subprocess
    import shutil
    import os
    import sys

    def run(cmd):
        return subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

    # iptables exists?
    if not shutil.which("iptables"):
        sys.exit(1)

    # detect interface
    interface = None
    try:
        interface = subprocess.check_output(
            "ip route | grep default | awk '{print $5}' | head -1",
            shell=True,
            text=True
        ).strip()
    except:
        pass

    if not interface:
        try:
            interface = subprocess.check_output(
                r"ip link show | grep -E '^[0-9]+: (eth|ens|enp)' | head -1 | cut -d':' -f2 | awk '{print $1}'",
                shell=True,
                text=True
            ).strip()
        except:
            pass

    if not interface:
        interface = "eth0"

    # IPv4
    if not run(f"iptables -I INPUT -p udp --dport {DNSTT_PORT} -j ACCEPT"):
        sys.exit(1)

    if not run(
            f"iptables -t nat -I PREROUTING -i {interface} -p udp --dport 53 "
            f"-j REDIRECT --to-ports {DNSTT_PORT}"
    ):
        sys.exit(1)

    # IPv6 (best-effort)
    if shutil.which("ip6tables") and os.path.exists("/proc/net/if_inet6"):
        run(f"ip6tables -I INPUT -p udp --dport {DNSTT_PORT} -j ACCEPT")
        run(
            f"ip6tables -t nat -I PREROUTING -i {interface} -p udp --dport 53 "
            f"-j REDIRECT --to-ports {DNSTT_PORT}"
        )


def setup_tun2socks_routing():
    rt_tables_path = Path("/etc/iproute2/rt_tables")
    rt_tables = rt_tables_path.read_text(errors="ignore")
    if not re.search(rf"^\s*{re.escape(PROXY_TABLE)}\s+tun2socks\s*$", rt_tables, re.MULTILINE):
        with rt_tables_path.open("a") as handle:
            handle.write(f"\n{PROXY_TABLE} tun2socks\n")

    rules = subprocess.run(
        ["ip", "rule", "show"], check=True, capture_output=True, text=True, timeout=15
    ).stdout
    if not any("fwmark 0x1" in line and ("lookup tun2socks" in line or "lookup 100" in line)
               for line in rules.splitlines()):
        run_cmd("ip rule add priority 100 fwmark 0x1/0x1 table tun2socks", check=True)

    gateway = TUN_ADDR.split("/")[0]
    run_cmd(
        f"ip route replace default via {shlex.quote(gateway)} dev {shlex.quote(TUN_DEV)} table tun2socks",
        check=True,
    )


# ---------------- systemd tun2socks ----------------
def clean_proxy_url(raw_url: str) -> str:
    url = raw_url.strip().replace('\ufeff', '')
    url = re.sub(r'\s+', '', url)
    if not url.startswith("socks5://") and not url.startswith("http://") and not url.startswith("https://"):
        url = "socks5://" + url
    url = url.rstrip('/')
    try:
        parsed = urlsplit(url)
        valid = (
            parsed.scheme in {"socks5", "http", "https"}
            and bool(parsed.hostname)
            and parsed.port is not None
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("proxy API returned an invalid proxy URL")
    return url


def current_service_proxy():
    service_path = Path("/etc/systemd/system/tun2socks.service")
    if not service_path.exists():
        return None
    match = re.search(
        r"^ExecStart=.*?\s-proxy\s+(\S+)",
        service_path.read_text(errors="ignore"),
        re.MULTILINE,
    )
    if not match:
        return None
    try:
        # A literal percent sign is escaped as %% inside a systemd unit.
        return clean_proxy_url(match.group(1).strip("\"'").replace("%%", "%"))
    except ValueError:
        return None


def fetch_proxy_url():
    try:
        request = urllib.request.Request(PROXY_API_URL, headers={"User-Agent": "XD-route-ads/2"})
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 200:
                raise RuntimeError(f"proxy API returned HTTP {response.status}")
            return clean_proxy_url(response.read(4096).decode("utf-8", errors="replace"))
    except Exception as exc:
        existing = current_service_proxy()
        if existing:
            print(f"[!] Proxy fetch failed; preserving current service proxy: {exc}")
            return existing
        raise RuntimeError(f"proxy fetch failed and no previous proxy is available: {exc}") from exc


def redact_proxy(proxy_url):
    return re.sub(r"(?<=//)[^/@]+@", "***@", proxy_url)


def create_systemd_service():
    global SOCKS_PROXY
    # Proxy refresh and floating-IP refresh share one lifecycle entry point.
    # The database remains authoritative; cached state is only a safe fallback.
    sync_managed_floating_ips_from_database()
    SOCKS_PROXY = fetch_proxy_url()
    systemd_proxy = SOCKS_PROXY.replace("%", "%%")
    print(f"[+] Using proxy: {redact_proxy(SOCKS_PROXY)}")

    service_content = f"""[Unit]
Description=Tun2Socks Service
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStartPre=/bin/bash -c 'ip link show {TUN_DEV} >/dev/null 2>&1 || ip tuntap add dev {TUN_DEV} mode tun'
ExecStartPre=/bin/bash -c 'ip addr show dev {TUN_DEV} | grep -q "{TUN_ADDR.split("/")[0]}" || ip addr add {TUN_ADDR} dev {TUN_DEV}'
ExecStartPre=/sbin/ip link set {TUN_DEV} up
ExecStart=/opt/tun2socks -device {TUN_DEV} -proxy {systemd_proxy} -loglevel error
Restart=always
RestartSec=3
LimitNOFILE=1048576
TasksMax=infinity
TimeoutStopSec=5s
KillMode=mixed
SendSIGKILL=yes

[Install]
WantedBy=multi-user.target
"""
    changed = write_text_if_changed(
        "/etc/systemd/system/tun2socks.service", service_content, mode=0o600
    )
    if changed:
        run_cmd("systemctl daemon-reload", check=True)
    run_cmd("systemctl enable tun2socks.service", check=True)
    run_cmd("systemctl restart tun2socks.service", check=True)


def prepare_dnsmasq_install():
    run_cmd("systemctl disable --now systemd-resolved 2>/dev/null || true")
    try:
        Path("/etc/resolv.conf").unlink(missing_ok=True)
    except OSError:
        pass
    write_text_if_changed(
        "/etc/resolv.conf", "nameserver 1.1.1.1\nnameserver 1.0.0.1\n"
    )


def use_local_dnsmasq():
    run_cmd("systemctl disable --now systemd-resolved 2>/dev/null || true")
    try:
        Path("/etc/resolv.conf").unlink(missing_ok=True)
    except OSError:
        pass
    write_text_if_changed("/etc/resolv.conf", "nameserver 10.8.0.1\n")


def firewall_rules_present(vpn_subnets):
    if iptables_call("mangle", ["-C", "PREROUTING", "-j", MARK_CHAIN]).returncode != 0:
        return False
    if iptables_call("filter", ["-C", "FORWARD", "-j", FORWARD_CHAIN]).returncode != 0:
        return False
    if iptables_call("nat", ["-C", "POSTROUTING", "-j", NAT_CHAIN]).returncode != 0:
        return False
    for subnet in vpn_subnets:
        mark_rule = ["-s", subnet]
        if not FULL_ROUTE_TO_PROXY:
            mark_rule.extend([
                "-p", "tcp", "-m", "multiport", "--dports", "80,443,8080,8443"
            ])
        mark_rule.extend([
            "-m", "set", "--match-set", IPSET_NAME, "dst",
            "-j", "MARK", "--set-xmark", "0x1/0x1",
        ])
        forward_out = ["-s", subnet, "-o", TUN_DEV, "-j", "ACCEPT"]
        forward_back = [
            "-d", subnet, "-i", TUN_DEV,
            "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT",
        ]
        masquerade = ["-s", subnet, "-o", TUN_DEV, "-j", "MASQUERADE"]
        checks = (
            ("mangle", MARK_CHAIN, mark_rule),
            ("filter", FORWARD_CHAIN, forward_out),
            ("filter", FORWARD_CHAIN, forward_back),
            ("nat", NAT_CHAIN, masquerade),
        )
        if any(
            iptables_call(table, ["-C", chain] + rule).returncode != 0
            for table, chain, rule in checks
        ):
            return False
        if block_udp:
            udp_drop = [
                "-s", subnet, "-p", "udp",
                "-m", "mark", "--mark", "0x1/0x1", "-j", "DROP",
            ]
            if iptables_call("mangle", ["-C", MARK_CHAIN] + udp_drop).returncode != 0:
                return False
    return True


def service_is_active(unit):
    return subprocess.run(
        ["systemctl", "is-active", "--quiet", unit],
        timeout=15,
    ).returncode == 0


def tun_interface_is_ready():
    result = subprocess.run(
        ["ip", "-o", "-4", "addr", "show", "dev", TUN_DEV],
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result.returncode == 0 and TUN_ADDR.split("/")[0] in result.stdout


def policy_routing_is_ready():
    rules = subprocess.run(
        ["ip", "rule", "show"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    routes = subprocess.run(
        ["ip", "route", "show", "table", PROXY_TABLE],
        capture_output=True,
        text=True,
        timeout=15,
    )
    rule_present = rules.returncode == 0 and any(
        "fwmark 0x1" in line
        and ("lookup tun2socks" in line or f"lookup {PROXY_TABLE}" in line)
        for line in rules.stdout.splitlines()
    )
    expected_gateway = TUN_ADDR.split("/")[0]
    route_present = (
        routes.returncode == 0
        and any(
            line.startswith("default ")
            and f"via {expected_gateway}" in line
            and f"dev {TUN_DEV}" in line
            for line in routes.stdout.splitlines()
        )
    )
    return rule_present and route_present


def ipset_is_ready():
    return subprocess.run(
        ["ipset", "list", IPSET_NAME],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
    ).returncode == 0


def apply_runtime_routing(vpn_subnets):
    setup_tun2socks_interface()
    setup_tun2socks_routing()
    setup_vpn_forwarding(vpn_subnets)
    setup_iptables_fwmark(vpn_subnets)


def health_loop(initial_subnets):
    known_subnets = initial_subnets
    while True:
        time.sleep(HEALTH_INTERVAL_SECONDS)
        try:
            if load_managed_float_states():
                sync_managed_floating_ips_from_database()
            current_subnets = discover_vpn_subnets()
            if not service_is_active("dnsmasq.service"):
                setup_ipset()
                run_cmd("systemctl restart dnsmasq.service", check=True)
            if not service_is_active("tun2socks.service"):
                run_cmd("systemctl restart tun2socks.service", check=True)
            runtime_ready = (
                ipset_is_ready()
                and tun_interface_is_ready()
                and policy_routing_is_ready()
                and firewall_rules_present(current_subnets)
            )
            if current_subnets != known_subnets or not runtime_ready:
                setup_ipset()
                apply_runtime_routing(current_subnets)
                known_subnets = current_subnets
                print("[+] Runtime routing rules repaired.")
        except Exception as exc:
            print(f"[!] Health check failed: {exc}")


# ---------------- main ----------------
def main():
    if os.geteuid() != 0:
        print("[!] لطفاً با sudo اجرا کنید.")
        sys.exit(1)

    prepare_dnsmasq_install()
    ensure_required_packages()
    setup_install_packages()
    setup_ipset()
    setup_dnsmasq()
    use_local_dnsmasq()
    setup_tun2socks_interface()
    create_systemd_service()
    vpn_subnets = discover_vpn_subnets()
    apply_runtime_routing(vpn_subnets)

    if use_dnstt:
        setup_iptables_dnstt(5300)
    print("\n[+] Selective tun2socks routing is active for every OpenVPN subnet.")
    health_loop(vpn_subnets)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Stopped by user.")
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)
