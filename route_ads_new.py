#!/usr/bin/env python3
import glob
import hashlib
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
# The legacy interface/service is kept until all multi-lane services are ready.
TUN_DEV = "xd_tun2socks"
TUN_ADDR = "192.168.255.1/24"
SOCKS_PROXY = "socks5://127.0.0.1:1080"
MULTI_TUN_PREFIX = "xd_t2s"
MULTI_TUN_NETWORK = ipaddress.ip_network("198.18.0.0/15")
MULTI_UNIT_PREFIX = "xd-tun2socks-"
MULTI_STATE_DIR = Path("/etc/xd-tun2socks")
MULTI_PROXY_CACHE_PATH = MULTI_STATE_DIR / "proxies.json"
MULTI_SLOT_PATH = MULTI_STATE_DIR / "slots.json"
MULTI_MARKER_PATH = MULTI_STATE_DIR / "multi.enabled"
MAX_PROXY_LANES = 32
PROXY_REFRESH_SECONDS = 300
MARK_CHAIN = "XD_T2S_MARK"
FORWARD_CHAIN = "XD_T2S_FWD"
NAT_CHAIN = "XD_T2S_NAT"
RECONCILE_INTERVAL_SECONDS = 300
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

# Some clients resolve through browser DNS cache or DoH, so dnsmasq never sees
# their query. Resolve critical route domains locally as well and seed ipset.
IPSET_PREWARM_DOMAINS = tuple(dict.fromkeys(
    DOMAINS + ["www.browserleaks.com", "tls.browserleaks.com"]
))

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


def refresh_proxy_ipset():
    resolved_ips = set()
    try:
        lookup = subprocess.run(
            ["getent", "ahostsv4", *IPSET_PREWARM_DOMAINS],
            capture_output=True,
            text=True,
            timeout=45,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"[!] Proxy ipset prewarm lookup failed: {exc}")
        return

    for line in lookup.stdout.splitlines():
        fields = line.split()
        if not fields:
            continue
        try:
            address = ipaddress.ip_address(fields[0])
        except ValueError:
            continue
        if isinstance(address, ipaddress.IPv4Address):
            resolved_ips.add(str(address))

    added = 0
    for address in sorted(resolved_ips):
        result = subprocess.run(
            ["ipset", "add", IPSET_NAME, address, "-exist"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            added += 1

    print(
        f"[+] Proxy ipset prewarm: {added} IPv4 addresses for "
        f"{len(IPSET_PREWARM_DOMAINS)} configured domains"
    )


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

    changed = write_text_if_changed("/etc/dnsmasq.conf", dnsmasq_main)
    changed = write_text_if_changed("/etc/dnsmasq.d/ipset.conf", ipset_config) or changed
    changed = write_text_if_changed("/etc/dnsmasq.d/openvpn_dns.conf", dns_openvpn) or changed
    run_cmd("dnsmasq --test", check=True)
    run_cmd("systemctl enable dnsmasq", check=True)
    if changed or not service_is_active("dnsmasq.service"):
        run_cmd("systemctl restart dnsmasq", check=True)


# ---------------- tun2socks interfaces ----------------
def lane_device(slot):
    return f"{MULTI_TUN_PREFIX}{slot:02d}"


def lane_address(slot):
    address = MULTI_TUN_NETWORK.network_address + (slot * 4) + 1
    return f"{address}/30"


def lane_gateway(slot):
    return lane_address(slot).split("/", 1)[0]


def lane_unit(slot):
    return f"{MULTI_UNIT_PREFIX}{slot:02d}.service"


def setup_tun2socks_interface(lane):
    device = lane["device"]
    address = lane["address"]
    run_cmd(
        f"ip link show {shlex.quote(device)} >/dev/null 2>&1 || "
        f"ip tuntap add dev {shlex.quote(device)} mode tun",
        check=True,
    )
    run_cmd(
        f"ip addr replace {shlex.quote(address)} dev {shlex.quote(device)}",
        check=True,
    )
    run_cmd(
        f"ip link set dev {shlex.quote(device)} mtu 1500 txqueuelen 8192 up",
        check=True,
    )
    run_cmd(
        f"sysctl -w net.ipv4.conf.{shlex.quote(device)}.rp_filter=0",
        check=True,
    )


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
        # Keep the legacy interface accepted as a rollback path while the
        # multipath route is switched atomically by `ip route replace`.
        for output_interface in (f"{MULTI_TUN_PREFIX}+", TUN_DEV):
            iptables_call("filter", [
                "-A", FORWARD_CHAIN, "-s", subnet,
                "-o", output_interface, "-j", "ACCEPT"
            ], check=True)
            iptables_call("filter", [
                "-A", FORWARD_CHAIN, "-d", subnet,
                "-i", output_interface,
                "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"
            ], check=True)
            iptables_call("nat", [
                "-A", NAT_CHAIN, "-s", subnet,
                "-o", output_interface, "-j", "MASQUERADE"
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


def setup_tun2socks_routing(lanes):
    if not lanes:
        raise RuntimeError("refusing to install an empty tun2socks route")

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

    # L4 hashing keeps every TCP connection on one proxy while distributing
    # different connections across all active lanes.
    run_cmd("sysctl -w net.ipv4.fib_multipath_hash_policy=1", check=True)
    command = [
        "ip", "route", "replace", "default", "table", PROXY_TABLE,
        "scope", "global",
    ]
    for lane in sorted(lanes, key=lambda item: item["slot"]):
        command.extend([
            "nexthop", "dev", lane["device"],
            "weight", str(max(1, int(lane.get("weight", 1)))),
        ])
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"multipath route failed: {result.stderr.strip()}")
    print(f"[+] Active proxy route lanes: {len(lanes)}")


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
        r"^ExecStart=.*?\s--?proxy\s+(\S+)",
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


def proxy_record_key(record):
    digest = hashlib.sha256(record["proxy"].encode("utf-8")).hexdigest()[:12]
    return f"{record.get('id', 0)}-{digest}"


def normalize_proxy_records(records):
    normalized = []
    seen = set()
    for position, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        try:
            proxy_url = clean_proxy_url(str(record.get("proxy", "")))
        except ValueError:
            continue
        if proxy_url in seen:
            continue
        seen.add(proxy_url)
        try:
            record_id = int(record.get("id", position + 1))
        except (TypeError, ValueError):
            record_id = position + 1
        country = re.sub(r"[^a-z]", "", str(record.get("country", "")).lower())[:2]
        item = {"id": record_id, "country": country, "proxy": proxy_url}
        item["key"] = proxy_record_key(item)
        normalized.append(item)
    return normalized


def load_cached_proxy_records():
    try:
        payload = json.loads(MULTI_PROXY_CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return []
    records = payload.get("proxies", []) if isinstance(payload, dict) else []
    return normalize_proxy_records(records)


def fetch_proxy_records():
    separator = "&" if "?" in PROXY_API_URL else "?"
    url = PROXY_API_URL + separator + "format=json"
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "XD-route-ads/3"})
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 200:
                raise RuntimeError(f"proxy API returned HTTP {response.status}")
            raw_payload = response.read(1024 * 1024).decode("utf-8", errors="replace")
        payload = json.loads(raw_payload)
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            raise RuntimeError("proxy API returned an unsuccessful payload")
        records = normalize_proxy_records(payload.get("proxies", []))
        if not records:
            raise RuntimeError("proxy API returned no valid proxies")
        MULTI_STATE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(MULTI_STATE_DIR, 0o700)
        cache_payload = json.dumps(
            {"version": 1, "proxies": records}, sort_keys=True, separators=(",", ":")
        ) + "\n"
        write_text_if_changed(MULTI_PROXY_CACHE_PATH, cache_payload, mode=0o600)
        return records
    except Exception as exc:
        cached = load_cached_proxy_records()
        if cached:
            print(f"[!] Proxy-list fetch failed; preserving {len(cached)} cached lanes: {exc}")
            return cached
        legacy = fetch_proxy_url()
        records = normalize_proxy_records([{"id": 0, "country": "", "proxy": legacy}])
        print(f"[!] Multi-proxy API unavailable; using the legacy proxy: {exc}")
        return records


def proxy_lane_limit(proxy_count):
    override_raw = os.environ.get("XD_TUN2SOCKS_MAX_LANES", "").strip()
    if override_raw:
        try:
            override = int(override_raw)
        except ValueError:
            override = 0
        if override > 0:
            return min(proxy_count, MAX_PROXY_LANES, override)
    return min(proxy_count, MAX_PROXY_LANES)


def select_proxy_records(records):
    limit = proxy_lane_limit(len(records))
    return records[:limit]


def load_slot_map():
    try:
        payload = json.loads(MULTI_SLOT_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    result = {}
    used = set()
    for key, raw_slot in payload.items():
        try:
            slot = int(raw_slot)
        except (TypeError, ValueError):
            continue
        if 0 <= slot < MAX_PROXY_LANES and slot not in used:
            result[str(key)] = slot
            used.add(slot)
    return result


def assign_lane_slots(records):
    previous = load_slot_map()
    active_keys = {record["key"] for record in records}
    mapping = {key: slot for key, slot in previous.items() if key in active_keys}
    used = set(mapping.values())
    for record in records:
        if record["key"] in mapping:
            continue
        for slot in range(MAX_PROXY_LANES):
            if slot not in used:
                mapping[record["key"]] = slot
                used.add(slot)
                break
        else:
            raise RuntimeError("no free tun2socks lane slot")

    MULTI_STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(MULTI_STATE_DIR, 0o700)
    write_text_if_changed(
        MULTI_SLOT_PATH,
        json.dumps(mapping, sort_keys=True, separators=(",", ":")) + "\n",
        mode=0o600,
    )
    return mapping


def build_lanes(records):
    selected = select_proxy_records(records)
    mapping = assign_lane_slots(selected)
    lanes = []
    for record in selected:
        slot = mapping[record["key"]]
        lane = dict(record)
        lane.update({
            "slot": slot,
            "device": lane_device(slot),
            "address": lane_address(slot),
            "gateway": lane_gateway(slot),
            "unit": lane_unit(slot),
            "weight": 1,
        })
        lanes.append(lane)
    return sorted(lanes, key=lambda item: item["slot"])


def lane_gomaxprocs(lane_count):
    cpus = max(1, os.cpu_count() or 1)
    return max(1, min(4, cpus // max(1, lane_count)))


def lane_service_content(lane, lane_count):
    systemd_proxy = lane["proxy"].replace("%", "%%")
    label = lane["country"] or "proxy"
    return f"""[Unit]
Description=XD tun2socks lane {lane['slot']:02d} ({label})
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
Environment=GOMAXPROCS={lane_gomaxprocs(lane_count)}
ExecStartPre=/bin/bash -c 'ip link show {lane['device']} >/dev/null 2>&1 || ip tuntap add dev {lane['device']} mode tun'
ExecStartPre=/sbin/ip addr replace {lane['address']} dev {lane['device']}
ExecStartPre=/sbin/ip link set dev {lane['device']} mtu 1500 txqueuelen 8192 up
ExecStart=/opt/tun2socks --device {lane['device']} --proxy {systemd_proxy} --loglevel error
Restart=always
RestartSec=2
LimitNOFILE=1048576
TasksMax=infinity
TimeoutStopSec=5s
KillMode=mixed
SendSIGKILL=yes

[Install]
WantedBy=multi-user.target
"""


def prepare_proxy_lanes(records):
    lanes = build_lanes(records)
    changed_units = set()
    for lane in lanes:
        setup_tun2socks_interface(lane)
        unit_path = Path("/etc/systemd/system") / lane["unit"]
        if write_text_if_changed(
            unit_path, lane_service_content(lane, len(lanes)), mode=0o600
        ):
            changed_units.add(lane["unit"])

    if changed_units:
        run_cmd("systemctl daemon-reload", check=True)
    for lane in lanes:
        run_cmd(f"systemctl enable {shlex.quote(lane['unit'])}", check=True)
        action = "restart" if lane["unit"] in changed_units else "start"
        run_cmd(f"systemctl {action} {shlex.quote(lane['unit'])}", check=True)

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if all(service_is_active(lane["unit"]) for lane in lanes):
            break
        time.sleep(1)
    active = [lane for lane in lanes if service_is_active(lane["unit"])]
    if not active:
        raise RuntimeError("none of the tun2socks lanes started")
    if len(active) != len(lanes):
        print(f"[!] Only {len(active)}/{len(lanes)} tun2socks lanes started")
    return lanes, active


def cleanup_stale_lanes(active_slots):
    active_slots = {int(slot) for slot in active_slots}
    for unit_path in Path("/etc/systemd/system").glob(f"{MULTI_UNIT_PREFIX}*.service"):
        match = re.fullmatch(rf"{re.escape(MULTI_UNIT_PREFIX)}(\d+)\.service", unit_path.name)
        if not match:
            continue
        slot = int(match.group(1))
        if slot in active_slots:
            continue
        run_cmd(f"systemctl disable --now {shlex.quote(unit_path.name)}")
        try:
            unit_path.unlink()
        except OSError:
            pass
        run_cmd(f"ip link delete {shlex.quote(lane_device(slot))} 2>/dev/null || true")


def activate_multi_lane_mode(route_lanes, configured_lanes=None):
    configured_lanes = configured_lanes or route_lanes
    setup_tun2socks_routing(route_lanes)
    write_text_if_changed(
        MULTI_MARKER_PATH,
        json.dumps({
            "enabled": True,
            "configured_lanes": len(configured_lanes),
            "route_lanes": len(route_lanes),
        }, sort_keys=True) + "\n",
        mode=0o600,
    )
    run_cmd("systemctl disable --now tun2socks.service 2>/dev/null || true")
    run_cmd("systemctl reset-failed tun2socks.service 2>/dev/null || true")
    run_cmd(f"ip link delete {shlex.quote(TUN_DEV)} 2>/dev/null || true")
    cleanup_stale_lanes({lane["slot"] for lane in configured_lanes})


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
        checks = [("mangle", MARK_CHAIN, mark_rule)]
        for output_interface in (f"{MULTI_TUN_PREFIX}+", TUN_DEV):
            checks.extend([
                ("filter", FORWARD_CHAIN, [
                    "-s", subnet, "-o", output_interface, "-j", "ACCEPT",
                ]),
                ("filter", FORWARD_CHAIN, [
                    "-d", subnet, "-i", output_interface,
                    "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
                    "-j", "ACCEPT",
                ]),
                ("nat", NAT_CHAIN, [
                    "-s", subnet, "-o", output_interface, "-j", "MASQUERADE",
                ]),
            ])
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


def tun_interfaces_are_ready(lanes):
    for lane in lanes:
        result = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "dev", lane["device"]],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0 or lane["gateway"] not in result.stdout:
            return False
    return bool(lanes)


def policy_routing_is_ready(lanes):
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
    route_present = routes.returncode == 0 and all(
        f"dev {lane['device']}" in routes.stdout
        for lane in lanes
    )
    return rule_present and route_present


def ipset_is_ready():
    return subprocess.run(
        ["ipset", "list", IPSET_NAME],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
    ).returncode == 0


def apply_runtime_routing(vpn_subnets, lanes):
    for lane in lanes:
        setup_tun2socks_interface(lane)
    setup_vpn_forwarding(vpn_subnets)
    setup_iptables_fwmark(vpn_subnets)
    setup_tun2socks_routing(lanes)


def lane_signature(lanes):
    return tuple(sorted((lane["key"], lane["slot"], lane["proxy"]) for lane in lanes))


def reconcile_loop(initial_subnets, initial_lanes, initial_route_lanes):
    known_subnets = initial_subnets
    configured_lanes = initial_lanes
    route_lanes = initial_route_lanes
    known_signature = lane_signature(configured_lanes)
    last_proxy_refresh = time.monotonic()
    while True:
        time.sleep(RECONCILE_INTERVAL_SECONDS)
        try:
            if load_managed_float_states():
                sync_managed_floating_ips_from_database()
            current_subnets = discover_vpn_subnets()
            if not service_is_active("dnsmasq.service"):
                setup_ipset()
                run_cmd("systemctl restart dnsmasq.service", check=True)
            refresh_proxy_ipset()

            proxy_list_changed = False
            if time.monotonic() - last_proxy_refresh >= PROXY_REFRESH_SECONDS:
                records = fetch_proxy_records()
                refreshed_lanes, _started_lanes = prepare_proxy_lanes(records)
                refreshed_signature = lane_signature(refreshed_lanes)
                proxy_list_changed = refreshed_signature != known_signature
                configured_lanes = refreshed_lanes
                known_signature = refreshed_signature
                last_proxy_refresh = time.monotonic()
                if proxy_list_changed:
                    print(f"[+] Proxy lane configuration changed: {len(configured_lanes)} lanes")

            for lane in configured_lanes:
                if not service_is_active(lane["unit"]):
                    run_cmd(f"systemctl restart {shlex.quote(lane['unit'])}")

            active_lanes = [
                lane for lane in configured_lanes if service_is_active(lane["unit"])
            ]
            if not active_lanes:
                print("[!] No tun2socks service is active; preserving the previous route")
                continue

            route_changed = {
                lane["key"] for lane in active_lanes
            } != {lane["key"] for lane in route_lanes}
            runtime_ready = (
                ipset_is_ready()
                and tun_interfaces_are_ready(active_lanes)
                and policy_routing_is_ready(active_lanes)
                and firewall_rules_present(current_subnets)
            )
            if (
                proxy_list_changed
                or route_changed
                or current_subnets != known_subnets
                or not runtime_ready
            ):
                setup_ipset()
                apply_runtime_routing(current_subnets, active_lanes)
                activate_multi_lane_mode(active_lanes, configured_lanes)
                known_subnets = current_subnets
                route_lanes = active_lanes
                print(
                    f"[+] Runtime routing repaired: "
                    f"{len(route_lanes)}/{len(configured_lanes)} active lanes"
                )
            else:
                print(
                    f"[+] Proxy routing: {len(active_lanes)}/{len(configured_lanes)} "
                    f"active lanes"
                )
        except Exception as exc:
            print(f"[!] Routing reconciliation failed: {exc}")


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
    refresh_proxy_ipset()
    sync_managed_floating_ips_from_database()
    proxy_records = fetch_proxy_records()
    configured_lanes, started_lanes = prepare_proxy_lanes(proxy_records)
    route_lanes = started_lanes
    vpn_subnets = discover_vpn_subnets()
    apply_runtime_routing(vpn_subnets, route_lanes)
    activate_multi_lane_mode(route_lanes, configured_lanes)

    if use_dnstt:
        setup_iptables_dnstt(5300)
    print(
        f"\n[+] Selective multi-proxy routing is active with "
        f"{len(route_lanes)}/{len(configured_lanes)} active lanes."
    )
    reconcile_loop(vpn_subnets, configured_lanes, route_lanes)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Stopped by user.")
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)
