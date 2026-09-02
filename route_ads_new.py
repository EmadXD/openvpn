#!/usr/bin/env python3
import glob
import ipaddress
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

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
TUN2SOCKS_BINARY_URL = "https://aparatvpn.com/tun2socks"
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
    run_cmd(
        f"ipset create {shlex.quote(IPSET_NAME)} hash:ip "
        "family inet hashsize 4096 maxelem 1048576 -exist",
        check=True,
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
