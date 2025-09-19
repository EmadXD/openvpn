#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
raise_limits_persist.py
یک‌بار اجرا کن و بمونه — همه‌ی لیمیت‌های مهم را تا مقادیر بالا تنظیم می‌کند،
بدون نیاز به ریبوت (prlimit روی پروسس‌های زنده) و تغییرات پایدار برای بوت‌های بعدی.
"""

import os
import subprocess
import tempfile
import shutil
from datetime import datetime

# ---------- تنظیمات (در صورت نیاز تغییر بده) ----------
FS_FILE_MAX = 2_097_152        # fs.file-max (کرنل)
DEFAULT_LIMIT_NOFILE = 1_048_576   # DefaultLimitNOFILE برای systemd و limits.conf
DEFAULT_LIMIT_NPROC = 262144       # DefaultLimitNPROC برای systemd
USER_NOFILE_SOFT = 262144
USER_NOFILE_HARD = 524288
IP_LOCAL_PORT_RANGE = "1024 65535"
# نام سرویس‌های احتمالی shadowsocks
POSSIBLE_SERVICES = ["shadowsocks-libev.service", "ss-server.service", "shadowsocks.service"]
# -------------------------------------------------------

SUDO = "" if os.geteuid() == 0 else "sudo"

def run(cmd, check=False):
    print("[*] " + cmd)
    return subprocess.run(cmd, shell=True, text=True,
                          capture_output=not check, check=check).stdout.strip()

def shell_escape(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"

def backup(path):
    if not os.path.exists(path):
        return None
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    bak = f"{path}.bak.{stamp}"
    if os.geteuid() == 0:
        shutil.copy2(path, bak)
    else:
        run(f"{SUDO} cp -a {shell_escape(path)} {shell_escape(bak)}")
    print(f"[+] backup -> {bak}")
    return bak

def write_temp_and_move(dest, content, mode=0o644):
    fd, tmp = tempfile.mkstemp(prefix="raise_limits_", text=True)
    os.close(fd)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content.rstrip() + "\n")
    os.chmod(tmp, mode)
    if os.geteuid() == 0:
        shutil.move(tmp, dest)
    else:
        run(f"{SUDO} mv {shell_escape(tmp)} {shell_escape(dest)}")
        run(f"{SUDO} chown root:root {shell_escape(dest)} || true")
    print(f"[+] wrote {dest}")

def set_runtime_sysctl(entries: dict):
    for k, v in entries.items():
        run(f"{SUDO} sysctl -w {k}='{v}'")
    print("[+] sysctl (runtime) set")

def persist_sysctl(entries: dict):
    path = "/etc/sysctl.conf"
    backup(path)
    # read existing
    existing = ""
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            existing = f.read()
    # ensure keys replaced or appended
    lines = existing.splitlines()
    mapping = entries.copy()
    out = []
    for ln in lines:
        stripped = ln.strip()
        if not stripped or stripped.startswith("#"):
            out.append(ln)
            continue
        key = stripped.split("=")[0].strip()
        if key in mapping:
            out.append(f"{key} = {mapping[key]}")
            del mapping[key]
        else:
            out.append(ln)
    if mapping:
        out.append("\n# Added by raise_limits_persist.py")
        for k, v in mapping.items():
            out.append(f"{k} = {v}")
    new = "\n".join(out) + "\n"
    write_temp_and_move(path, new)

def ensure_pam_limits():
    pam_line = "session required pam_limits.so"
    for p in ["/etc/pam.d/common-session", "/etc/pam.d/common-session-noninteractive"]:
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                c = f.read()
            if pam_line not in c:
                # append
                if os.geteuid() == 0:
                    with open(p, "a", encoding="utf-8") as f:
                        f.write("\n" + pam_line + "\n")
                else:
                    run(f"printf %s {shell_escape(pam_line+'\\n')} | {SUDO} tee -a {shell_escape(p)} > /dev/null")
                print(f"[+] appended pam_limits to {p}")
        else:
            write_temp_and_move(p, pam_line)

def update_limits_conf(soft, hard):
    path = "/etc/security/limits.conf"
    backup(path)
    # ensure entries exist (append if not)
    entry = f"""
# Added by raise_limits_persist.py
* soft nofile {soft}
* hard nofile {hard}
root soft nofile {soft}
root hard nofile {hard}
ubuntu soft nofile {soft}
ubuntu hard nofile {hard}
"""
    # append if not present
    with open(path, "a+", encoding="utf-8") as f:
        f.seek(0)
        content = f.read()
        if str(soft) in content and str(hard) in content:
            print("[~] limits.conf looks like already updated")
        else:
            if os.geteuid() == 0:
                f.write("\n" + entry + "\n")
            else:
                run(f"printf %s {shell_escape(entry+'\\n')} | {SUDO} tee -a {shell_escape(path)} > /dev/null")
            print(f"[+] appended limits.conf entries")

def write_systemd_defaults(limit_no_file, limit_nproc):
    for conf in ("/etc/systemd/system.conf", "/etc/systemd/user.conf"):
        backup(conf)
        # read existing
        existing = ""
        if os.path.exists(conf):
            with open(conf, "r", encoding="utf-8") as f:
                existing = f.read()
        # replace or append
        import re
        new = existing
        if re.search(r"(?m)^DefaultLimitNOFILE=", existing):
            new = re.sub(r"(?m)^DefaultLimitNOFILE=.*$", f"DefaultLimitNOFILE={limit_no_file}", new)
        else:
            new += f"\n# Added by raise_limits_persist.py\nDefaultLimitNOFILE={limit_no_file}\n"
        if re.search(r"(?m)^DefaultLimitNPROC=", existing):
            new = re.sub(r"(?m)^DefaultLimitNPROC=.*$", f"DefaultLimitNPROC={limit_nproc}", new)
        else:
            new += f"DefaultLimitNPROC={limit_nproc}\n"
        write_temp_and_move(conf, new)

def apply_systemd_override_for(service, limit_no_file, limit_nproc):
    ddir = f"/etc/systemd/system/{service}.d"
    if not os.path.exists(ddir):
        if os.geteuid() == 0:
            os.makedirs(ddir, exist_ok=True)
        else:
            run(f"{SUDO} mkdir -p {shell_escape(ddir)}")
    override = f"""# override created by raise_limits_persist.py
[Service]
LimitNOFILE={limit_no_file}
LimitNPROC={limit_nproc}
"""
    tmp = "/tmp/raise_limits_override.conf"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(override)
    run(f"{SUDO} cp {shell_escape(tmp)} {shell_escape(ddir+'/override.conf')}")
    run(f"{SUDO} systemctl daemon-reload")
    # restart service if exists and active (to pick new limits)
    status = run(f"systemctl is-enabled {service} || true")
    active = run(f"systemctl is-active {service} || true")
    if active.strip() == "active" or status.strip() in ("enabled", "static"):
        run(f"{SUDO} systemctl restart {service}")
        print(f"[+] restarted {service}")

def detect_service():
    out = run("systemctl list-units --type=service --all --no-legend")
    for s in POSSIBLE_SERVICES:
        if s in out:
            return s
    # fallback: if ss-server running, try to find its unit
    pid = run("pidof ss-server || true")
    if pid:
        # try to find unit via cgroup
        unit = run(f"cat /proc/{pid}/cgroup 2>/dev/null | grep name=systemd -m1 || true")
        # not robust; fallback to ss-server.service
        return "ss-server.service"
    return None

def apply_prlimit_to_running_ss(limit_no_file, limit_nproc):
    pid_out = run("pidof ss-server || true")
    if not pid_out:
        print("[~] no ss-server process found for prlimit")
        return
    pids = pid_out.split()
    for p in pids:
        run(f"{SUDO} prlimit --pid {p} --nofile={limit_no_file}:{limit_no_file} --nproc={limit_nproc}:{limit_nproc}")
        print(f"[+] prlimit applied to pid {p}")

def create_systemd_helper_unit(script_path):
    """یک unit ایجاد می‌کنیم که هنگام بوت اجرا شده و RemainAfterExit=yes باشد.
       کاربر فقط یکبار این unit را enable کند تا در بوت‌های بعدی اجرا شود."""
    unit_path = "/etc/systemd/system/raise-limits.service"
    unit_content = f"""[Unit]
Description=Raise file descriptor and proc limits (persistent)
After=network.target

[Service]
Type=oneshot
ExecStart={script_path}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
    write_temp_and_move(unit_path, unit_content, mode=0o644)
    run(f"{SUDO} systemctl daemon-reload")
    print(f"[+] systemd unit created: {unit_path}")
    # enable but do not start automatically here unless user wants
    run(f"{SUDO} systemctl enable raise-limits.service || true")

def show_status():
    print("\n--- verify ---")
    run("sysctl fs.file-max")
    run("sysctl net.ipv4.ip_local_port_range")
    pid = run("pidof ss-server || true")
    if pid:
        run(f"cat /proc/{pid}/limits | grep 'Max open files' || true")
    run("systemctl status raise-limits.service --no-pager || true")

def main():
    print("[*] Starting raise_limits_persist")

    sysctl_entries = {
        "fs.file-max": str(FS_FILE_MAX),
        "net.core.somaxconn": "65535",
        "net.ipv4.ip_local_port_range": IP_LOCAL_PORT_RANGE,
        "net.ipv4.tcp_max_syn_backlog": "8192",
        "net.ipv4.tcp_tw_reuse": "1",
    }
    set_runtime_sysctl(sysctl_entries)
    persist_sysctl(sysctl_entries)

    ensure_pam_limits()
    update_limits_conf(USER_NOFILE_SOFT, USER_NOFILE_HARD)

    write_systemd_defaults(DEFAULT_LIMIT_NOFILE, DEFAULT_LIMIT_NPROC)

    svc = detect_service()
    if svc:
        apply_systemd_override_for(svc, DEFAULT_LIMIT_NOFILE, DEFAULT_LIMIT_NPROC)
    else:
        print("[~] no known shadowsocks service detected; override not applied.")

    apply_prlimit_to_running_ss(DEFAULT_LIMIT_NOFILE, DEFAULT_LIMIT_NPROC)

    # create helper unit so at future boots this script runs early (enable once)
    script_dest = "/usr/local/sbin/raise_limits_persist.py"
    if os.path.abspath(__file__) != script_dest:
        # copy itself to /usr/local/sbin
        if os.geteuid() == 0:
            shutil.copy2(__file__, script_dest)
            os.chmod(script_dest, 0o755)
        else:
            run(f"{SUDO} cp {shell_escape(__file__)} {shell_escape(script_dest)}")
            run(f"{SUDO} chmod 755 {shell_escape(script_dest)}")
    create_systemd_helper_unit(script_dest)

    show_status()
    print("\n[*] Done. No reboot required. For services launched by systemd this also set persistent overrides.")

if __name__ == "__main__":
    main()
