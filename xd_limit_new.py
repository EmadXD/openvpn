#!/usr/bin/env python3
import os
import subprocess
import shutil
import time
from datetime import datetime

SUDO = "" if os.geteuid() == 0 else "sudo"

# ---------- تنظیمات ----------
FS_FILE_MAX = 2_097_152
DEFAULT_LIMIT_NOFILE = 1_048_576
DEFAULT_LIMIT_NPROC = 262_144
USER_NOFILE_SOFT = 262_144
USER_NOFILE_HARD = 524_288
IP_LOCAL_PORT_RANGE = "1024 65535"
POSSIBLE_SERVICES = ["shadowsocks-libev.service", "ss-server.service"]


# -----------------------------

def run(cmd):
    print("[*]", cmd)
    return subprocess.run(cmd, shell=True, text=True,
                          capture_output=True).stdout.strip()


def backup(path):
    if not os.path.exists(path):
        return
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    bak = f"{path}.bak.{stamp}"
    if os.geteuid() == 0:
        shutil.copy2(path, bak)
    else:
        run(f"{SUDO} cp -a {path} {bak}")
    print(f"[+] backup -> {bak}")


def write_temp_and_move(dest, content, mode=0o644):
    tmp = "/tmp/tmpfile_for_raise_limits"
    with open(tmp, "w") as f:
        f.write(content.rstrip() + "\n")
    os.chmod(tmp, mode)
    if os.geteuid() == 0:
        shutil.move(tmp, dest)
    else:
        run(f"{SUDO} mv {tmp} {dest}")
        run(f"{SUDO} chown root:root {dest} || true")
    print(f"[+] wrote {dest}")


def set_runtime_sysctl():
    entries = {
        "fs.file-max": str(FS_FILE_MAX),
        "net.core.somaxconn": "65535",
        "net.ipv4.ip_local_port_range": IP_LOCAL_PORT_RANGE,
        "net.ipv4.tcp_max_syn_backlog": "8192",
        "net.ipv4.tcp_tw_reuse": "1",
    }
    for k, v in entries.items():
        run(f"{SUDO} sysctl -w {k}='{v}'")
    # ذخیره در sysctl.conf
    path = "/etc/sysctl.conf"
    backup(path)
    try:
        with open(path, "r") as f:
            content = f.read()
    except:
        content = ""
    new_lines = [line for line in content.splitlines() if not any(line.startswith(k) for k in entries)]
    new_lines.append("\n# Added by raise_limits_persist.py")
    for k, v in entries.items():
        new_lines.append(f"{k} = {v}")
    write_temp_and_move(path, "\n".join(new_lines))


def ensure_pam_limits():
    pam_line = "session required pam_limits.so"
    for p in ["/etc/pam.d/common-session", "/etc/pam.d/common-session-noninteractive"]:
        if os.path.exists(p):
            with open(p, "r") as f:
                c = f.read()
            if pam_line not in c:
                with open(p, "a") as f:
                    f.write("\n" + pam_line + "\n")
                print(f"[+] appended pam_limits to {p}")


def update_limits_conf():
    path = "/etc/security/limits.conf"
    backup(path)
    entry = f"""
# Added by raise_limits_persist.py
* soft nofile {USER_NOFILE_SOFT}
* hard nofile {USER_NOFILE_HARD}
root soft nofile {USER_NOFILE_SOFT}
root hard nofile {USER_NOFILE_HARD}
ubuntu soft nofile {USER_NOFILE_SOFT}
ubuntu hard nofile {USER_NOFILE_HARD}
"""
    with open(path, "a+") as f:
        f.seek(0)
        content = f.read()
        if str(USER_NOFILE_SOFT) not in content or str(USER_NOFILE_HARD) not in content:
            f.write("\n" + entry + "\n")
            print(f"[+] appended limits.conf entries")


def write_systemd_defaults():
    for conf in ("/etc/systemd/system.conf", "/etc/systemd/user.conf"):
        backup(conf)
        try:
            with open(conf, "r") as f:
                content = f.read()
        except:
            content = ""
        lines = [line for line in content.splitlines() if
                 not line.startswith("DefaultLimitNOFILE") and not line.startswith("DefaultLimitNPROC")]
        lines.append(f"\n# Added by raise_limits_persist.py")
        lines.append(f"DefaultLimitNOFILE={DEFAULT_LIMIT_NOFILE}")
        lines.append(f"DefaultLimitNPROC={DEFAULT_LIMIT_NPROC}")
        write_temp_and_move(conf, "\n".join(lines))


def apply_systemd_override_if_service_exists():
    out = run("systemctl list-units --type=service --all --no-legend")
    for svc in POSSIBLE_SERVICES:
        if svc in out:
            ddir = f"/etc/systemd/system/{svc}.d"
            if not os.path.exists(ddir):
                if os.geteuid() == 0:
                    os.makedirs(ddir, exist_ok=True)
                else:
                    run(f"{SUDO} mkdir -p {ddir}")
            override = f"""# override created by raise_limits_persist.py
[Service]
LimitNOFILE={DEFAULT_LIMIT_NOFILE}
LimitNPROC={DEFAULT_LIMIT_NPROC}
"""
            tmp = "/tmp/raise_limits_override.conf"
            with open(tmp, "w") as f:
                f.write(override)
            run(f"{SUDO} cp {tmp} {ddir}/override.conf")
            run(f"{SUDO} systemctl daemon-reexec")
            # restart service if active
            active = run(f"systemctl is-active {svc} || true")
            if active.strip() == "active":
                run(f"{SUDO} systemctl restart {svc}")
                print(f"[+] systemd override applied and restarted {svc}")


def apply_prlimit_to_ss():
    pid_out = run("pidof ss-server || true")
    if not pid_out:
        print("[~] no ss-server process found for prlimit")
        return
    pids = pid_out.split()
    for p in pids:
        run(f"{SUDO} prlimit --pid {p} --nofile={DEFAULT_LIMIT_NOFILE}:{DEFAULT_LIMIT_NOFILE} --nproc={DEFAULT_LIMIT_NPROC}:{DEFAULT_LIMIT_NPROC}")
        print(f"[+] prlimit applied to pid {p}")


def main():
    set_runtime_sysctl()
    ensure_pam_limits()
    update_limits_conf()
    write_systemd_defaults()
    apply_systemd_override_if_service_exists()
    apply_prlimit_to_ss()
    print("\n✅ All limits raised (persistent, no reboot needed).")


if __name__ == "__main__":
    main()
    time.sleep(900000)
