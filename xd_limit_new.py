#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
increase_fd_limits.py
اسکریپتی برای افزایش محدودیت open files و پارامترهای مرتبط systemd/پروفایل
حذف شده: بخش‌های مربوط به redsocks

نکات:
- با دسترسی root اجرا شود (sudo).
- قبل از اعمال تغییرات بکاپ می‌سازد.
- پس از اجرا توصیه به reboot دارد تا همه چیز به درستی اعمال شود.
"""

import os
import time
import subprocess
from datetime import datetime

# ---------- تنظیمات قابل تغییر ----------
# مقدار پیشنهادی برای بیشینه فایل‌های باز در کرنل
FS_FILE_MAX = 2_097_152  # = 2M
# مقدار nofile که به users اختصاص داده می‌شود
USER_NOFILE_SOFT = 262144
USER_NOFILE_HARD = 524288
# systemd limit
SYSTEMD_LIMIT_NOFILE = 524288
# محدوده پورت‌های لوکال پیشنهادی (اختیاری)
IP_LOCAL_PORT_RANGE = "1024 65535"
# -----------------------------------------

def run(cmd, check=False):
    try:
        completed = subprocess.run(cmd, shell=True, text=True,
                                   capture_output=True, check=check)
        if completed.returncode != 0 and completed.stderr:
            print(f"[!] cmd: {cmd}\n    stderr: {completed.stderr.strip()}")
        return completed.stdout.strip()
    except Exception as e:
        print(f"[!] Exception running cmd '{cmd}': {e}")
        return ""

def backup_file(path):
    if not os.path.exists(path):
        return None
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    bak = f"{path}.bak.{stamp}"
    try:
        run(f"cp -a {path} {bak}", check=True)
        print(f"[+] Backup created: {bak}")
        return bak
    except Exception as e:
        print(f"[!] Could not backup {path}: {e}")
        return None

def append_if_missing(path, content):
    """Append content (multi-line string) to file if those lines are not present."""
    try:
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write(content.rstrip() + "\n")
            print(f"[+] Created {path}")
            return

        with open(path, "r+", encoding="utf-8") as f:
            existing = f.read()
            if content.strip() in existing:
                print(f"[~] Content already present in {path}")
                return
            f.write("\n" + content.rstrip() + "\n")
            print(f"[+] Appended content to {path}")
    except Exception as e:
        print(f"[!] Error writing to {path}: {e}")

def replace_or_add_sysctl(entries: dict):
    """در /etc/sysctl.conf مقدارها را جایگزین یا اضافه می‌کند."""
    path = "/etc/sysctl.conf"
    backup_file(path)
    try:
        lines = []
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        mapping = entries.copy()
        out_lines = []
        for ln in lines:
            stripped = ln.strip()
            if not stripped or stripped.startswith("#"):
                out_lines.append(ln)
                continue
            key = stripped.split("=")[0].strip()
            if key in mapping:
                # replace
                out_lines.append(f"{key} = {mapping[key]}\n")
                del mapping[key]
            else:
                out_lines.append(ln)
        # append remaining mapping
        if mapping:
            out_lines.append("\n# Added by increase_fd_limits.py\n")
            for k, v in mapping.items():
                out_lines.append(f"{k} = {v}\n")
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(out_lines)
        print(f"[+] /etc/sysctl.conf updated")
        run("sysctl -p")
    except Exception as e:
        print(f"[!] Failed to update /etc/sysctl.conf: {e}")

def ensure_pam_limits():
    """اطمینان از فعال بودن pam_limits در common-session files"""
    pam_line = "session required pam_limits.so"
    files = ["/etc/pam.d/common-session", "/etc/pam.d/common-session-noninteractive"]
    for p in files:
        backup_file(p)
        if os.path.exists(p):
            with open(p, "r+", encoding="utf-8") as f:
                content = f.read()
                if pam_line in content:
                    print(f"[~] pam_limits present in {p}")
                else:
                    f.write("\n" + pam_line + "\n")
                    print(f"[+] Added pam_limits to {p}")
        else:
            try:
                with open(p, "w", encoding="utf-8") as f:
                    f.write(pam_line + "\n")
                print(f"[+] Created {p} with pam_limits")
            except Exception as e:
                print(f"[!] Could not create {p}: {e}")

def update_limits_conf(soft, hard):
    """افزودن تنظیمات nofile در /etc/security/limits.conf برای root و همه‌ی کاربران"""
    path = "/etc/security/limits.conf"
    backup_file(path)
    entry = f"""
# Added by increase_fd_limits.py
* soft nofile {soft}
* hard nofile {hard}
root soft nofile {soft}
root hard nofile {hard}
"""
    append_if_missing(path, entry)

def write_systemd_limits(limit):
    """نوشتن DefaultLimitNOFILE و LimitNOFILE در systemd system.conf و user.conf"""
    sys_conf = "/etc/systemd/system.conf"
    user_conf = "/etc/systemd/user.conf"
    backup_file(sys_conf)
    backup_file(user_conf)
    conf_block = f"""
# Added by increase_fd_limits.py
DefaultLimitNOFILE={limit}
DefaultLimitNPROC={limit}
# Also set default limits for services
"""
    # write or replace DefaultLimitNOFILE line
    for p in (sys_conf, user_conf):
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                content = f.read()
            if "DefaultLimitNOFILE" in content:
                # replace existing line(s)
                import re
                content = re.sub(r"(?m)^DefaultLimitNOFILE=.*$", f"DefaultLimitNOFILE={limit}", content)
                content = re.sub(r"(?m)^DefaultLimitNPROC=.*$", f"DefaultLimitNPROC={limit}", content)
                with open(p, "w", encoding="utf-8") as f:
                    f.write(content)
                print(f"[~] Updated DefaultLimit* in {p}")
            else:
                with open(p, "a", encoding="utf-8") as f:
                    f.write("\n" + conf_block)
                print(f"[+] Appended DefaultLimit* to {p}")
        else:
            try:
                with open(p, "w", encoding="utf-8") as f:
                    f.write(conf_block)
                print(f"[+] Created {p} with DefaultLimit* settings")
            except Exception as e:
                print(f"[!] Could not write {p}: {e}")
    # reload systemd daemon to pick up changes for services
    run("systemctl daemon-reload")

def create_profile_ulimit(soft):
    """ایجاد /etc/profile.d/ulimit.sh برای افزایش ulimit در شل‌ها"""
    path = "/etc/profile.d/ulimit.sh"
    content = f"""# set file descriptor limit for interactive and non-interactive shells
if [ "$(id -u)" -eq 0 ]; then
    ulimit -n {soft} || true
else
    ulimit -n {soft} || true
fi
"""
    backup_file(path)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(path, 0o644)
        print(f"[+] Wrote {path}")
    except Exception as e:
        print(f"[!] Could not write {path}: {e}")

def show_current_limits():
    print("\n--- Current kernel and limits ---")
    print("fs.file-max:", run("sysctl fs.file-max"))
    print("ulimit -n (shell):", run("bash -lc 'ulimit -n'"))
    print("systemd DefaultLimitNOFILE (system.conf):")
    print(run("grep -E '^DefaultLimitNOFILE|^DefaultLimitNPROC' /etc/systemd/system.conf || true"))
    print("/etc/security/limits.conf preview:")
    print(run("tail -n 20 /etc/security/limits.conf || true"))

def main():
    if os.geteuid() != 0:
        print("[!] This script must be run as root (use sudo). Exiting.")
        return

    print("[*] Backing up and applying system-wide sysctl settings...")
    sysctl_entries = {
        "fs.file-max": str(FS_FILE_MAX),
        "net.core.somaxconn": "65535",
        "net.ipv4.ip_local_port_range": IP_LOCAL_PORT_RANGE,
        "net.ipv4.tcp_max_syn_backlog": "8192",
        "net.ipv4.tcp_tw_reuse": "1",
    }
    replace_or_add_sysctl(sysctl_entries)

    print("[*] Ensuring PAM limits...")
    ensure_pam_limits()

    print("[*] Updating /etc/security/limits.conf ...")
    update_limits_conf(USER_NOFILE_SOFT, USER_NOFILE_HARD)

    print("[*] Writing systemd-wide DefaultLimit and reloading daemon...")
    write_systemd_limits(SYSTEMD_LIMIT_NOFILE)

    print("[*] Creating /etc/profile.d/ulimit.sh ...")
    create_profile_ulimit(USER_NOFILE_SOFT)

    print("[*] Syncing and showing current values...")
    run("sysctl -p || true")
    show_current_limits()

    print("\n[!] Done. For full effect please reboot the machine:")
    print("    sudo reboot")
    print("[!] If you run services under systemd, consider restarting them after reboot or if needed run 'systemctl daemon-reload' and restart specific services.")

if __name__ == "__main__":
    main()
