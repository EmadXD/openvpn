#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
increase_fd_limits_sudo_friendly.py

همان اسکریپت افزایش محدودیت‌ها، اما سازگار با اجرا توسط کاربر غیر-root (مثلاً ubuntu).
اگر اسکریپت با root اجرا نشود، از sudo برای دستورات نیازمند روت استفاده می‌کند.
"""

import os
import time
import subprocess
from datetime import datetime
import tempfile
import shutil

# ---------- تنظیمات قابل تغییر ----------
FS_FILE_MAX = 2_097_152      # پیشنهاد: 2 میلیون
USER_NOFILE_SOFT = 262144
USER_NOFILE_HARD = 524288
SYSTEMD_LIMIT_NOFILE = 524288
IP_LOCAL_PORT_RANGE = "1024 65535"
# -----------------------------------------

def run(cmd, check=False):
    """اجرا کننده دستورات شل. خروجی stdout را برمی‌گرداند."""
    try:
        completed = subprocess.run(cmd, shell=True, text=True,
                                   capture_output=True, check=check)
        if completed.returncode != 0 and completed.stderr:
            print(f"[!] cmd: {cmd}\n    stderr: {completed.stderr.strip()}")
        return completed.stdout.strip()
    except Exception as e:
        print(f"[!] Exception running cmd '{cmd}': {e}")
        return ""

def is_root():
    return os.geteuid() == 0

# SUDO متغیری که اگر کاربر روت نبود 'sudo' خواهد داشت
SUDO = "" if is_root() else "sudo"

def backup_file(path):
    """بکاپ با mv/cp با sudo اگر لازم باشد"""
    if not os.path.exists(path):
        return None
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    bak = f"{path}.bak.{stamp}"
    try:
        if is_root():
            shutil.copy2(path, bak)
        else:
            # use sudo cp -a
            run(f"{SUDO} cp -a {shell_escape(path)} {shell_escape(bak)}", check=True)
        print(f"[+] Backup created: {bak}")
        return bak
    except Exception as e:
        print(f"[!] Could not backup {path}: {e}")
        return None

def shell_escape(s: str) -> str:
    """فرمت ساده برای escape کردن مسیرها در دستور شل (basic)"""
    return "'" + s.replace("'", "'\"'\"'") + "'"

def write_temp_and_move(dest_path: str, content: str, mode=0o644):
    """محتوا را در فایل temp بنویس و سپس با sudo mv به مقصد منتقل کن."""
    try:
        fd, tmp = tempfile.mkstemp(prefix="increase_fd_", text=True)
        os.close(fd)
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(content.rstrip() + "\n")
        os.chmod(tmp, mode)
        if is_root():
            shutil.move(tmp, dest_path)
        else:
            # move with sudo: use mv tmp dest (tmp is readable by current user)
            run(f"{SUDO} mv {shell_escape(tmp)} {shell_escape(dest_path)}", check=True)
            run(f"{SUDO} chown root:root {shell_escape(dest_path)} || true")
            run(f"{SUDO} chmod {oct(mode)[2:]} {shell_escape(dest_path)} || true")
        print(f"[+] Wrote {dest_path}")
    except Exception as e:
        print(f"[!] Could not write {dest_path}: {e}")
        # cleanup
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

def append_if_missing(path: str, content: str):
    """
    اگر محتوا در فایل نبود، محتوای چندخطی را به انتهای فایل اضافه می‌کند.
    در صورت عدم دسترسی مستقیم از sudo tee استفاده می‌شود.
    """
    try:
        existing = ""
        if os.path.exists(path):
            if is_root():
                with open(path, "r", encoding="utf-8") as f:
                    existing = f.read()
            else:
                existing = run(f"{SUDO} cat {shell_escape(path)} || true")
        if content.strip() in existing:
            print(f"[~] Content already present in {path}")
            return
        if is_root():
            with open(path, "a", encoding="utf-8") as f:
                f.write("\n" + content.rstrip() + "\n")
            print(f"[+] Appended content to {path}")
        else:
            # use sudo tee -a
            safe = content.replace("'", "'\"'\"'")
            run(f"printf %s '{safe}\\n' | {SUDO} tee -a {shell_escape(path)} > /dev/null", check=True)
            print(f"[+] Appended content to {path} (via sudo)")
    except Exception as e:
        print(f"[!] Error appending to {path}: {e}")

def replace_or_add_sysctl(entries: dict):
    """در /etc/sysctl.conf مقدارها را جایگزین یا اضافه می‌کند."""
    path = "/etc/sysctl.conf"
    backup_file(path)
    try:
        existing = ""
        if os.path.exists(path):
            if is_root():
                with open(path, "r", encoding="utf-8") as f:
                    existing = f.read()
            else:
                existing = run(f"{SUDO} cat {shell_escape(path)} || true")
        # پارس ساده خط به خط
        lines = existing.splitlines()
        mapping = entries.copy()
        out_lines = []
        for ln in lines:
            stripped = ln.strip()
            if not stripped or stripped.startswith("#"):
                out_lines.append(ln)
                continue
            key = stripped.split("=")[0].strip()
            if key in mapping:
                out_lines.append(f"{key} = {mapping[key]}")
                del mapping[key]
            else:
                out_lines.append(ln)
        if mapping:
            out_lines.append("\n# Added by increase_fd_limits.py")
            for k, v in mapping.items():
                out_lines.append(f"{k} = {v}")
        new_content = "\n".join(out_lines) + "\n"
        write_temp_and_move(path, new_content, mode=0o644)
        # apply
        run(f"{SUDO} sysctl -p || true")
        print(f"[+] /etc/sysctl.conf updated")
    except Exception as e:
        print(f"[!] Failed to update /etc/sysctl.conf: {e}")

def ensure_pam_limits():
    """اطمینان از فعال بودن pam_limits در common-session files"""
    pam_line = "session required pam_limits.so"
    files = ["/etc/pam.d/common-session", "/etc/pam.d/common-session-noninteractive"]
    for p in files:
        backup_file(p)
        # read
        content = ""
        if os.path.exists(p):
            content = run(f"{SUDO} cat {shell_escape(p)} || true") if not is_root() else open(p, "r", encoding="utf-8").read()
        if pam_line in content:
            print(f"[~] pam_limits present in {p}")
        else:
            append_if_missing(p, pam_line)

def update_limits_conf(soft: int, hard: int):
    """افزودن تنظیمات nofile در /etc/security/limits.conf برای root و همه‌ی کاربران"""
    path = "/etc/security/limits.conf"
    backup_file(path)
    entry = f"""
# Added by increase_fd_limits.py
* soft nofile {soft}
* hard nofile {hard}
root soft nofile {soft}
root hard nofile {hard}
ubuntu soft nofile {soft}
ubuntu hard nofile {hard}
"""
    append_if_missing(path, entry)

def write_systemd_limits(limit: int):
    """نوشتن DefaultLimitNOFILE و DefaultLimitNPROC در system.conf و user.conf"""
    sys_conf = "/etc/systemd/system.conf"
    user_conf = "/etc/systemd/user.conf"
    backup_file(sys_conf)
    backup_file(user_conf)
    conf_block = f"""
# Added by increase_fd_limits.py
DefaultLimitNOFILE={limit}
DefaultLimitNPROC={limit}
"""
    # خواندن و جایگزینی یا اضافه کردن
    for p in (sys_conf, user_conf):
        existing = ""
        if os.path.exists(p):
            existing = run(f"{SUDO} cat {shell_escape(p)} || true") if not is_root() else open(p, "r", encoding="utf-8").read()
        if "DefaultLimitNOFILE" in existing or "DefaultLimitNPROC" in existing:
            # جایگزینی خطوط موجود
            import re
            new = re.sub(r"(?m)^DefaultLimitNOFILE=.*$", f"DefaultLimitNOFILE={limit}", existing)
            new = re.sub(r"(?m)^DefaultLimitNPROC=.*$", f"DefaultLimitNPROC={limit}", new)
            write_temp_and_move(p, new, mode=0o644)
            print(f"[~] Updated DefaultLimit* in {p}")
        else:
            # اضافه کردن
            append_if_missing(p, conf_block)
            print(f"[+] Appended DefaultLimit* to {p}")
    run(f"{SUDO} systemctl daemon-reload || true")

def create_profile_ulimit(soft: int):
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
    write_temp_and_move(path, content, mode=0o644)

def show_current_limits():
    print("\n--- Current kernel and limits ---")
    print(run(f"{SUDO} sysctl fs.file-max || true"))
    print(run(f"{SUDO} bash -lc 'ulimit -n' || true"))
    print(run(f"{SUDO} grep -E '^DefaultLimitNOFILE|^DefaultLimitNPROC' /etc/systemd/system.conf || true"))
    print(run(f"{SUDO} tail -n 20 /etc/security/limits.conf || true"))

def main():
    print(f"[*] Running as: {run('whoami')}, using SUDO='{SUDO or '(none)'}'")
    # نوتیفای کاربر اگر root نیست اما اسکریپت با sudo توزیع خواهد شد
    if not is_root():
        print("[!] Note: not root. The script will use sudo for operations that need root privileges.")
        # optional check for sudo available
        if run("which sudo || true") == "":
            print("[!] 'sudo' not found — for full functionality run this script as root.")
    # اعمال تنظیمات
    sysctl_entries = {
        "fs.file-max": str(FS_FILE_MAX),
        "net.core.somaxconn": "65535",
        "net.ipv4.ip_local_port_range": IP_LOCAL_PORT_RANGE,
        "net.ipv4.tcp_max_syn_backlog": "8192",
        "net.ipv4.tcp_tw_reuse": "1",
    }
    replace_or_add_sysctl(sysctl_entries)
    ensure_pam_limits()
    update_limits_conf(USER_NOFILE_SOFT, USER_NOFILE_HARD)
    write_systemd_limits(SYSTEMD_LIMIT_NOFILE)
    create_profile_ulimit(USER_NOFILE_SOFT)
    run(f"{SUDO} sysctl -p || true")
    show_current_limits()
    print("\n[!] Done. Recommended: reboot the system to apply everything (sudo reboot).")

if __name__ == "__main__":
    main()
