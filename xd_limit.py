import subprocess
import os
import sys
import time


def run_command(command, check=True):
    """Run a shell command and handle errors."""
    try:
        result = subprocess.run(command, shell=True, check=check, text=True, capture_output=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running command '{command}': {e.stderr}")
        sys.exit(1)


def append_to_file(file_path, content):
    """Append content to a file if it doesn't already exist."""
    with open(file_path, 'a+') as f:
        f.seek(0)
        if content not in f.read():
            f.write(content + '\n')


def get_default_interface():
    """Get the default network interface."""
    return run_command("ip route | grep default | awk '{print $5}'")


def main():
    # Ensure script is run as root
    if os.geteuid() != 0:
        print("This script must be run as root (use sudo).")
        sys.exit(1)

    # Step 1: Set system-wide file descriptor limits in /etc/sysctl.conf
    print("Configuring system-wide file descriptor limits in /etc/sysctl.conf...")
    sysctl_content = """
fs.file-max = 2097152
net.core.somaxconn = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_tw_reuse = 1
"""
    append_to_file('/etc/sysctl.conf', sysctl_content.strip())

    # Apply sysctl changes
    run_command('sysctl -p')

    # Step 2: Configure limits.conf for root and ubuntu users
    print("Configuring /etc/security/limits.conf for root and ubuntu...")
    limits_content = """
root soft nofile 1048576
root hard nofile 1048576
ubuntu soft nofile 1048576
ubuntu hard nofile 1048576
"""
    append_to_file('/etc/security/limits.conf', limits_content.strip())

    # Step 3: Ensure pam_limits.so is enabled
    print("Ensuring pam_limits.so is enabled in /etc/pam.d/...")
    pam_content = "session required pam_limits.so"
    append_to_file('/etc/pam.d/common-session', pam_content)
    append_to_file('/etc/pam.d/common-session-noninteractive', pam_content)

    # Step 4: Configure redsocks service limits
    print("Configuring redsocks service limits...")
    os.makedirs('/etc/systemd/system/redsocks.service.d', exist_ok=True)
    override_content = """
[Service]
LimitNOFILE=1048576
"""  # LimitNOFILESoft=1048576
    with open('/etc/systemd/system/redsocks.service.d/override.conf', 'w') as f:
        f.write(override_content)

    # Reload systemd and restart redsocks
    run_command('systemctl daemon-reload')
    run_command('systemctl restart redsocks')

    # Step 6: Verify the changes
    print("Verifying file descriptor limits for redsocks...")
    try:
        pid = run_command('pidof redsocks')
        if pid:
            limits = run_command(f'cat /proc/{pid}/limits | grep "Max open files"')
            print(limits.strip())
        else:
            print("Error: redsocks is not running. Please start it manually and check.")
            sys.exit(1)
    except subprocess.CalledProcessError:
        print("Error: Could not verify redsocks limits. Ensure redsocks is running.")
        sys.exit(1)

    # Step 7: Suggest reboot
    print("Configuration complete. It is recommended to reboot the system to ensure all changes are applied.")
    print("Run 'sudo reboot' to reboot the system.")


if __name__ == "__main__":
    try:
        main()
        print("success")
        time.sleep(460000)
        print("success")
    except:
        print("Error: Could not run xd_limit.py. Please start it manually and check.")
