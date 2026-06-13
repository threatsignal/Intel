# 🐧 Linux Server Hardening Checklist

**Maintained by:** [ThreatSignal](https://threatsignal.in)  
**Last Updated:** May 2026  
**Applies to:** Ubuntu 22.04/24.04 LTS, Debian 12, RHEL/Rocky 9

Use this checklist when provisioning new Linux servers or auditing existing ones. Each item links to context where applicable.

---

## 1. Initial Setup

- [ ] Change default SSH port from 22
- [ ] Disable root SSH login (`PermitRootLogin no` in `/etc/ssh/sshd_config`)
- [ ] Enforce SSH key-based authentication only (`PasswordAuthentication no`)
- [ ] Create a non-root admin user with sudo access
- [ ] Set a strong, unique hostname
- [ ] Set correct timezone (`timedatectl set-timezone`)
- [ ] Enable automatic security updates (`unattended-upgrades`)

---

## 2. User & Access Management

- [ ] Audit all user accounts: `cat /etc/passwd`
- [ ] Lock unused accounts: `usermod -L <username>`
- [ ] Remove/disable accounts not in use
- [ ] Enforce password complexity via PAM (`/etc/pam.d/common-password`)
- [ ] Set password expiry: `chage -M 90 <username>`
- [ ] Restrict `su` to wheel/sudo group: `pam_wheel.so`
- [ ] Review sudo privileges: `visudo` and `/etc/sudoers.d/`
- [ ] Enable login failure lockout (`faillock` or `pam_tally2`)

---

## 3. SSH Hardening

- [ ] Use SSH protocol 2 only
- [ ] Set `MaxAuthTries 3`
- [ ] Set `ClientAliveInterval 300` and `ClientAliveCountMax 2`
- [ ] Disable X11 forwarding unless needed
- [ ] Restrict SSH to specific users/IPs using `AllowUsers` or firewall rules
- [ ] Use 4096-bit RSA or Ed25519 keys
- [ ] Rotate SSH host keys if the system was cloned/imaged

---

## 4. Firewall & Network

- [ ] Enable UFW or firewalld; default deny inbound
- [ ] Allow only necessary ports (22/custom SSH, 80, 443 as needed)
- [ ] Block outbound to non-essential ports if possible
- [ ] Disable IPv6 if not in use (`net.ipv6.conf.all.disable_ipv6 = 1`)
- [ ] Enable SYN flood protection: `net.ipv4.tcp_syncookies = 1`
- [ ] Disable IP forwarding unless server is a router: `net.ipv4.ip_forward = 0`
- [ ] Enable reverse path filtering: `net.ipv4.conf.all.rp_filter = 1`
- [ ] Use fail2ban to auto-ban repeated failed logins

---

## 5. File System & Permissions

- [ ] Set sticky bit on `/tmp`: `chmod +t /tmp`
- [ ] Mount `/tmp` with `noexec,nosuid,nodev`
- [ ] Find world-writable files: `find / -xdev -type f -perm -0002`
- [ ] Find SUID/SGID binaries: `find / -xdev \( -perm -4000 -o -perm -2000 \) -type f`
- [ ] Restrict `/etc/cron.*` permissions to root only
- [ ] Audit `.ssh/authorized_keys` on all users
- [ ] Ensure `/etc/shadow` permissions are `640` or `000`

---

## 6. Logging & Monitoring

- [ ] Enable and configure `auditd` for key file/syscall monitoring
- [ ] Forward logs to a remote syslog server or SIEM
- [ ] Monitor `/var/log/auth.log` for failed login attempts
- [ ] Set log rotation policies (`logrotate`)
- [ ] Enable process accounting (`acct` package)
- [ ] Install and run `rkhunter` or `chkrootkit` periodically
- [ ] Set up AIDE or Tripwire for file integrity monitoring (FIM)

---

## 7. Services & Software

- [ ] Disable unnecessary services: `systemctl disable <service>`
- [ ] List all listening services: `ss -tlnp`
- [ ] Remove unneeded packages: `apt autoremove` / `dnf autoremove`
- [ ] Check for outdated packages: `apt list --upgradable`
- [ ] Pin critical package versions where appropriate
- [ ] Verify software integrity with checksums after manual installs

---

## 8. Kernel Hardening (sysctl)

Add to `/etc/sysctl.conf` or `/etc/sysctl.d/99-hardening.conf`:

```ini
# Prevent smurf attacks
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Log martians
net.ipv4.conf.all.log_martians = 1

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# ASLR
kernel.randomize_va_space = 2

# Restrict dmesg to root
kernel.dmesg_restrict = 1

# Restrict ptrace
kernel.yama.ptrace_scope = 1
```

Apply: `sysctl -p`

---

## 9. Compliance Frameworks Reference

| Framework | Relevance |
|-----------|-----------|
| CIS Benchmarks | Baseline hardening guides per OS |
| NIST SP 800-123 | Server security guidelines |
| PCI DSS | If handling card data |
| SOC 2 | For SaaS/cloud environments |

---

*More checklists at [threatsignal.in](https://threatsignal.in)*

<!-- Hardening guidelines update -->
