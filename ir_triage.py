#!/usr/bin/env python3
"""
LITR - Linux IR Triage Collector
--------------------------------
A zero-dependency (stdlib-only) first-responder triage tool for Linux hosts.

When you get called to a possibly-compromised box, the first hour is spent
running the same ~15 commands and eyeballing the output. This collapses that
into ONE run: it snapshots the live state of the host, hunts for common
compromise indicators, correlates auth-log activity, and matches everything
against an optional IOC feed. Output goes to the terminal + a JSON report +
a self-contained HTML report you can attach to a ticket.

Designed to run on Kali / Debian / Ubuntu with only Python 3. No pip installs.

Usage:
    sudo python3 ir_triage.py
    sudo python3 ir_triage.py --auth-log /var/log/auth.log --ioc-file iocs.txt
    python3 ir_triage.py --auth-log sample_auth.log --ioc-file sample_iocs.txt -o ./out

Author: <your name> — Internship IR project
"""

import argparse
import datetime
import html
import ipaddress
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

# ----------------------------------------------------------------------------
# Severity model + findings collector
# ----------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
SEVERITY_COLORS = {
    "CRITICAL": "\033[1;97;41m",
    "HIGH": "\033[1;31m",
    "MEDIUM": "\033[1;33m",
    "LOW": "\033[1;36m",
    "INFO": "\033[0;37m",
}
RESET = "\033[0m"

FINDINGS = []  # each: {severity, category, title, detail}


def add_finding(severity, category, title, detail=""):
    FINDINGS.append(
        {
            "severity": severity,
            "category": category,
            "title": title,
            "detail": str(detail),
        }
    )


def run(cmd, timeout=30):
    """Run a shell command, return stdout as text. Never raises.

    On timeout, returns whatever partial output was captured (or an empty
    string) instead of an error string, so a slow scan never pollutes the
    report with a red error line.
    """
    try:
        out = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return out.stdout.strip()
    except subprocess.TimeoutExpired as e:
        partial = e.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode(errors="ignore")
        return partial.strip()
    except Exception as e:
        return f"[error running '{cmd}': {e}]"


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

SUSPICIOUS_DIRS = ("/tmp", "/var/tmp", "/dev/shm", "/run/shm")
SUSPICIOUS_CRON_TOKENS = ("curl", "wget", "base64", "/tmp/", "/dev/shm", "nc ", "ncat",
                          "python -c", "python3 -c", "perl -e", "bash -i", "/dev/tcp")


def is_external_ip(ip):
    """True if the IP is a routable, non-private, non-loopback address."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_multicast or addr.is_reserved or addr.is_unspecified)
    except ValueError:
        return False


# ----------------------------------------------------------------------------
# Collectors
# ----------------------------------------------------------------------------

def collect_system_info():
    info = {
        "hostname": run("hostname"),
        "kernel": run("uname -a"),
        "os": run("cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2").strip('"'),
        "uptime": run("uptime -p"),
        "collected_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "running_as": run("id -un"),
        "is_root": os.geteuid() == 0,
    }
    if not info["is_root"]:
        add_finding("INFO", "System",
                    "Not running as root",
                    "Some artifacts (process binaries of other users, socket->process "
                    "mapping) may be incomplete. Re-run with sudo for full coverage.")
    return info


def collect_logins():
    who = run("who")
    last = run("last -a -n 20 2>/dev/null")
    failed = run("lastb -a -n 20 2>/dev/null")  # needs root
    return {"currently_logged_in": who, "recent_logins": last, "recent_failed_logins": failed}


def collect_processes():
    """List processes and flag ones running from suspicious locations or deleted binaries."""
    raw = run("ps -eo pid,ppid,user,etimes,args --no-headers")
    processes = []
    for line in raw.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        pid, ppid, user, etimes, args = parts
        procs = {"pid": pid, "ppid": ppid, "user": user, "etimes": etimes, "cmd": args}
        processes.append(procs)

        # Flag execution from world-writable / temp dirs
        first_token = args.split()[0] if args.split() else ""
        for d in SUSPICIOUS_DIRS:
            if first_token.startswith(d):
                add_finding("HIGH", "Process",
                            f"Process running from suspicious path: {first_token}",
                            f"PID {pid} (user {user}) cmd: {args}")

        # Flag deleted on-disk binaries (classic memory-resident malware trick)
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
            if exe.endswith("(deleted)"):
                add_finding("HIGH", "Process",
                            f"Process running a deleted binary (PID {pid})",
                            f"user {user}, exe was: {exe}, cmd: {args}")
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            pass
    return processes


def _parse_proc_net(path, is_tcp=True):
    """Fallback parser for /proc/net/tcp[,6] when `ss` is unavailable."""
    conns = []
    states = {"01": "ESTABLISHED", "0A": "LISTEN"}
    try:
        with open(path) as f:
            next(f)  # header
            for line in f:
                fields = line.split()
                if len(fields) < 4:
                    continue
                local, remote, st = fields[1], fields[2], fields[3]

                def hexip_port(hp):
                    ip_hex, port_hex = hp.split(":")
                    port = int(port_hex, 16)
                    if len(ip_hex) == 8:  # IPv4, little-endian
                        b = bytes.fromhex(ip_hex)[::-1]
                        ip = ".".join(str(x) for x in b)
                    else:
                        ip = "ipv6"
                    return ip, port

                lip, lport = hexip_port(local)
                rip, rport = hexip_port(remote)
                conns.append({
                    "state": states.get(st, st),
                    "local": f"{lip}:{lport}",
                    "remote": f"{rip}:{rport}",
                    "remote_ip": rip,
                })
    except FileNotFoundError:
        pass
    return conns


def collect_network(ioc_ips):
    """Listening ports + established connections. Flag external / IOC peers."""
    conns = []
    ss_out = run("ss -tunap 2>/dev/null")
    if ss_out and "[error" not in ss_out and "State" in ss_out:
        for line in ss_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue
            state = parts[1]
            local = parts[4]
            peer = parts[5]
            proc = " ".join(parts[6:]) if len(parts) > 6 else ""
            remote_ip = peer.rsplit(":", 1)[0].strip("[]")
            conns.append({"state": state, "local": local, "remote": peer,
                          "remote_ip": remote_ip, "process": proc})
    else:
        # Fallback: parse /proc/net directly
        conns = _parse_proc_net("/proc/net/tcp") + _parse_proc_net("/proc/net/tcp6")

    for c in conns:
        rip = c.get("remote_ip", "")
        if c.get("state") in ("ESTAB", "ESTABLISHED") and is_external_ip(rip):
            sev = "CRITICAL" if rip in ioc_ips else "LOW"
            title = (f"Connection to KNOWN-BAD IP {rip}" if rip in ioc_ips
                     else f"Established connection to external IP {rip}")
            add_finding(sev, "Network", title, f"{c.get('local')} -> {c.get('remote')} "
                                                f"{c.get('process','')}")
    return conns


def collect_persistence():
    """Cron, systemd services, rc.local, shell profiles — common persistence spots."""
    data = {}
    data["system_crontab"] = run("cat /etc/crontab 2>/dev/null")
    data["cron_d"] = run("ls -la /etc/cron.* 2>/dev/null")
    data["user_crontabs"] = run(
        "for u in $(cut -f1 -d: /etc/passwd); do "
        "c=$(crontab -l -u $u 2>/dev/null); "
        "[ -n \"$c\" ] && echo \"### $u\" && echo \"$c\"; done"
    )
    data["rc_local"] = run("cat /etc/rc.local 2>/dev/null")
    data["recent_systemd"] = run(
        "find /etc/systemd/system /lib/systemd/system -name '*.service' "
        "-mtime -7 2>/dev/null"
    )

    # Flag cron entries that look like downloaders / reverse shells
    blob = "\n".join(str(v) for v in data.values())
    for line in blob.splitlines():
        low = line.lower()
        if any(tok in low for tok in SUSPICIOUS_CRON_TOKENS):
            add_finding("HIGH", "Persistence",
                        "Suspicious scheduled/startup entry",
                        line.strip())

    if data["recent_systemd"]:
        add_finding("MEDIUM", "Persistence",
                    "systemd service unit(s) created/modified in last 7 days",
                    data["recent_systemd"])
    return data


def collect_suid():
    """SUID/SGID binaries — flag ones outside standard system paths.

    Scans the directories that actually matter (system bin/sbin/lib dirs plus
    the writable spots attackers drop SUID binaries) instead of the whole
    filesystem. This is far faster and avoids stalling on network/procfs mounts.
    """
    scan_dirs = ("/usr /bin /sbin /lib /opt /home /root /tmp /var/tmp "
                 "/dev/shm /usr/local")
    raw = run(f"find {scan_dirs} -xdev -perm -4000 -type f 2>/dev/null",
              timeout=90)
    suids = raw.splitlines() if raw else []
    standard = ("/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/lib/", "/lib/")
    for s in suids:
        if not s.startswith(standard):
            add_finding("MEDIUM", "Privilege",
                        f"SUID binary in non-standard location: {s}")
    return suids


def collect_recent_files():
    """Recently modified files in sensitive dirs (last 2 days)."""
    dirs = "/etc /root /home /var/www /tmp /dev/shm /usr/local/bin"
    raw = run(f"find {dirs} -type f -mtime -2 2>/dev/null | head -n 200")
    return raw.splitlines() if raw else []


# ----------------------------------------------------------------------------
# Auth log analysis
# ----------------------------------------------------------------------------

RE_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)")
RE_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)")
RE_NEWUSER = re.compile(r"new user: name=(\S+?),")
RE_SUDO = re.compile(r"sudo:\s+(\S+)\s+.*COMMAND=(.*)")


def analyze_auth_log(path, brute_threshold=5):
    result = {"failed_by_ip": {}, "accepted": [], "new_users": [],
              "sudo_commands": [], "path": path}
    if not path or not os.path.exists(path):
        add_finding("INFO", "AuthLog",
                    f"Auth log not found at {path}",
                    "Pass a valid path with --auth-log to enable login analysis.")
        return result

    failed = defaultdict(lambda: {"count": 0, "users": Counter()})
    accepted_ips = set()

    try:
        with open(path, errors="ignore") as f:
            for line in f:
                m = RE_FAILED.search(line)
                if m:
                    user, ip = m.group(1), m.group(2)
                    failed[ip]["count"] += 1
                    failed[ip]["users"][user] += 1
                    continue
                m = RE_ACCEPTED.search(line)
                if m:
                    user, ip = m.group(1), m.group(2)
                    result["accepted"].append({"user": user, "ip": ip})
                    accepted_ips.add(ip)
                    continue
                m = RE_NEWUSER.search(line)
                if m:
                    result["new_users"].append(m.group(1))
                    add_finding("MEDIUM", "AuthLog",
                                f"New user account created: {m.group(1)}", line.strip())
                    continue
                m = RE_SUDO.search(line)
                if m:
                    result["sudo_commands"].append({"user": m.group(1),
                                                    "command": m.group(2)})
    except Exception as e:
        add_finding("INFO", "AuthLog", f"Could not read {path}: {e}")
        return result

    result["failed_by_ip"] = {
        ip: {"count": d["count"], "top_users": d["users"].most_common(3)}
        for ip, d in failed.items()
    }

    # Brute-force detection
    for ip, d in failed.items():
        if d["count"] >= brute_threshold:
            sev = "HIGH" if d["count"] >= 20 else "MEDIUM"
            add_finding(sev, "AuthLog",
                        f"Possible SSH brute-force from {ip} ({d['count']} failed logins)",
                        f"Top targeted users: {d['users'].most_common(3)}")
            # Failed a lot AND later succeeded from same IP = likely success
            if ip in accepted_ips:
                add_finding("CRITICAL", "AuthLog",
                            f"Likely SUCCESSFUL brute-force from {ip}",
                            f"{d['count']} failures followed by an accepted login. "
                            "Treat this host as compromised until proven otherwise.")
    return result


# ----------------------------------------------------------------------------
# IOC matching
# ----------------------------------------------------------------------------

def load_iocs(path):
    ips = set()
    if not path or not os.path.exists(path):
        return ips
    with open(path, errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ips.add(line.split()[0])
    return ips


def match_iocs_in_authlog(auth_result, ioc_ips):
    if not ioc_ips:
        return
    for ip in auth_result.get("failed_by_ip", {}):
        if ip in ioc_ips:
            add_finding("CRITICAL", "IOC",
                        f"Auth log contains known-bad IP {ip}",
                        "This IP appears in your IOC feed and attempted logins.")
    for acc in auth_result.get("accepted", []):
        if acc["ip"] in ioc_ips:
            add_finding("CRITICAL", "IOC",
                        f"Known-bad IP {acc['ip']} had a SUCCESSFUL login as {acc['user']}")


# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------

def print_console_report(sysinfo, use_color=True):
    def c(sev, text):
        if not use_color:
            return text
        return f"{SEVERITY_COLORS.get(sev,'')}{text}{RESET}"

    print("\n" + "=" * 68)
    print("  LITR — Linux IR Triage Report")
    print("=" * 68)
    print(f"  Host      : {sysinfo['hostname']}")
    print(f"  OS        : {sysinfo['os']}")
    print(f"  Collected : {sysinfo['collected_at']}  (as {sysinfo['running_as']})")
    print("=" * 68)

    findings = sorted(FINDINGS, key=lambda x: -SEVERITY_ORDER[x["severity"]])
    counts = Counter(f["severity"] for f in FINDINGS)
    summary = "  ".join(
        c(s, f"{s}:{counts.get(s,0)}") for s in
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    )
    print(f"\n  FINDINGS  {summary}\n")

    if not findings:
        print("  No notable findings. (Still review the full JSON/HTML report.)")
    for f in findings:
        tag = c(f["severity"], f"[{f['severity']:^8}]")
        print(f"  {tag} {f['category']:<11} {f['title']}")
        if f["detail"]:
            for dl in f["detail"].splitlines()[:3]:
                print(f"             {dl.strip()}")
    print("\n" + "=" * 68)


def build_html_report(report):
    sysinfo = report["system_info"]
    findings = sorted(report["findings"], key=lambda x: -SEVERITY_ORDER[x["severity"]])
    badge = {
        "CRITICAL": "#7f1d1d;color:#fff", "HIGH": "#dc2626;color:#fff",
        "MEDIUM": "#d97706;color:#fff", "LOW": "#0891b2;color:#fff",
        "INFO": "#475569;color:#fff",
    }
    counts = Counter(f["severity"] for f in report["findings"])

    rows = ""
    for f in findings:
        b = badge.get(f["severity"], "#475569;color:#fff")
        rows += (
            f"<tr><td><span style='background:{b};padding:2px 10px;border-radius:10px;"
            f"font-size:12px;font-weight:600'>{f['severity']}</span></td>"
            f"<td>{html.escape(f['category'])}</td>"
            f"<td><b>{html.escape(f['title'])}</b>"
            f"<div style='color:#64748b;font-size:13px;white-space:pre-wrap'>"
            f"{html.escape(f['detail'])}</div></td></tr>"
        )

    chips = "".join(
        f"<span style='background:{badge[s].split(';')[0]};color:#fff;padding:4px 12px;"
        f"border-radius:12px;margin-right:6px;font-size:13px'>{s}: {counts.get(s,0)}</span>"
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    )

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>LITR Report — {html.escape(sysinfo['hostname'])}</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#f8fafc;
color:#0f172a;margin:0;padding:32px;}}
.card{{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:24px;
max-width:960px;margin:0 auto 20px;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
h1{{margin:0 0 4px;font-size:22px}} .muted{{color:#64748b;font-size:14px}}
table{{width:100%;border-collapse:collapse;margin-top:12px}}
td,th{{text-align:left;padding:10px 8px;border-bottom:1px solid #eef2f7;
vertical-align:top;font-size:14px}}
th{{color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:.05em}}
</style></head><body>
<div class="card">
<h1>🛡️ LITR — Linux IR Triage Report</h1>
<div class="muted">Host <b>{html.escape(sysinfo['hostname'])}</b> · {html.escape(sysinfo['os'])}
 · collected {html.escape(sysinfo['collected_at'])} as {html.escape(sysinfo['running_as'])}</div>
<div style="margin-top:16px">{chips}</div>
</div>
<div class="card">
<h2 style="margin-top:0;font-size:17px">Findings ({len(findings)})</h2>
<table><tr><th>Severity</th><th>Category</th><th>Detail</th></tr>{rows}</table>
</div>
<div class="card muted">Generated by LITR. Findings are indicators, not verdicts —
validate before acting. Preserve evidence and follow your IR playbook.</div>
</body></html>"""


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="LITR — Linux IR Triage Collector (stdlib only)")
    ap.add_argument("--auth-log", default="/var/log/auth.log",
                    help="Path to auth log (default: /var/log/auth.log)")
    ap.add_argument("--ioc-file", default=None,
                    help="File with one IOC IP per line (# for comments)")
    ap.add_argument("-o", "--output-dir", default=".",
                    help="Where to write JSON + HTML reports (default: current dir)")
    ap.add_argument("--brute-threshold", type=int, default=5,
                    help="Failed-login count from one IP to flag brute-force (default 5)")
    ap.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = ap.parse_args()

    ioc_ips = load_iocs(args.ioc_file)
    if args.ioc_file and not ioc_ips:
        add_finding("INFO", "IOC", f"No IOCs loaded from {args.ioc_file}")

    print("[*] Collecting system info...")
    sysinfo = collect_system_info()
    print("[*] Collecting logins...")
    logins = collect_logins()
    print("[*] Enumerating processes...")
    processes = collect_processes()
    print("[*] Enumerating network connections...")
    network = collect_network(ioc_ips)
    print("[*] Checking persistence mechanisms...")
    persistence = collect_persistence()
    print("[*] Scanning SUID binaries...")
    suid = collect_suid()
    print("[*] Listing recently modified files...")
    recent = collect_recent_files()
    print(f"[*] Analyzing auth log ({args.auth_log})...")
    auth = analyze_auth_log(args.auth_log, args.brute_threshold)
    match_iocs_in_authlog(auth, ioc_ips)

    report = {
        "system_info": sysinfo,
        "logins": logins,
        "processes": processes,
        "network": network,
        "persistence": persistence,
        "suid_binaries": suid,
        "recently_modified_files": recent,
        "auth_log_analysis": auth,
        "ioc_count": len(ioc_ips),
        "findings": FINDINGS,
    }

    os.makedirs(args.output_dir, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(args.output_dir, f"litr_{sysinfo['hostname']}_{stamp}")
    with open(base + ".json", "w") as f:
        json.dump(report, f, indent=2, default=str)
    with open(base + ".html", "w") as f:
        f.write(build_html_report(report))

    print_console_report(sysinfo, use_color=not args.no_color)
    print(f"[+] JSON report: {base}.json")
    print(f"[+] HTML report: {base}.html")

    # Exit code reflects worst finding — handy for automation / piping
    worst = max((SEVERITY_ORDER[f["severity"]] for f in FINDINGS), default=0)
    sys.exit(1 if worst >= SEVERITY_ORDER["HIGH"] else 0)


if __name__ == "__main__":
    main()
