<h1 align="center">🛡️ LITR — Linux IR Triage Collector</h1>

<p align="center">
  <b>One command. Full incident-response triage.</b><br>
  A zero-dependency, stdlib-only first-responder tool for Linux hosts.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.6%2B-blue.svg">
  <img src="https://img.shields.io/badge/dependencies-none-brightgreen.svg">
  <img src="https://img.shields.io/badge/platform-Kali%20%7C%20Debian%20%7C%20Ubuntu-informational.svg">
  <img src="https://img.shields.io/badge/license-MIT-lightgrey.svg">
  <img src="https://img.shields.io/badge/purpose-DFIR%20%7C%20Blue%20Team-red.svg">
</p>

---

## 📖 Overview

When an analyst is called to a possibly-compromised Linux host, the **first hour**
is spent running the same 15+ manual commands — `ps`, `ss`, `last`, `crontab`,
`find -perm -4000`, grepping `auth.log` — and correlating the output by eye.
It's slow, inconsistent, and easy to miss indicators under pressure.

**LITR collapses that first hour into a single command.** It snapshots the live
state of the host, hunts for common compromise indicators, correlates SSH auth
activity, matches everything against an optional IOC feed, and produces a
severity-ranked report you can attach straight to a ticket.

> Built during a cybersecurity internship as a practical DFIR tool — not a demo.

---

## ✨ Features

| Module | What it does |
|--------|--------------|
| 🖥️ **System info** | Host, OS, kernel, uptime, privilege level |
| 👤 **Logins** | Currently logged-in users, recent + failed logins |
| ⚙️ **Processes** | Flags binaries run from `/tmp`, `/dev/shm`, and **deleted** on-disk binaries (memory-resident malware) |
| 🌐 **Network** | Listening ports + established connections; flags external peers, **CRITICAL** on IOC match |
| 🔁 **Persistence** | cron, cron.d, user crontabs, rc.local, new systemd units; flags downloader / reverse-shell patterns |
| 🔑 **Privilege** | SUID binaries in non-standard locations |
| 📄 **Recent files** | Files modified in the last 2 days under sensitive directories |
| 🔍 **Auth log analysis** | SSH brute-force detection **and successful brute-force** (failures → later accepted login from same IP) |
| 🚨 **IOC matching** | Cross-references network + auth IPs against a bad-IP feed |

**Outputs:** color-coded terminal summary · full **JSON** artifact · self-contained **HTML** report.
Exit code `1` if any HIGH/CRITICAL finding — handy for automation.

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/<your-username>/litr.git
cd litr

# Demo run with included sample data (no root needed)
python3 ir_triage.py --auth-log sample_auth.log --ioc-file sample_iocs.txt -o ./out
```

### Live triage on a real host
```bash
# Run as root for full coverage
sudo python3 ir_triage.py

# With a real auth log + IOC feed
sudo python3 ir_triage.py --auth-log /var/log/auth.log --ioc-file iocs.txt -o ./reports
```

---

## ⚙️ Options

| Flag | Description | Default |
|------|-------------|---------|
| `--auth-log PATH` | Path to the auth log to analyze | `/var/log/auth.log` |
| `--ioc-file PATH` | File with one bad IP per line (`#` for comments) | none |
| `-o, --output-dir DIR` | Where to write JSON + HTML reports | current dir |
| `--brute-threshold N` | Failed logins from one IP to flag brute-force | `5` |
| `--no-color` | Disable colored terminal output | off |

---

## 🧪 Example Output

Running against the included sample data flags a full compromise chain:

```
  FINDINGS  CRITICAL:3  HIGH:0  MEDIUM:2  LOW:0  INFO:0

  [CRITICAL] AuthLog     Likely SUCCESSFUL brute-force from 45.134.26.9
  [CRITICAL] IOC         Auth log contains known-bad IP 45.134.26.9
  [CRITICAL] IOC         Known-bad IP 45.134.26.9 had a SUCCESSFUL login as root
  [ MEDIUM ] AuthLog     New user account created: svc_backup
  [ MEDIUM ] AuthLog     Possible SSH brute-force from 45.134.26.9 (7 failed logins)
```

The generated HTML report is a clean, self-contained file ready to attach to a ticket:

<p align="center">
  <img src="docs/report-screenshot.png" alt="LITR HTML report showing a detected SSH brute-force compromise" width="820">
</p>

---

## 🗂️ Repository Structure

```
litr/
├── ir_triage.py       # The tool (single file, stdlib only)
├── sample_auth.log    # Demo auth log (brute-force + successful compromise)
├── sample_iocs.txt    # Demo IOC feed
├── README.md
└── LICENSE
```

---

## ⚠️ Scope & Limitations

- LITR is a **triage** tool, not full forensics. Findings are **indicators, not verdicts** — validate before acting.
- Live collection touches the host; in strict forensics you would image first.
- Auth parsing targets Debian/Ubuntu `auth.log` (syslog format), not journald.

---

## 🛣️ Roadmap

- [ ] `journald` (`journalctl`) support
- [ ] YARA scanning of `/tmp` and recently-modified files
- [ ] Pull IOC feeds from a URL / MISP
- [ ] Package as a single static binary for airgapped response

---

## 📜 License

Released under the [MIT License](LICENSE).

> **Disclaimer:** Use only on systems you are authorized to assess.
