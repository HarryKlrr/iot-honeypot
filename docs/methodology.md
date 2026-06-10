# Methodology

This document describes the full research methodology for the IoT Honeypot & Threat Analysis project, from environment design through to data analysis and reporting. It is written so the experiment can be independently reproduced.

## 1. Research Aim

To deploy a controlled IoT honeypot, capture authentication attacks against SSH and Telnet, and analyse the resulting telemetry to characterise attacker behaviour and produce actionable threat intelligence.

## 2. Threat Model & Scope

- **In scope:** SSH and Telnet authentication attacks, credential dictionary profiling, post-authentication shell activity, and secondary HTTP probing against the emulated device.
- **Out of scope:** Live internet exposure beyond the documented test, exploitation of real third-party hosts, and any offensive action outside the isolated lab.
- **Persona:** The sensor is configured to look like a low-end IoT/embedded device (`hostname = iot_device`, dated OpenSSH banner, IoT-typical service exposure) to attract IoT-targeted tooling.

## 3. Lab Architecture

| Component | Role | Detail |
|---|---|---|
| Oracle VirtualBox | Hypervisor | Hosts both VMs |
| Host-Only network | Isolation | `192.168.56.0/24`; no route to the internet |
| Ubuntu Server 22.04 | Sensor | Runs Cowrie + iptables redirect |
| Kali Linux | Adversary emulation | Hydra, Nmap, Nikto, Dirb |

The Host-Only adapter is the critical safety control: it guarantees the honeypot cannot reach external systems, so the experiment is contained and ethical.

## 4. Honeypot Configuration

Cowrie was installed in a Python virtual environment on the Ubuntu sensor (see [`deployment_guide.md`](deployment_guide.md)). Key configuration (see [`../config/cowrie.cfg`](../config/cowrie.cfg)):

- `hostname = iot_device` — IoT persona presented at the shell prompt.
- **SSH** enabled on `tcp:2222`, **Telnet** enabled on `tcp:2223`.
- JSON output plugin enabled → `var/log/cowrie/cowrie.json` (structured, machine-parseable telemetry).
- TTY logging enabled to capture full session transcripts.
- Authentication policy defined in [`../config/userdb.txt`](../config/userdb.txt) — a small set of credentials is accepted so that limited post-login behaviour can be observed, while the majority are rejected. This is what produces the realistic, low single-digit success rate.

Standard service ports were redirected to Cowrie's high ports with `iptables` so the honeypot could listen as an unprivileged process while still being reached on the expected 22/23 (see [`../config/iptables_rules.txt`](../config/iptables_rules.txt)):

```
22  → 2222   (SSH)
23  → 2223   (Telnet)
```

## 5. Attack Generation

From the Kali VM, attacks were generated against the sensor to populate the honeypot with realistic telemetry:

- **Credential brute force** (SSH/Telnet) using IoT-style dictionaries — usernames in [`../wordlists/users.txt`](../wordlists/users.txt) and passwords in [`../wordlists/passwords.txt`](../wordlists/passwords.txt). The password list deliberately mirrors the **Mirai** default credential table to emulate real IoT-botnet behaviour.
- **Service & web probing** using Nmap, Nikto, and Dirb to generate reconnaissance traffic for the secondary-vector analysis.

## 6. Data Collection

All activity was recorded by Cowrie as line-delimited JSON. The relevant event types are:

| Event ID | Meaning |
|---|---|
| `cowrie.session.connect` | New connection from a source IP |
| `cowrie.login.failed` | Failed authentication (username + password captured) |
| `cowrie.login.success` | Successful authentication |
| `cowrie.command.input` | Command issued in an authenticated shell |
| `cowrie.session.file_download` | Artifact retrieved by the attacker |

## 7. Data Analysis

Analysis was automated in Python ([`../analysis/enhanced_credential_analyzer.py`](../analysis/enhanced_credential_analyzer.py)) using pandas, matplotlib, and NumPy. The pipeline:

1. **Parses** the Cowrie JSON line-by-line, tolerating malformed lines.
2. **Extracts** login events into a dataframe with `timestamp, username, password, success, src_ip, session`.
3. **Aggregates** to produce: top usernames, top passwords, success/failure split, per-minute attack timeline, top source IPs, and per-session attempt distribution.
4. **Fingerprints** web-probing tools (Nikto vs. Dirb) from URL path signatures and summarises HTTP status codes.
5. **Renders** each analysis as a high-resolution chart saved to [`../results/`](../results/), and prints summary statistics to the console.

## 8. Validity & Limitations

- **Controlled environment:** Attacks were generated in an isolated lab, so source IPs reflect the lab attacker rather than worldwide internet sources. The geolocation method in the threat report describes how the same pipeline attributes sources when the sensor is internet-facing.
- **Authentication policy:** The success rate is a function of the honeypot's configured `userdb`, by design — it is not a measure of real-world device resilience.
- **Medium interaction:** Cowrie emulates a shell rather than running a real OS, so highly evasive malware that detects the emulation may behave differently than on a real device.

## 9. Ethical Considerations

The experiment used no third-party systems, collected no personal data, and was fully contained by the Host-Only network. Published configuration files are sanitised. Credential dictionaries are already-public default lists, included solely for defensive research and reproducibility.
