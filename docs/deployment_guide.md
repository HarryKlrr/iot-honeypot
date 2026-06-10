# Deployment Guide

Step-by-step instructions to reproduce the IoT honeypot lab. The entire build runs on a single host using VirtualBox and an **isolated Host-Only network** — the honeypot never touches the public internet.

## 1. Requirements

- Oracle VirtualBox
- Ubuntu Server 22.04 LTS (honeypot sensor)
- Kali Linux (attacker / adversary emulation)

## 2. Network Setup (isolation first)

1. In VirtualBox, create a **Host-Only Adapter** (`File → Host Network Manager`).
2. Assign the network range, e.g. `192.168.56.0/24`.
3. Attach **both** VMs to this Host-Only adapter only. Do **not** attach a NAT/Bridged adapter to the sensor — this guarantees the honeypot has no route to the internet.

## 3. Honeypot Setup (Ubuntu VM)

Install dependencies:

```bash
sudo apt update && sudo apt install git python3 python3-venv python3-pip -y
```

Create a non-root `cowrie` user and clone Cowrie:

```bash
sudo adduser --disabled-password cowrie
sudo su - cowrie
git clone https://github.com/cowrie/cowrie.git
cd cowrie
```

Set up the Python environment:

```bash
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 4. Configuration

Apply the configuration from this repository:

```bash
# from the repo, copy the provided config into Cowrie's etc/ directory
cp config/cowrie.cfg   ~/cowrie/etc/cowrie.cfg
cp config/userdb.txt   ~/cowrie/etc/userdb.txt
```

Key settings (already set in `config/cowrie.cfg`):
- `hostname = iot_device` — IoT persona.
- SSH enabled on `2222`, Telnet enabled on `2223`.
- JSON logging enabled → `var/log/cowrie/cowrie.json`.

## 5. Port Redirection

Redirect the standard service ports to Cowrie's high ports so attackers reach the honeypot on 22/23 (run as root on the sensor):

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-ports 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-ports 2223
# persist
sudo apt install iptables-persistent -y && sudo netfilter-persistent save
```

The exported ruleset is provided in `config/iptables_rules.txt`.

## 6. Run the Honeypot

```bash
cd ~/cowrie
source cowrie-env/bin/activate
bin/cowrie start
# check status
bin/cowrie status
# follow the JSON log
tail -f var/log/cowrie/cowrie.json
```

## 7. Verification

From the Kali VM, confirm the honeypot is reachable and logging:

```bash
ssh root@<honeypot-ip>          # should present the iot_device banner
telnet <honeypot-ip>            # Telnet service
```

Any login attempt should appear immediately in `var/log/cowrie/cowrie.json`.

## 8. Generate Test Activity (optional)

Use the credential dictionaries in `wordlists/` to drive brute-force attempts, e.g. with Hydra from Kali:

```bash
hydra -L wordlists/users.txt -P wordlists/passwords.txt ssh://<honeypot-ip>
```

## 9. Collect & Analyse

Copy `var/log/cowrie/cowrie.json` off the sensor into the repo's `data/` directory and run the analysis pipeline:

```bash
python3 analysis/enhanced_credential_analyzer.py
```

See [`methodology.md`](methodology.md) and [`threat-intelligence-report.md`](threat-intelligence-report.md) for analysis and findings.
