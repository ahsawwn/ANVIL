<div align="center">

# ⚒️ ANVIL

**Professional GUI Nmap Scanner for Kali Linux**

Enumerate everything. Map it to exploits. Store it like a true analyst.

`Nmap` · `PySide6` · `Tor` · `Metasploit` · `Obsidian` · `SQLite`

</div>

---

## What is Anvil?

Anvil is a full-featured, dark-mode GUI front-end for Nmap designed for Kali Linux penetration testers and security researchers. It does three things extremely well:

1. **Maximize enumeration** — runs aggressive Nmap profiles with `--script=default,vuln,exploit,brute,auth` on every scan.
2. **Map results to exploits** — fuzzy-matches detected services against a local database of CVEs, Exploit-DB IDs, and Metasploit modules.
3. **Store everything** — writes every scan into an Obsidian-compatible Markdown vault and indexes history in SQLite.

It also ships with built-in **Tor / proxychains** support so your scanning footprint stays quiet.

---

## ✨ Features

| Feature | Details |
|---|---|
| 🎯 **4 Scan Profiles** | Quick, Full, Stealth (decoys + fragments), UDP |
| 🧠 **Exploit Mapping** | CVEs, Exploit-DB IDs, Metasploit modules, remediation notes |
| 🕶️ **Anonymity** | Tor routing via `proxychains4`, NEWNYM circuit renewal via Stem, custom SOCKS5 proxy |
| 📁 **Obsidian Vault** | `Index.md`, `Targets/`, `Services/`, `Attacks/` with `![[embed]]` links |
| 🗃️ **Scan History** | Every scan logged to SQLite, exportable as JSON |
| 🖥️ **Live Console** | Real-time Nmap stdout streaming into the UI |
| 🚦 **Findings Tree** | Color-coded criticality badges + CVE column |
| 🛑 **Graceful Stop** | SIGTERM terminates Nmap cleanly |
| 🔔 **Desktop Alerts** | plyer notification when a Critical vuln is found |
| 🧵 **Thread-Safe UI** | All scans run in a `QThread` — the UI never freezes |
| 🎨 **Dark Theme** | Flat dark-gray UI with blue accents (custom QSS) |

---

## 🖼️ Screenshot

```
┌──────────────────────────────────────────────────────────────────────────┐
│ ANVIL - GUI Nmap Scanner v1.0.0                                  ─  □  X │
├──────────────────────────────────────────────────────────────────────────┤
│ Target: 192.168.1.1 │ Profile: Full ▾ │ [✓] Use Tor │ Proxy: _ │ [Renew] │
│ [ Start Scan ] [ Stop Scan ]                                               │
├──────────────────────────────────────────────────────────────────────────┤
│ $ nmap -sS -sV -O -A -p- --min-rate=1000 --script=default,vuln,...       │
│ [*] Tor circuit renewed (NEWNYM sent).                                    │
│ [CRITICAL] MS17-010 EternalBlue on port 445 (microsoft-ds)                │
├──────────────────────────────────────────────────────────────────────────┤
│ Port │ Protocol │ Service      │ Version    │ Criticality │ CVEs          │
│ 445  │ tcp      │ microsoft-ds │ Windows 7  │   CRITICAL  │ CVE-2017-0144 │
│ 22   │ tcp      │ ssh          │ OpenSSH7.4 │    Medium   │ CVE-2018-15473│
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 📦 Installation

> **Anvil is designed for Kali Linux.** Nmap, Tor, and proxychains are preinstalled there.

### 1. Install system dependencies

```bash
sudo apt update
sudo apt install -y nmap tor proxychains4 python3-venv python3-full
```

### 2. Create a virtual environment (required — Kali enforces PEP 668)

```bash
cd anvil
python3 -m venv venv
./venv/bin/python -m pip install --upgrade pip
./venv/bin/python -m pip install -r requirements.txt
```

### 3. Start Tor (optional, only if you plan to use anonymity mode)

```bash
sudo systemctl enable --now tor
sudo systemctl status tor   # confirm it is active
```

---

## 🚀 Usage

```bash
# From inside the anvil/ directory
sudo ./venv/bin/python main.py
```

> Anvil requires **root** for the privileged Nmap flags (`-O`, `-sS`, `--script=vuln`). If you launch it as a normal user, it will offer to relaunch itself via `pkexec`.

### Scanning workflow

1. Enter a **target** — single IP (`192.168.1.1`) or CIDR (`10.0.0.0/24`).
2. Pick a **profile**:
   - **Quick** — `-T4 -F` top-100 ports
   - **Full** — `-sS -sV -O -A -p- --min-rate=1000`
   - **Stealth** — decoys + IP fragmentation + `--data-length 200`
   - **UDP** — `-sU --top-ports 200`
3. Toggle **Use Tor** for routed scanning, optionally override with a custom `socks5 host port`.
4. Hit **Start Scan** and watch live output in the console.
5. Review the **Findings** table, then open the **Vault Explorer** tab.

---

## 📁 Obsidian Vault Layout

Every scan is written to `~/anvil_vault/`:

```
~/anvil_vault/
├── Index.md                          # Table of all scans, cross-linked
├── Targets/
│   └── 192.168.1.1.md                # Host summary + [[Services/...]] links
├── Services/
│   └── 192.168.1.1_445_microsoft-ds.md   # Banner, version, scripts, exploits
└── Attacks/
    └── MS17-010-EternalBlue.md       # CVE, Exploit-DB, MSF command, remediation
```

Open the folder as a vault in **Obsidian** — everything is wired together with `![[embeds]]`.

Example attack note:

```markdown
# MS17-010 EternalBlue

**Port**: 445
**CVE**: CVE-2017-0144
**Exploit-DB**: 42315
**MSF Command**: `use exploit/windows/smb/ms17_010_eternalblue`

## Remediation

Apply Microsoft patch MS17-010 and disable SMBv1 where possible.
```

---

## 🧱 Architecture

Anvil follows a clean **MVC-style** separation for scalability:

```
anvil/
├── main.py                  # Entry point, root check, logging, Qt app
├── config/settings.py       # Global constants, profiles, ScanProfile enum
├── core/                    # Business logic (no UI dependencies)
│   ├── scanner.py           # Nmap execution, ScanWorker (QThread), profiles
│   ├── parser.py            # python-nmap → ElementTree fallback
│   ├── attack_mapper.py     # service → CVE / EDB / MSF fuzzy matching
│   └── proxy_manager.py     # Tor lifecycle, NEWNYM, proxychains conf
├── models/scan_result.py    # Dataclasses: Port, Vulnerability, ScanReport
├── ui/                      # PySide6 layer
│   ├── main_window.py       # QMainWindow with Scanner + Vault tabs
│   ├── widgets/             # ScanConfigPanel, ConsoleOutput, FindingsTree
│   └── styles/dark_theme.qss
├── storage/                 # Persistence
│   ├── database.py          # SQLite scan history
│   └── markdown_generator.py# Obsidian vault writer
└── resources/attack_db.json # 17 services → exploit lookup table
```

> The `core/` layer never imports the UI, so adding a CLI mode or new profile is trivial. The attack DB is a drop-in JSON file — extend it without touching code.

---

## 🧪 Testing

Core logic (parser, attack mapping, vault generation, DB) is verified with a quick smoke test:

```bash
./venv/bin/python -c "import json; d=json.load(open('resources/attack_db.json')); print(len(d), 'attack entries')"
```

---

## ⚠️ Legal & Ethical Use

Anvil is a **security research and assessment tool**. Only scan systems you own or have explicit written authorization to test. Unauthorized scanning is illegal in most jurisdictions. You are responsible for using this tool lawfully.

---

## 🛠️ Troubleshooting

| Problem | Fix |
|---|---|
| `error: externally-managed-environment` | Use the venv — `python3 -m venv venv && venv/bin/pip install -r requirements.txt` |
| `No module named 'PySide6'` | You ran system `python3`; always use `./venv/bin/python` |
| Tor scan "hangs" or fails | `sudo systemctl restart tor`, confirm `systemctl status tor` shows active |
| Nmap needs sudo | Anvil auto-relaunches via `pkexec`, or just run `sudo ./venv/bin/python main.py` |

---

## 📄 License

[MIT](LICENSE) © ahsawwn

---

<div align="center">
Made with 🔥 for the offensive security community.
</div>
