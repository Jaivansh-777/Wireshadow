# WIRESHADOW — move unseen · see everything

WIRESHADOW scans your own network, finds live devices and open ports, checks
them against known vulnerabilities, asks an AI to grade the risk, and writes
you a PDF report. Think of it as a security camera for your Wi-Fi.

> ⚠️ **Only scan networks you own** (your home Wi-Fi, your own laptop).
> Scanning someone else's network without written permission is illegal in most
> countries. WIRESHADOW logs every scan, so there is always a record.

---

## What it does (in plain English)

1. **Finds devices** — asks "who's on this Wi-Fi?" (ping sweep of your subnet)
2. **Checks doors** — knocks on ports to see which are open (TCP SYN / Connect + UDP)
3. **Reads nameplates** — figures out what software each port runs (versions, OS guesses, banners)
4. **Matches known break-ins** — compares versions against a CVE list (e.g. ancient FTP = backdoor)
5. **Asks the AI** — sends results to a free AI model for a 0–100 risk score + fix advice
6. **Writes the report** — PDF with summary, per-device details, recommendations
7. **Remembers** — every scan is saved in a local database you can browse later

---

## You need

- **Linux** — Kali or Arch/CachyOS both work
- **Python 3.11+** (`python3 --version` to check)
- **nmap** — the actual scanning engine
  - Kali/Debian: `sudo apt install -y nmap python3-venv`
  - Arch: `sudo pacman -S nmap`
- An **OpenRouter API key** (free) — only needed for the AI verdict; without it
  WIRESHADOW still works using built-in offline scoring

## Install (copy-paste)

**Step 0 — get the code (everyone):**

```bash
git clone https://github.com/Jaivansh-777/Wireshadow.git
cd Wireshadow
```

> Cloned folder is named `Wireshadow` (capital W) — `cd` into it, then follow
> your distro block below. All later commands assume you're inside it.

**Kali Linux / Debian / Ubuntu (bash):**

```bash
python3 -m venv venv
source venv/bin/activate
pip install setuptools wheel
pip install -r requirements.txt
sudo apt install -y nmap python3-venv
```

**Arch / CachyOS (fish):**

```fish
python -m venv venv
source venv/bin/activate.fish
pip install setuptools wheel
pip install -r requirements.txt
sudo pacman -S nmap
```

For **bash/zsh**, replace line 3 with `source venv/bin/activate`.

> Seeing `error: externally-managed-environment`? That's Arch protecting system
> Python — the `venv` above is the fix. Never use `--break-system-packages`.

## Get a free AI key (2 minutes)

1. Go to **https://openrouter.ai** → sign up (no credit card needed)
2. **Keys** page → **Create Key** → copy it (starts with `sk-or-v1-...`)
3. Tell your shell about it:
   ```fish
   set -x OPENROUTER_API_KEY "sk-or-v1-paste-yours-here"   # fish
   ```
   ```bash
   export OPENROUTER_API_KEY="sk-or-v1-paste-yours-here"   # bash/zsh
   ```
   Fish forever: `set -Ux OPENROUTER_API_KEY "..."`. Bash forever: append the
   export line to `~/.bashrc`.

## Run your first scan

```fish
source venv/bin/activate.fish   # fish — every new terminal!
# source venv/bin/activate      # bash/zsh instead
python main.py scan -t auto
```

What happens:

- A red **authorization box** appears → type `I AUTHORIZE` (or pass `-y`)
- `auto` detects your subnet (e.g. `192.168.1.0/24`) — or give one: `-t 192.168.1.0/24`
- Live hosts are listed; confirm to deep-scan them
- Watch the progress bar, then read your **AI verdict + per-host panels**
- A PDF lands in `reports_output/`, history is saved automatically

Quick single device: `python main.py scan -t 192.168.1.10 -p 22,80,443`

See past scans:

```fish
python main.py history --limit 10
python main.py history --show <scan_id>
```

## Reading the output

- **Risk bar** `92 Critical █████████░` — score 0–100 + level (Low/Medium/High/Critical),
  border color matches the level
- **Ports table** — every open port with detected service + version + grabbed banner
- **Vulnerabilities (red panel)** — CVE matches like `[Critical] CVE-2011-2523 :2121`
- **Findings & fixes (blue panel)** — misconfigurations ⚠ and what to do ▸
- **Provider line** in the verdict title tells you who scored it:
  a model name = AI, `heuristic-*` = offline fallback

## Try it safely (fake vulnerable services)

Test WIRESHADOW without touching real devices — two decoys on your own laptop:

```fish
python3 /tmp/opencode/fake_services.py   # leave running (Ctrl+C to stop)
python main.py scan -t 127.0.0.1 -p 2121,2323 -y
```

Expect: fake `vsftpd 2.3.4` → CVE-2011-2523 Critical, fake Telnet → High,
risk in the 90s. Delete/ignore that file whenever — it's only a test toy.

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'nmap'` | venv not active or deps missing → `source venv/bin/activate.fish` + `pip install -r requirements.txt` |
| `externally-managed-environment` | Use the venv (see Install). Never `--break-system-packages` |
| `source: No such file or directory` (activate) | Path must match the venv you made (`venv/` vs `.venv/`); fish needs `activate.fish` |
| `fish: Unknown command: I` | You typed `I AUTHORIZE` at the shell — type it at the scanner's prompt instead |
| Verdict says `heuristic-*`, no AI | `OPENROUTER_API_KEY` not set in this shell (`set -x ...`), or model 404 — the tool retries via `openrouter/free` automatically |
| All hosts show 0 open ports | Re-run privileged: `sudo -E venv/bin/python main.py scan ...` (`-E` keeps your API key). Quiet LANs can also be genuinely clean |
| AI reply empty / `risk n/a` | Fixed in current version — results are backfilled from offline scoring so panels never render empty |

## Project map

```
main.py                  authorization → discovery → scan → AI → PDF → history
scanner/discovery.py     find live hosts (nmap ping sweep, subnet auto-detect)
scanner/portscan.py      TCP SYN / Connect + UDP top ports + versions + OS
scanner/fingerprint.py   banner grabbing (control chars cleaned)
scanner/vuln_check.py    offline CVE signature matching
ai/analyzer.py           OpenRouter call (3-attempt fallback) + offline heuristic
ai/prompts.py            the analyst prompt
reports/generator.py     reportlab PDF builder
db/history.py            SQLite save / list / show
utils/                   config loader, file-only audit logger, validators, theme
config.yaml              ports, model, report dir, legal flags
```

Tune defaults in `config.yaml` (port range, model, output dir). Secrets stay in
environment variables (`OPENROUTER_API_KEY`, optional `OPENROUTER_MODEL`) —
never in the config file.

## FAQ

- **Does it hack anything?** No — it only *looks* (port states, banners, versions).
  It never logs in, never exploits.
- **Why sudo?** Raw-socket SYN/OS scans need root. Without it WIRESHADOW
  automatically falls back to TCP Connect scans.
- **Is my API key safe?** It's only sent to OpenRouter with the scan summary.
  Don't commit it anywhere; rotate it if it ever leaks.
- **Where is my data?** `scan_audit.log` (audit trail), `db/scan_history.db`
  (results), `reports_output/*.pdf` (reports). All local.
