#!/usr/bin/env python3
"""
Axios Supply Chain Attack IoC Scanner + Remediator
Malicious: axios@1.14.1, axios@0.30.4, plain-crypto-js@4.2.1
C2: sfrclak[.]com / callnrwise[.]com (142.11.206.73:8000)
Advisory: GHSA-fw8c-xr5c-95f9 | MAL-2026-2306
Cross-platform (macOS/Windows/Linux) — stdlib only.
Author: Jake Swiz @ Swiz Security (hacking.swizsecurity.com)
"""

import argparse, hashlib, json, os, platform, re, shutil, signal, socket, subprocess, sys
from pathlib import Path
from datetime import datetime

# ─── IoC Definitions 

C2_DOMAINS = ["sfrclak.com", "callnrwise.com"]
C2_IP = "142.11.206.73"
SYSTEM = platform.system()

PAYLOAD_HASHES = {
    # Dropper
    "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09": "Dropper (setup.js)",
    # Windows
    "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101": "Win PS RAT (stage2.ps1)",
    "f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd": "Win persistence (system.bat v1)",
    "e49c2732fb9861548208a78e72996b9c3c470b6b562576924bcc3a9fb75bf9ff": "Win persistence (system.bat v2)",
    "ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c": "Win dropper (6202033.ps1)",
    # macOS
    "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a": "macOS NukeSped RAT (com.apple.act.mond -- universal)",
    "506690fcbd10fbe6f2b85b49a1fffa9d984c376c25ef6b73f764f670e932cab4": "macOS RAT (x86_64)",
    "4465bdeaddc8c049a67a3d5ec105b2f07dae72fa080166e51b8f487516eb8d07": "macOS RAT (ARM64)",
    "5b5fbc627502c5797d97b206b6dcf537889e6bea6d4e81a835e103e311690e22": "macOS RAT variant 2",
    "9c64f1c7eba080b4e5ff17369ddcd00b9fe2d47dacdc61444b4cbfebb23a166c": "macOS RAT v3 (stripped sig)",
    # Linux
    "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf": "Linux RAT (ld.py)",
    # Malicious package tarballs
    "58401c195fe0a6204b42f5f90995ece5fab74ce7c69c67a24c61a057325af668": "plain-crypto-js-4.2.1.tgz",
    "5bb67e88846096f1f8d42a0f0350c9c46260591567612ff9af46f98d1b7571cd": "axios-1.14.1.tgz",
    "59336a964f110c25c112bcc5adca7090296b54ab33fa95c0744b94f8a0d80c0f": "axios-0.30.4.tgz",
    # Shellcode / C2 payloads
    "a224dd73b7ed33e0bf6a2ea340c8f8859dfa9ec5736afa8baea6225bf066b248": "Shellcode payload 1",
    "5e2ab672c3f98f21925bd26d9a9bba036b67d84fde0dfdbe2cf9b85b170cab71": "Shellcode payload 2",
    "20df0909a3a0ef26d74ae139763a380e49f77207aa1108d4640d8b6f14cab8ca": "Shellcode trampoline",
    "e0829aff46c24415fc9b8a346d617ca5877b53cdd80e7a0f92dd877499fbebfe": "C2 response payload",
}

ARTIFACTS = {
    "Darwin":  ["/Library/Caches/com.apple.act.mond"],
    "Windows": [os.path.join(os.environ.get(v, ""), f) for v, f in [
        ("PROGRAMDATA", "wt.exe"), ("PROGRAMDATA", "system.bat"),
        ("TEMP", "6202033.vbs"), ("TEMP", "6202033.ps1")]],
    "Linux":   ["/tmp/ld.py"],
}

PROC_NAMES = {"Darwin": "com.apple.act.mond", "Windows": "wt.exe", "Linux": "ld.py"}
WIN_REG_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
WIN_REG_VALUE = "MicrosoftUpdate"

MALICIOUS_PACKAGES = {
    "axios": ["1.14.1", "0.30.4"], "plain-crypto-js": ["4.2.1"],
    "@shadanai/openclaw": ["2026.3.28-2", "2026.3.28-3", "2026.3.31-1", "2026.3.31-2"],
    "@qqbrowser/openclaw-qbot": ["0.0.130"],
}

# ─── Output 

R, G, Y, C, B, X = "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[1m", "\033[0m"
if SYSTEM == "Windows":
    try: os.system("")
    except: R = G = Y = C = B = X = ""

def found(m):  print(f"  {R}{B}[!] FOUND: {m}{X}")
def ok(m):     print(f"  {G}[✓] Clean: {m}{X}")
def info(m):   print(f"  {C}[i] {m}{X}")
def warn(m):   print(f"  {Y}[~] {m}{X}")
def fixed(m):  print(f"  {G}{B}[+] {m}{X}")
def header(t): print(f"\n{B}{'─'*60}\n  {t}\n{'─'*60}{X}")

# ─── Tracker 

class Tracker:
    def __init__(self):
        self.files = []
        self.dirs = []
        self.pids = []
        self.reg_keys = []
        self.cache = []
        self.count = 0
    def hit(self): self.count += 1
    @property
    def has_remediable(self):
        return bool(self.files or self.dirs or self.pids or self.reg_keys or self.cache)

t = Tracker()

# ─── Helpers 

def sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError): return None

def run(cmd, timeout=15):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return ""

# ─── Scans 

def scan_files():
    header("RAT ARTIFACT SCAN")
    info(f"Platform: {SYSTEM}")

    if SYSTEM == "Darwin":
        for f in Path("/private/tmp").glob(".*") if Path("/private/tmp").exists() else []:
            if f.suffix == ".scpt":
                found(f"Suspicious AppleScript: {f}")
                t.files.append(str(f)); t.hit()

    for path in ARTIFACTS.get(SYSTEM, []):
        if os.path.exists(path):
            found(f"Malicious artifact: {path}")
            t.files.append(path); t.hit()
            h = sha256(path)
            if h and h in PAYLOAD_HASHES: found(f"  Hash match: {PAYLOAD_HASHES[h]}")
            elif h: warn(f"  SHA256: {h} (examine manually)")
        else:
            ok(f"Not found: {path}")


def scan_npm(scan_paths):
    header("NPM PACKAGE SCAN")

    if not scan_paths:
        home = Path.home()
        scan_paths = [home] + [home/d for d in
            ["projects","dev","code","src","repos","workspace","Sites","www","Desktop"]
            if (home/d).exists()]

    info(f"Scanning {len(scan_paths)} path(s) for node_modules...")
    checked, seen = 0, set()

    for root_path in scan_paths:
        for root, dirs, _ in os.walk(root_path, followlinks=False):
            dirs[:] = [d for d in dirs if d not in {".git",".venv","venv","__pycache__",".cache"}]
            if "node_modules" not in dirs: continue

            nm = Path(root) / "node_modules"
            if nm in seen: continue
            seen.add(nm); checked += 1

            # plain-crypto-js directory = strongest signal
            pcs = nm / "plain-crypto-js"
            if pcs.exists():
                found(f"plain-crypto-js found: {pcs}")
                t.dirs.append(str(pcs)); t.hit()
                pkg = pcs / "package.json"
                if pkg.exists():
                    try:
                        v = json.loads(pkg.read_text()).get("version","?")
                        found(f"  version: {v}")
                        if v == "4.2.0":
                            warn("  Shows 4.2.0 — dropper already ran and self-cleaned")
                    except: pass
                sjs = pcs / "setup.js"
                if sjs.exists():
                    found(f"  Dropper present: {sjs}")
                    h = sha256(str(sjs))
                    if h and h in PAYLOAD_HASHES: found(f"  Hash confirmed: {PAYLOAD_HASHES[h]}")
                else:
                    warn("  setup.js gone — dropper self-deleted after execution")

            # Lockfile check
            for lf in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]:
                lp = Path(root) / lf
                if not lp.exists(): continue
                try:
                    content = lp.read_text()
                    for ver in ["1.14.1", "0.30.4"]:
                        # Match axios adjacent to version — avoids false positives
                        # from unrelated packages (e.g. @emotion/styled@11.14.1)
                        if re.search(rf'axios[/@\-]{re.escape(ver)}', content):
                            found(f"Lockfile refs axios@{ver}: {lp}"); t.hit()
                    if "plain-crypto-js" in content:
                        found(f"Lockfile refs plain-crypto-js: {lp}"); t.hit()
                except: pass

            # axios package.json
            apkg = nm / "axios" / "package.json"
            if apkg.exists():
                try:
                    data = json.loads(apkg.read_text())
                    v = data.get("version","")
                    if v in ("1.14.1","0.30.4"):
                        found(f"Compromised axios@{v}: {apkg.parent}"); t.hit()
                    if "plain-crypto-js" in data.get("dependencies",{}):
                        found(f"axios depends on plain-crypto-js: {apkg}"); t.hit()
                except: pass

            dirs.remove("node_modules")

    info(f"Scanned {checked} node_modules director{'y' if checked==1 else 'ies'}" if checked else
         "No node_modules found")


def scan_network():
    header("NETWORK CONNECTION SCAN")

    for domain in C2_DOMAINS:
        try:
            ip = socket.getaddrinfo(domain, None)[0][4][0]
            warn(f"C2 domain resolves: {domain} -> {ip}")
            warn("  (Infra is up — does NOT mean you're infected)")
        except socket.gaierror:
            info(f"C2 domain down: {domain}")

    info("Checking active connections to C2...")
    cmd = ["netstat","-ano"] if SYSTEM == "Windows" else ["lsof","-i","-nP"]
    output = run(cmd)
    if not output:
        warn("Could not check connections (permissions or tool missing)"); return

    if C2_IP in output:
        found(f"Active connection to C2 IP {C2_IP}!")
        t.hit()
        for line in output.splitlines():
            if C2_IP not in line: continue
            found(f"  {line.strip()}")
            parts = line.split()
            try: t.pids.append(int(parts[-1] if SYSTEM == "Windows" else parts[1]))
            except (ValueError, IndexError): pass
    else:
        ok(f"No connections to {C2_IP}")

    for domain in C2_DOMAINS:
        if domain in output:
            found(f"Connection to C2 domain {domain}!"); t.hit()


def scan_processes():
    header("PROCESS SCAN")
    proc_name = PROC_NAMES.get(SYSTEM)
    if not proc_name: return

    cmd = ["tasklist","/FO","CSV"] if SYSTEM == "Windows" else ["ps","aux"]
    output = run(cmd, 10)
    if not output: warn("Could not enumerate processes"); return

    if proc_name in output:
        found(f"Suspicious process: {proc_name}"); t.hit()
        for line in output.splitlines():
            if proc_name not in line: continue
            found(f"  {line.strip()}")
            parts = line.split()
            try: t.pids.append(int(parts[1].strip('"').strip(',')))
            except (ValueError, IndexError): pass
    else:
        ok(f"Process not found: {proc_name}")

    # Node spawning suspicious children
    if SYSTEM != "Windows":
        ps = run(["ps","-eo","ppid,pid,comm"], 10)
        if not ps: return
        lines = ps.splitlines()
        node_pids = {p[1].strip() for p in (l.split() for l in lines) if len(p)>=3 and "node" in p[2]}
        if node_pids:
            suspect = {"curl","osascript","cscript","python3","python","sh","bash"}
            for line in lines:
                p = line.split()
                if len(p)>=3 and p[0].strip() in node_pids and p[2].split("/")[-1] in suspect:
                    warn(f"Node spawning {p[2].split('/')[-1]} (PID {p[1]}) — matches attack chain")


def scan_registry():
    if SYSTEM != "Windows": return
    header("REGISTRY PERSISTENCE SCAN")
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
        try:
            val, _ = winreg.QueryValueEx(key, WIN_REG_VALUE)
            found(f"Registry persistence: {WIN_REG_KEY}\\{WIN_REG_VALUE}")
            found(f"  Value: {val}")
            t.reg_keys.append(WIN_REG_VALUE); t.hit()
        except FileNotFoundError:
            ok(f"No '{WIN_REG_VALUE}' in Run key")
        winreg.CloseKey(key)
    except Exception as e: warn(f"Registry check: {e}")


def scan_caches():
    header("PACKAGE MANAGER CACHE SCAN")
    home = Path.home()
    caches = [(n,p) for n,p in [
        ("npm", home/".npm"), ("yarn", home/".cache"/"yarn"),
        ("yarn", home/"Library"/"Caches"/"Yarn"),
        ("pnpm", home/".local"/"share"/"pnpm"/"store"),
    ] if p.exists()]

    if not caches: info("No package manager caches found"); return

    for name, path in caches:
        info(f"Scanning {name} cache...")
        try:
            for root, _, files in os.walk(path):
                if "package.json" not in files: continue
                fp = os.path.join(root, "package.json")
                try:
                    content = Path(fp).read_text()
                    if '"plain-crypto-js"' in content:
                        found(f"plain-crypto-js in {name} cache: {fp}")
                        t.cache.append(fp); t.hit()
                    data = json.loads(content)
                    n, v = data.get("name",""), data.get("version","")
                    if n in MALICIOUS_PACKAGES and v in MALICIOUS_PACKAGES[n]:
                        found(f"Malicious {n}@{v} in {name} cache")
                        t.cache.append(os.path.dirname(fp)); t.hit()
                except: pass
        except PermissionError: warn(f"Permission denied: {name} cache")

    if not t.cache: ok("Caches clean")


def scan_dns():
    header("DNS CACHE SCAN")
    if SYSTEM == "Darwin":
        info("Checking macOS DNS logs...")
        out = run(["log","show","--predicate",
            'processImagePath contains "mDNSResponder" AND eventMessage contains "sfrclak"',
            "--last","24h","--style","compact"], 30)
        if "sfrclak" in out: found("DNS lookup for sfrclak.com in logs!"); t.hit()
        else: ok("No C2 DNS lookups in last 24h")
    elif SYSTEM == "Windows":
        out = run(["ipconfig","/displaydns"])
        hits = [d for d in C2_DOMAINS if d in out]
        for d in hits: found(f"C2 domain {d} in DNS cache!"); t.hit()
        if not hits: ok("No C2 domains in DNS cache")
    elif SYSTEM == "Linux":
        info("Check manually: journalctl -u systemd-resolved --since '24h ago' | grep sfrclak")


# ─── Remediation 

def remediate():
    header("REMEDIATION")
    if not t.has_remediable:
        info("No remediable artifacts. Manual review recommended for DNS/lockfile hits.")
        return

    print(f"\n  {R}{B}The following actions will be performed:{X}\n")
    n = 1
    all_pids = list(set(t.pids))

    actions = [
        (all_pids, "KILL PROCESSES", lambda p: f"Send SIGKILL to PID {p}"),
        (t.files,  "DELETE FILES",   lambda f: f"Delete: {f}"),
        (t.dirs,   "DELETE DIRS",    lambda d: f"Remove tree: {d}"),
        (t.reg_keys, "REMOVE REGISTRY", lambda k: f"Delete: {WIN_REG_KEY}\\{k}"),
        (t.cache,  "CLEAN CACHES",   lambda p: f"Remove: {p}"),
    ]
    for items, label, fmt in actions:
        if not items: continue
        print(f"  {Y}{n}. {label}{X}")
        for item in items: print(f"     - {fmt(item)}")
        if label == "CLEAN CACHES":
            print(f"     - npm cache clean --force")
            print(f"     - yarn cache clean / pnpm store prune")
        n += 1; print()

    print(f"  {R}{B}{'─'*54}")
    print(f"  WARNING: These actions are IRREVERSIBLE.")
    print(f"  Deleted files cannot be recovered.")
    print(f"  Killed processes cannot be restarted by this tool.")
    print(f"  {'─'*54}{X}\n")
    print(f"  Type {B}CONFIRM{X} to proceed, or anything else to abort.\n")

    try: resp = input(f"  {C}> {X}").strip()
    except (EOFError, KeyboardInterrupt): print(); info("Aborted."); return
    if resp != "CONFIRM":
        info(f"Aborted. Got '{resp}' — need exactly 'CONFIRM'."); return

    print(); info("Remediating...\n")
    log = []
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Kill processes
    for pid in all_pids:
        try: os.kill(pid, signal.SIGKILL); fixed(f"Killed PID {pid}"); log.append(f"Killed PID {pid}")
        except ProcessLookupError: warn(f"PID {pid} already gone"); log.append(f"PID {pid} already dead")
        except PermissionError: warn(f"Permission denied: PID {pid}"); log.append(f"FAILED: PID {pid}")

    # Delete files
    for fp in t.files:
        try: os.remove(fp); fixed(f"Deleted: {fp}"); log.append(f"Deleted: {fp}")
        except FileNotFoundError: warn(f"Already gone: {fp}")
        except PermissionError: warn(f"Permission denied: {fp}"); log.append(f"FAILED: {fp}")

    # Delete directories
    for dp in t.dirs:
        try: shutil.rmtree(dp); fixed(f"Removed: {dp}"); log.append(f"Removed dir: {dp}")
        except FileNotFoundError: warn(f"Already gone: {dp}")
        except PermissionError: warn(f"Permission denied: {dp}"); log.append(f"FAILED: {dp}")

    # Registry
    if t.reg_keys and SYSTEM == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            for v in t.reg_keys:
                try: winreg.DeleteValue(key, v); fixed(f"Removed registry: {v}"); log.append(f"Reg: {v}")
                except: warn(f"Could not remove: {v}")
            winreg.CloseKey(key)
        except Exception as e: warn(f"Registry error: {e}")

    # Caches
    if t.cache:
        for p in t.cache:
            try:
                (shutil.rmtree if os.path.isdir(p) else os.remove)(p)
                fixed(f"Cleaned: {p}"); log.append(f"Cleaned: {p}")
            except Exception as e: warn(f"Failed: {p} — {e}")
        for cmd, name in [("npm cache clean --force","npm"),("yarn cache clean","yarn"),("pnpm store prune","pnpm")]:
            try: subprocess.run(cmd.split(), capture_output=True, timeout=30); fixed(f"Ran {name} cache clean")
            except: pass

    # Write log
    lp = Path.home() / "axios-ioc-remediation.log"
    try:
        with open(lp, "a") as f:
            f.write(f"\n{'='*60}\nAxios IoC Remediation — {ts}\n{'='*60}\n")
            for e in log: f.write(f"[{ts}] {e}\n")
        fixed(f"Log: {lp}")
    except: pass

    print(f"""
  {G}{B}
  ╔══════════════════════════════════════════════════╗
     REMEDIATION COMPLETE                            
  ╚══════════════════════════════════════════════════╝{X}

  {R}{B}YOU MUST STILL:{X}
  1. Rotate ALL credentials, API keys, tokens, secrets
  2. Revoke and regenerate npm tokens
  3. Audit CI/CD runs during exposure window (Mar 31 00:21-03:15 UTC)
  4. Check git history for unauthorized commits
  5. Notify your security team

  {Y}Assume all env vars were exfiltrated.{X}
""")


# ─── Report 

def report(do_remediate):
    header("SCAN COMPLETE")
    print(f"\n  {datetime.now():%Y-%m-%d %H:%M:%S} | {SYSTEM} ({platform.node()}) | {platform.platform()}\n")

    if t.count == 0:
        print(f"""  {G}{B}
  ╔══════════════════════════════════════════════╗
    NO INDICATORS OF COMPROMISE DETECTED        
    Your system appears clean.                  
  ╚══════════════════════════════════════════════╝{X}

  If you ran npm install during the exposure window
  (March 31 00:21 — 03:15 UTC), consider:
  - Verify lockfiles don't reference affected versions
  - npm cache clean --force
  - Rotate secrets as a precaution""")
    else:
        print(f"""  {R}{B}
  ╔══════════════════════════════════════════════╗
    {t.count:>2} INDICATOR(S) OF COMPROMISE FOUND        
    YOUR SYSTEM MAY BE COMPROMISED              
  ╚══════════════════════════════════════════════╝{X}""")
        if not do_remediate:
            print(f"""
  {Y}Run again with --remediate to clean up:{X}
  python3 {sys.argv[0]} --remediate

  {R}IMMEDIATE ACTIONS:{X}
  1. Disconnect from network
  2. Rotate ALL credentials, API keys, tokens, secrets
  3. npm install axios@1.14.0
  4. rm -rf node_modules/plain-crypto-js
  5. npm cache clean --force
  6. Audit CI/CD pipelines
  7. Check git history
  8. Report to security team

  {Y}Assume all env vars were exfiltrated.{X}""")

    print(f"""
  {C}References:{X}
  - GHSA-fw8c-xr5c-95f9 | MAL-2026-2306
  - https://socket.dev/blog/axios-npm-package-compromised
  - https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package
""")


# ─── Main 

def main():
    p = argparse.ArgumentParser(description="Axios supply chain IoC scanner")
    p.add_argument("--scan-path", nargs="*", help="Path(s) to scan (default: ~)")
    p.add_argument("--quick", action="store_true", help="Skip cache + DNS checks")
    p.add_argument("--remediate", action="store_true", help="Remove artifacts (asks for confirmation)")
    args = p.parse_args()

    print(f"""
{C}{B}
╔══════════════════════════════════════════════════════════════╗
          AXIOS SUPPLY CHAIN ATTACK — IoC SCANNER 

  Advisory: GHSA-fw8c-xr5c-95f9 | Affected: axios 1.14.1 

  **Compromise occurred on 03-31-2026**

  North Korean-based C2: sfrclak[.]com / 142.11.206.73:8000 

  github.com/0xxyc           hacking.swizsecurity.com         
╚══════════════════════════════════════════════════════════════╝{X}
""")
    info(f"{datetime.now():%Y-%m-%d %H:%M:%S} | {SYSTEM} {platform.release()}" +
         (" | REMEDIATE MODE" if args.remediate else ""))

    scan_files()
    scan_npm([Path(p) for p in args.scan_path] if args.scan_path else None)
    scan_network()
    scan_processes()
    scan_registry()
    if not args.quick:
        scan_caches()
        scan_dns()

    report(args.remediate)
    if args.remediate and t.count > 0: remediate()
    sys.exit(1 if t.count > 0 else 0)

if __name__ == "__main__":
    main()