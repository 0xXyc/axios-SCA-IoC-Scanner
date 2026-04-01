# axios Supply Chain Attack — IoC Scanner & Remediator

On March 31, 2026, an attacker compromised the npm account of the lead axios maintainer and published two malicious versions — `axios@1.14.1` and `axios@0.30.4` — both injecting a dependency called `plain-crypto-js` that drops a cross-platform RAT on your system.

axios gets ~100 million downloads a week and is present in roughly 80% of cloud environments, so the blast radius here is massive. The malicious versions were only live for about 3 hours, but the first infection landed 89 seconds after publish. If your CI/CD uses caret ranges (`^1.x`), you could've pulled the compromised version without even knowing.

This script scans your system for indicators of compromise and can optionally nuke anything it finds.

## What It Checks

- **File artifacts** — OS-specific RAT binaries (`com.apple.act.mond` on macOS, `wt.exe`/`system.bat` on Windows, `/tmp/ld.py` on Linux)
- **npm packages** — recursively walks your projects looking for `plain-crypto-js` in `node_modules`, compromised axios versions in lockfiles, the works
- **Network** — active connections to the C2 at `142.11.206.73:8000` and DNS resolution of `sfrclak.com` / `callnrwise.com`
- **Processes** — running RAT processes and suspicious node child process chains
- **Registry** (Windows) — checks for `HKCU\...\Run\MicrosoftUpdate` persistence
- **Package caches** — npm, yarn, and pnpm caches for cached copies of the malicious packages
- **DNS cache/logs** — checks if your machine ever resolved the C2 domains

## Usage

```bash
# Basic scan (scans your home directory for node_modules)
python3 axios-ioc-scanner.py

# Scan specific project directories
python3 axios-ioc-scanner.py --scan-path /path/to/projects /other/path

# Quick scan (skips cache and DNS checks)
python3 axios-ioc-scanner.py --quick

# Scan AND remediate (kills processes, deletes artifacts, cleans caches)
python3 axios-ioc-scanner.py --remediate
```

Zero dependencies — stdlib only. Works on macOS, Windows, and Linux.

When you use `--remediate`, the script will show you exactly what it's about to do and ask you to type `CONFIRM` before it touches anything. Nothing gets deleted without your explicit go-ahead.

## IoCs

| Indicator | Value |
|---|---|
| Malicious packages | `axios@1.14.1`, `axios@0.30.4`, `plain-crypto-js@4.2.1` |
| C2 domain | `sfrclak[.]com`, `callnrwise[.]com` |
| C2 IP | `142.11.206.73:8000` |
| C2 endpoint | `/6202033` (reversed = 3-30-2026, date of attack) |
| macOS artifact | `/Library/Caches/com.apple.act.mond` |
| Windows artifacts | `%PROGRAMDATA%\wt.exe`, `%PROGRAMDATA%\system.bat` |
| Linux artifact | `/tmp/ld.py` |
| Win registry persistence | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate` |
| User-Agent | `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)` |

## Advisory

- **GHSA-fw8c-xr5c-95f9**
- **MAL-2026-2306**

## References

- [Socket.dev](https://socket.dev/blog/axios-npm-package-compromised)
- [Huntress](https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package)
- [Wiz](https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack)
- [Snyk](https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/)
- [Semgrep](https://semgrep.dev/blog/2026/axios-supply-chain-incident-indicators-of-compromise-and-how-to-contain-the-threat/)
- [StepSecurity](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)
- [The Hacker News](https://thehackernews.com/2026/03/axios-supply-chain-attack-pushes-cross.html)
- [SANS](https://www.sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan)
