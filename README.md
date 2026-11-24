# Feverfew

Feverfew is a free Windows diagnostics tool. Run it once to get a single report on a PC's hardware, firmware, drivers and recent crashes, with likely problems and suggested fixes at the top. Use it to troubleshoot your own PC, support someone else's, or keep a record of a machine's health.

Named after feverfew, a daisy-like flower long used as a home remedy.

## Using it

1. Download `setup.exe` from the [latest release](https://github.com/TessArdent/feverfew/releases/latest) and run it. No admin rights are needed to install.
2. Open Feverfew and accept the Windows permission prompt, then press **Run diagnostics**. A scan takes under a minute.
3. Press **Show file to send** and send that `.html` file to whoever is helping.

Reports are saved in `Feverfew Reports` in your Documents folder.

From 1.4.0, `setup.exe` is signed (and timestamped) by the publisher's own code-signing authority, not one Windows already knows. Windows doesn't trust that authority, so on your PC SmartScreen may still warn about it or show "Unknown publisher". Choose **More info**, then **Run anyway**. Feverfew checks the signature itself when it updates (see [Updates](#updates)). Versions up to 1.3.0 weren't signed. Each release lists the file's SHA-256 hash so you can check your download.

## What it collects

| Area | Details |
| --- | --- |
| Motherboard and BIOS | Maker, model, revision, BIOS version and date, UEFI or Legacy boot, Secure Boot |
| Boot and Secure Boot | Setup Mode, platform key, allowed and revoked signature counts, trusted certificates, the BIOS's default keys, Windows' Secure Boot certificate update status, firmware boot entries, EFI boot loaders and who signed them, and whether the firmware trusts the Windows boot file |
| TPM and security | TPM version, maker and state, BitLocker on or off and whether each drive has a recovery password, virtualization-based security, antivirus, firewall |
| Processor and memory | CPU model, cores, live speed and load, virtualization (including when Windows' own hypervisor uses it), each RAM module, rated speed (from the part number when Windows reports only the fallback speed), actual speed, slots used, soldered memory |
| Graphics and devices | GPU and driver details (with real driver dates, and placeholder dates marked), virtual display adapters, each monitor's connection, resolution and refresh rate, monitors plugged into the motherboard instead of the graphics card, sound, USB devices, devices with errors, third-party drivers, third-party kernel drivers that belong to no device (antivirus, VPN, anti-cheat), third-party device filter drivers (with a warning when one points at a missing driver), and the drivers Windows logged as keeping memory integrity off |
| Storage | Drive type and health, SMART failure prediction, NVMe health read straight from the drive (temperature, wear, spare, media errors, unsafe shutdowns, power-on hours, lifetime data written and its rate per power-on hour, with a note when heavy writing explains fast wear), GPT or MBR for each disk, every partition (including EFI and recovery), unallocated space, fixed and removable volumes, free space |
| Windows | Edition, build, activation, uptime, pending restarts, recent updates, power settings, Fast Startup, System Protection and restore points, the recovery environment |
| Software | Installed programs, startup programs, stopped services (with ones that normally stop by themselves marked), top memory use |
| Crashes | Blue screen stop codes, repeated stop codes, the driver each crash dump points to, the events leading up to each unexpected restart, drivers logging large numbers of errors, hardware (WHEA) errors by source, disk errors for each disk, CPU throttling, graphics driver resets, program crashes, last 30 days of event log errors (with usually harmless ones marked) |
| Network | Adapters and their type, addresses, DNS, proxy, router, VPNs carrying internet traffic, IP address conflicts, Wi-Fi adapter failures, internet and name lookup tests |
| Gaming | Power plan, Game Mode, background recording, GPU scheduling, memory integrity, connection type, latency, jitter and packet loss, TCP and network adapter settings, NVIDIA power, PCIe and Resizable BAR details, AMD driver details, each monitor's refresh rate |
| AMD drive writes | Whether AMD's driver is constantly rewriting a file on the Windows drive (a known bug fixed in AMD Software 26.11.1), its write rate, and an estimate of what it has written to each drive and how much SSD wear that caused |
| Battery | Charge, wear, cycles, a note when it holds under 80% of its design capacity (laptops) |
| Windows 11 | Readiness for each hardware requirement, except Microsoft's supported CPU list |

The report comes as an `.html` file to read and a `.json` file with the same content for scripts.

## Privacy

- **Nothing is uploaded.** Feverfew has no telemetry. A scan's only network traffic is the connection tests: pings to the router and to `1.1.1.1` (about 20 each, to measure latency), and a name lookup for `www.microsoft.com`. Use `--no-network` to skip it. **Check for updates** contacts GitHub only when you press it, and sends no report data.
- **Identifiers are hidden by default.** Serial numbers, the system UUID, computer and user names, Windows account IDs, drive labels, MAC addresses, public IP addresses, and email addresses in log messages become `[hidden]`. Tick the checkbox to keep them, for example for a warranty claim.
- **Feverfew never reads** product keys, BitLocker recovery keys, passwords, browser data or personal files. It checks only whether a BitLocker drive has a recovery password, never the password itself.
- **Reports still say a lot about a PC.** The installed programs list, for one, is included even with identifiers hidden. Only send a report to someone you trust, and glance through it first if that matters to you.

## Repair tools

**Repair tools** lists the usual fixes. Each one runs in its own administrator window, only when you press **Run**. Fixes that need a restart or change settings ask first. Every report also lists these commands, so whoever is helping can see the options.

| Fix | Command |
| --- | --- |
| Create a restore point | `Checkpoint-Computer` |
| Check or repair the Windows image | `DISM /Online /Cleanup-Image /CheckHealth`, `/RestoreHealth` |
| Repair system files | `sfc /scannow` |
| Scan or repair the Windows drive | `chkdsk %SystemDrive% /scan`, `/f` |
| Test the memory | `mdsched.exe` |
| Clear the DNS cache | `ipconfig /flushdns` |
| Reset network settings | `netsh winsock reset`, `netsh int ip reset` |
| Reset Windows Update | Stops its services and renames its cache folders |
| Stop AMD's constant drive writes | `icacls` denies Windows' SYSTEM account write access to the one file AMD's External Events Utility keeps copying over. Undo removes it. |

## Gaming

**Gaming** lists optional changes and shows whether each is worth applying on this PC. Each one runs in its own administrator window, only when you press **Apply**, and most have an **Undo** that returns to the setting you had before. The page also suggests settings to check in NVIDIA or AMD's own app, because Feverfew can't safely change those. Feverfew leaves out popular tweaks with no reliable benefit, and doesn't offer to turn off security features such as memory integrity.

| Option | Command |
| --- | --- |
| High performance power plan | `powercfg /setactive SCHEME_MIN` |
| Game Mode, background recording, GPU scheduling | `reg add` on the matching Windows setting |
| Turn off Energy Efficient Ethernet | `Set-NetAdapterAdvancedProperty` on `*EEE` |
| Restore default TCP settings | `netsh int tcp set global autotuninglevel=normal`, `rss=enabled`, `netsh int tcp set heuristics disabled` |
| Restore default multimedia settings | `reg add` on `NetworkThrottlingIndex` and `SystemResponsiveness` |

## Updates

**Check for updates** looks at this repository's latest release. If there's a newer version, Feverfew offers to download `setup.exe` and runs it only if both checks pass:

- its SHA-256 matches the hash GitHub publishes for that file, which protects the download;
- it carries an intact Authenticode signature from a code-signing certificate issued by the publisher's own root CA, whose public certificate is built into Feverfew. This protects against a changed release, because a changed release can't carry that signature.

If either check fails, Feverfew deletes the file, says why and links to the release page. The root isn't trusted by Windows, so Windows doesn't show the installer as signed by a known publisher. Feverfew does its own check against the built-in root.

Versions up to 1.3.0 check only the hash, so the first signed release installs through them as before. Every later version refuses unsigned updates. To ship an update, publish a GitHub release with a **signed** `setup.exe` asset and a tag like `v1.4.0`.

## Command line

```text
Feverfew.exe --cli [--out <folder>] [--include-identifiers] [--no-network]
Feverfew.exe --check-update
```

Run it from an elevated prompt for a full scan. Without administrator rights it still runs, but can't read the TPM, BitLocker, SMART prediction, restore points or crash dumps, and the report says so.

## Building

You need the [.NET SDK](https://dotnet.microsoft.com/download) (8 or later) and [Inno Setup 6](https://jrsoftware.org/isinfo.php).

```powershell
.\build.ps1
```

This creates `dist\setup.exe`. `.\test.ps1` builds and runs the tests (it needs the Windows SDK's signtool) and prints PASS or FAIL. The app targets .NET Framework 4.8, which comes with current Windows 10 and 11, so friends don't have to install a runtime.

## License

Proprietary. All rights reserved. See [LICENSE](LICENSE).
