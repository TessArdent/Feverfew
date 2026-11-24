# Device filters and memory integrity blockers (DI-15)

**Decision.** `FilterCollector` adds the section "Filter drivers and memory integrity". The classification is pure, in `FilterDriverAudit`.

**Filters.**
- It reads `UpperFilters` and `LowerFilters` on these class keys: USB, HID, keyboard, mouse, disk, volume, CD/DVD, network, camera, imaging, and sound/video/game controllers. It also reads them on every present device's Enum key (from `Win32_PnPEntity`).
- Each filter's service is checked: its Services key; its file (from ImagePath, or `System32\drivers\<name>.sys` when there's none); the file's company; and whether `Win32_SystemDriver` says it's running.
- Microsoft's filters are left out by the file's company. A filter whose service or file is missing is always shown, whoever made it, because that's the state that stops devices from starting.
- Severity: a missing driver is a Warning, and the detail says a class-wide one can stop every device in the class. A third-party filter that isn't running is Info.

**Memory integrity blockers: source.** The Microsoft-Windows-CodeIntegrity/Operational log, events:
- 3087 and 3111: "… is not compatible with hypervisor enforcement";
- 3072: non-page-aligned sections;
- 3073: an executable section that is also writable.

The module path is the second value (%2) in every version of these events. That's from the provider's own message catalog (`Get-WinEvent -ListProvider Microsoft-Windows-CodeIntegrity`), which Windows ships. Microsoft's public pages on Code Integrity events document 3076 and 3077 but not these, so the catalog is the authority.

**Limits.**
- Windows logs these only when it checks a driver, for example when the user tries to turn memory integrity on, or when such a driver loads. A driver never checked isn't listed.
- The log rolls over, so an empty list doesn't prove nothing blocks memory integrity. The section note says so.
- Old events can name drivers since removed. Each entry is checked against the file on disk and the installed driver services. Only drivers still installed are named in the finding; the rest show in the table as "Still installed: No".
- Windows Security's Core isolation page has its own incompatible-driver scan. Its results aren't exposed through any documented API we found, so we don't read it.

**Read-only.** Feverfew lists and advises; it never removes a driver or edits filter values. The advice says to use the program's own uninstaller first. Deleting a filter's driver while it's still listed in LowerFilters can stop the keyboard and mouse from starting.

**Privacy.** Code Integrity paths are kernel paths (`\Device\HarddiskVolumeN\Users\<name>\…`). The Redactor's user-folder rule now covers those as well as `C:\Users\<name>`.
