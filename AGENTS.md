# Feverfew

A Windows diagnostics tool (WPF, .NET Framework 4.8). It collects hardware and software diagnostics into one shareable HTML/JSON report, offers a few fixes, and updates itself from GitHub releases. User-facing docs: `README.md`.

## Build and test

- `.\test.ps1` builds the app and the tests and runs them. The last line is PASS or FAIL. It needs the .NET SDK and signtool at `C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe`.
- `.\build.ps1` builds the release installer `dist\setup.exe` (Inno Setup 6) and signs it in two `hawthorn sign` batches: Feverfew.exe before packing, then setup.exe. It finds `hawthorn` on PATH or at `~\bin\hawthorn.cmd`, and needs a registered YubiKey plugged in and asks for its PIN once per batch. `-Unsigned` builds without the key, and `hawthorn release` refuses that build. An agent may start a signed build when the user or the card asks. `hawthorn sign` then asks for the PIN in a desktop dialog that only the user types into: agents never ask for, type, relay or store the PIN. Unasked, agents use `-Unsigned`.

## Key folders

- `src/Feverfew/`: the app. `Program.cs` is the entry point and CLI, `MainWindow.xaml.cs` the UI, `Scanner.cs` runs `src/Feverfew/Collectors/`, `HtmlReport.cs` writes the report, `Fixes.cs` holds the fixes. `src/Feverfew/Collectors/FilterCollector.cs` lists device filter drivers and memory integrity blockers (read-only: Feverfew never removes drivers).
- `src/Feverfew/Updater.cs` and `src/Feverfew/SignatureCheck.cs`: the update check, download and the per-user toggles (`UpdateSettings`, HKCU `Software\Feverfew`). `src/Feverfew/UpdatePlan.cs` holds the pure parts (release JSON, accepted download address, launch decision, silent installer arguments) and is tested in `tests/Feverfew.Tests/Updates.cs`. An automatic update runs setup with `/SILENT /relaunch=yes`; the `RelaunchAfterUpdate` check in `installer/setup.iss` reopens the app.
- `src/Feverfew/Trust/`: the publisher's code-signing root certificate(s), embedded in the exe.
- `tests/Feverfew.Tests/`: a headless console test exe that prints PASS or FAIL per case. It links app source files; it doesn't reference the WPF project. To test a collector's logic, put it in a pure file (no WMI, registry or event log), such as `src/Feverfew/Collectors/FastStartupResume.cs`, link that file in the test `.csproj`, and test it in `tests/Feverfew.Tests/Diagnostics.cs`.
- `installer/setup.iss`: the Inno Setup script.

## Rules

- **Updates install only if they're signed by the publisher.** `Updater.Download` refuses, deletes and explains, with a link to the release page, unless all of these hold:
  - the SHA-256 matches GitHub's digest;
  - WinVerifyTrust finds the signature intact (only untrusted-root and partial-chain results are allowed, because users' PCs don't trust the private root);
  - the signer chains to a root in `Trust` that matches byte for byte;
  - the leaf has the Code Signing EKU.

  Never weaken this, and never fall back to "hash only". With no root embedded, every update is refused.
- `Trust` holds **public** `.cer` files only, never a `.pfx` or a key. To rotate or add a root, add its `.cer` there. Old versions trust only the roots they shipped with, so release under the new root only after a release that pins it.
- Tests must not add certificates to the user's stores or leave key containers behind. Sign with signtool's `/dg` and `/di` digest flow and keep the key in memory. `signtool /f some.pfx` persists a CNG key under `%APPDATA%\Microsoft\Crypto\Keys` on every call.
- Releases are signed (Hawthorn's `hawthorn sign`). Commit with `hawthorn commit`. Don't push or release unless asked.

## Traps

- GitHub returns the repo as `TessArdent/Feverfew`. A case-sensitive compare against another casing silently turned every update into a link to the release page (DI-18), so `UpdatePlan.IsReleaseAsset` ignores case.
- `X509VerificationFlags.AllowUnknownCertificateAuthority` also accepts a *partial* chain that ends at the leaf. That's why `SignatureCheck` compares the chain's last element with the pinned root instead of trusting `Build()`.
- Never launch the built exe or installer to check it: it opens a window on the user's desktop. Inspect the installer with innounp or 7-Zip, and check signatures with `hawthorn sign --verify`.
- signtool won't sign with a certificate whose EKU leaves out code signing. To test a "no Code Signing EKU" leaf, make it with no EKU extension at all.
