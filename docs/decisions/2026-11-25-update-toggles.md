# Launch update check and automatic updates (DI-18)

**Decision.** Two per-user toggles on the Updates page, both off by default: check at launch and say so, and install automatically at launch. Automatic install implies the check.

**Why off by default.** Feverfew promised it contacts GitHub only when asked. Turning either on is the user's choice, and the page text says so.

**Why automatic install still needs everything.** It goes through the same `Updater.Download` (digest, WinVerifyTrust, pinned root, Code Signing EKU). Nothing is relaxed for the unattended path. If the download can't be verified, or this copy isn't the per-user install under `%LOCALAPPDATA%\Programs\Feverfew` (for example, a different admin account approved the UAC prompt), it only notifies.

**Why it waits for a scan.** The window closes to let setup replace the exe. If the user started a scan during the download, a bar offers "Install now" instead.

**Reopening.** Inno's existing "Open Feverfew now" entry is `skipifsilent`, so manual silent installs stay quiet. A separate `[Run]` entry runs only when setup is silent and gets `/relaunch=yes`, which only Feverfew passes.

**Settings location.** HKCU `Software\Feverfew` (`NotifyOnLaunch`, `AutoUpdate` DWORDs) of the account the app runs as.
