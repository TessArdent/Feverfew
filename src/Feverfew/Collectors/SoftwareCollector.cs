using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using Microsoft.Win32;

namespace Feverfew.Collectors
{
    public static class SoftwareCollector
    {
        private static readonly string[] EssentialServices = { "RpcSs", "EventLog", "Winmgmt", "Dhcp", "Dnscache", "BFE", "mpssvc", "AudioSrv", "LanmanWorkstation" };

        public static void Security(Report r)
        {
            var s = r.NewSection("Protection and updates");

            Guard.Try(s, "Antivirus", () =>
            {
                var t = s.Table("Antivirus", "Product", "Active", "Definitions current");
                var products = Wmi.Query(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct");
                bool anyOn = false;
                foreach (var a in products)
                {
                    var state = (int)(a.Long("productState") ?? 0);
                    bool on = (((state >> 8) & 0xFF) & 0x10) != 0;
                    bool current = (state & 0xFF) == 0;
                    anyOn |= on;
                    t.Rows.Add(new[] { a.Str("displayName"), on ? "Yes" : "No", current ? "Yes" : "No" });
                }
                if (!anyOn)
                    r.Find(Severity.Warning, "No active antivirus reported", "Windows Security Center doesn't list an active antivirus.", "Check Windows Security > Virus & threat protection.");
            });

            Guard.Try(s, "Firewall", () =>
            {
                const string root = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\";
                var off = new List<string>();
                foreach (var p in new[] { "Domain", "Standard", "Public" })
                {
                    var v = Reg.Machine(root + p + "Profile", "EnableFirewall");
                    var on = v != null && Convert.ToInt32(v) == 1;
                    var label = p == "Standard" ? "Private" : p;
                    s.Add("Firewall (" + label + " networks)", v == null ? "Unknown" : on ? "On" : "Off");
                    if (v != null && !on) off.Add(label);
                }
                if (off.Count > 0)
                    r.Find(Severity.Warning, "Firewall is off", "Off for: " + string.Join(", ", off) + " networks. Third-party security software sometimes does this on purpose.", "Check Windows Security > Firewall & network protection.");
            });

            Guard.Try(s, "System Protection", () => SystemProtection(r, s));
            Guard.Try(s, "Recovery environment", () => RecoveryEnvironment(r, s));

            Guard.Try(s, "Windows updates", () =>
            {
                var fixes = Wmi.Cim("SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering")
                    .Select(f => new { Id = f.Str("HotFixID"), Kind = f.Str("Description"), When = ParseDate(f.Str("InstalledOn")) })
                    .OrderByDescending(f => f.When ?? DateTime.MinValue).ToList();
                var t = s.Table("Latest Windows updates", "Update", "Type", "Installed");
                foreach (var f in fixes.Take(15)) t.Rows.Add(new[] { f.Id, f.Kind, Fmt.Date(f.When) });
                var last = fixes.Select(f => f.When).FirstOrDefault(d => d != null);
                if (last != null && (DateTime.Now - last.Value).TotalDays > 75)
                    r.Find(Severity.Warning, "Windows hasn't updated recently", "The newest update was installed on " + Fmt.Date(last) + ".", "Run Windows Update and look for errors.");
            });

            Guard.Try(s, "Power settings", () =>
            {
                var plan = Wmi.Query(@"root\cimv2\power", "SELECT ElementName, IsActive FROM Win32_PowerPlan").FirstOrDefault(p => p.Bool("IsActive") == true);
                if (plan != null) s.Add("Power plan", plan.Str("ElementName"));
            });

            // Separate from the power plan, which needs admin rights to read.
            Guard.Try(s, "Fast Startup", () =>
            {
                var fast = Reg.Machine(@"SYSTEM\CurrentControlSet\Control\Session Manager\Power", "HiberbootEnabled");
                if (fast != null) s.Add("Fast Startup", Convert.ToInt32(fast) == 1 ? "On" : "Off");
                if (fast != null) r.Signals.FastStartup = Convert.ToInt32(fast) == 1;
                if (fast != null && Convert.ToInt32(fast) == 1)
                {
                    // The event log step adds any failed resumes to this finding rather than repeating it.
                    r.Find(Severity.Info, FastStartupResume.Title, FastStartupResume.OnDetail, FastStartupResume.OnAdvice);
                    r.Signals.FastStartupFinding = r.Findings[r.Findings.Count - 1];
                }
            });
        }

        private static DateTime? ParseDate(string text)
        {
            DateTime d;
            if (DateTime.TryParse(text, CultureInfo.GetCultureInfo("en-US"), DateTimeStyles.None, out d)) return d;
            if (DateTime.TryParse(text, CultureInfo.CurrentCulture, DateTimeStyles.None, out d)) return d;
            return null;
        }

        public static void Programs(Report r)
        {
            var s = r.NewSection("Software");

            Guard.Try(s, "Running programs", () =>
            {
                var t = s.Table("Top memory use", "Process", "Memory");
                var groups = Process.GetProcesses().GroupBy(p => p.ProcessName)
                    .Select(g => new { Name = g.Key, Count = g.Count(), Memory = g.Sum(p => SafeMemory(p)) })
                    .OrderByDescending(g => g.Memory).Take(15);
                foreach (var g in groups)
                    t.Rows.Add(new[] { g.Name + (g.Count > 1 ? " (x" + g.Count + ")" : ""), Fmt.Bytes(g.Memory) });
            });

            Guard.Try(s, "Startup programs", () =>
            {
                var t = s.Table("Programs that run at startup", "Name", "Command", "From");
                foreach (var a in Wmi.Cim("SELECT Name, Command, Location FROM Win32_StartupCommand").OrderBy(a => a.Str("Name")))
                    t.Rows.Add(new[] { a.Str("Name"), Fmt.Clip(a.Str("Command"), 180), a.Str("Location") });
            });

            Guard.Try(s, "Services", () =>
            {
                var services = Wmi.Cim("SELECT Name, DisplayName, State, StartMode, ExitCode FROM Win32_Service");
                var t = s.Table("Automatic services that aren't running", "Service", "Name", "State", "Exit code");
                foreach (var v in services.Where(v => v.Str("StartMode") == "Auto" && v.Str("State") != "Running")
                             .OrderBy(v => StopsByItself(v.Str("Name"))).ThenBy(v => v.Str("DisplayName")))
                    t.Rows.Add(new[] { v.Str("DisplayName") + (StopsByItself(v.Str("Name")) ? " (normally stops by itself)" : ""), v.Str("Name"), v.Str("State"), v.Str("ExitCode") });
                s.Note("Some automatic services stop by themselves when they have no work to do, so a stopped service isn't always a fault.");
                var down = services.Where(v => EssentialServices.Contains(v.Str("Name"), StringComparer.OrdinalIgnoreCase) && v.Str("State") != "Running").ToList();
                if (down.Count > 0)
                    r.Find(Severity.Critical, "Essential Windows services are stopped", string.Join(", ", down.Select(v => v.Str("DisplayName"))), "Try restarting the PC. If they stay stopped, scan for malware and run: sfc /scannow");
            });

            Guard.Try(s, "Installed programs", () =>
            {
                var apps = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
                const string path = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
                ReadUninstall(RegistryHive.LocalMachine, RegistryView.Registry64, path, apps);
                ReadUninstall(RegistryHive.LocalMachine, RegistryView.Registry32, path, apps);
                ReadUninstall(RegistryHive.CurrentUser, RegistryView.Default, path, apps);
                var t = s.Table("Installed programs", "Name", "Version", "Publisher", "Installed");
                t.Rows.AddRange(apps.Values.OrderBy(a => a[0], StringComparer.OrdinalIgnoreCase));
            });
        }

        // Automatic services that run briefly and stop, or start only when something triggers them.
        private static readonly string[] SelfStopping = { "MapsBroker", "GoogleUpdater", "gupdate", "edgeupdate", "gpsvc", "sppsvc", "RemoteRegistry", "TrustedInstaller", "WbioSrvc", "Intel(R) TPM Provisioning Service", "Intel(R) Platform License Manager Service", "BITS", "UsoSvc", "sedsvc" };

        private static bool StopsByItself(string name)
        {
            return SelfStopping.Any(n => (name ?? "").StartsWith(n, StringComparison.OrdinalIgnoreCase));
        }

        // Restore points: whether Windows makes them, how many exist, and whether they've been lost for lack of space.
        private static void SystemProtection(Report r, Section s)
        {
            var interval = Reg.Machine(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore", "RPSessionInterval");
            bool? on = interval == null ? (bool?)null : Convert.ToInt32(interval) == 1;
            s.Add("System Protection (restore points)", on == null ? "Unknown" : on.Value ? "On" : "Off");

            if (Scanner.IsElevated())
            {
                Guard.Try(s, "Restore points", () =>
                {
                    var points = Wmi.Query(@"root\default", "SELECT CreationTime FROM SystemRestore").Select(p => p.Date("CreationTime")).Where(d => d != null).ToList();
                    s.Add("Restore points", points.Count == 0 ? "None" : points.Count + ", newest " + Fmt.Time(points.Max()));
                });
                Guard.Try(s, "Restore point space", () =>
                {
                    var store = Wmi.Cim("SELECT UsedSpace, MaxSpace FROM Win32_ShadowStorage").FirstOrDefault();
                    if (store != null) s.Add("Restore point space", Fmt.Bytes(store.Long("UsedSpace")) + " used of " + Fmt.Bytes(store.Long("MaxSpace")));
                });
            }

            // Volsnap 25 and 36: shadow copies (restore points) deleted or aborted because their storage couldn't grow.
            int lost = 0;
            var q = new System.Diagnostics.Eventing.Reader.EventLogQuery("System", System.Diagnostics.Eventing.Reader.PathType.LogName,
                "*[System[Provider[@Name='volsnap'] and (EventID=25 or EventID=36) and TimeCreated[timediff(@SystemTime) <= " + 30 * 86400000L + "]]]");
            using (var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(q))
            {
                System.Diagnostics.Eventing.Reader.EventRecord e;
                while ((e = reader.ReadEvent()) != null) using (e) lost++;
            }
            if (lost > 0)
                r.Find(Severity.Warning, "Restore points were deleted for lack of space", "Windows deleted or abandoned restore points " + lost + " time" + (lost == 1 ? "" : "s") + " in the last 30 days because their storage limit was too small.",
                    "Open Create a restore point (sysdm.cpl), choose the C: drive, press Configure and raise Max Usage to 5 to 10%.");
            else if (on == false)
                r.Find(Severity.Info, "System Protection is off", "Windows isn't keeping restore points, so a bad driver or update can't be rolled back that way, and Repair tools' restore point will fail.",
                    "Open Create a restore point (sysdm.cpl), choose the C: drive, press Configure and turn on system protection with 5 to 10% of the drive.");
        }

        // The Windows Recovery Environment runs Startup Repair and asks for the BitLocker key when Windows can't start.
        private static void RecoveryEnvironment(Report r, Section s)
        {
            var path = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"Recovery\ReAgent.xml");
            if (!System.IO.File.Exists(path)) { s.Add("Recovery environment", "Unknown"); return; }
            var doc = System.Xml.Linq.XDocument.Load(path);
            var state = doc.Descendants("InstallState").Select(x => (string)x.Attribute("state")).FirstOrDefault();
            bool enabled = state == "1";
            s.Add("Recovery environment (WinRE)", enabled ? "On" : "Off");
            if (!enabled)
                r.Find(Severity.Warning, "Windows Recovery Environment is off", "If Windows stops starting, Startup Repair, System Restore and Reset this PC won't be available from the boot menu.",
                    "From an administrator prompt run: reagentc /enable. If that fails, the recovery partition may be missing or too small.");
        }

        private static long SafeMemory(Process p)
        {
            try { return p.WorkingSet64; }
            catch (Exception) { return 0; }
            finally { p.Dispose(); }
        }

        private static void ReadUninstall(RegistryHive hive, RegistryView view, string path, Dictionary<string, string[]> apps)
        {
            using (var root = RegistryKey.OpenBaseKey(hive, view))
            using (var key = root.OpenSubKey(path))
            {
                if (key == null) return;
                foreach (var name in key.GetSubKeyNames())
                    using (var k = key.OpenSubKey(name))
                    {
                        if (k == null) continue;
                        AddProgram(apps, k);
                    }
            }
        }

        // Installers write InstallDate as yyyyMMdd, but some write Unix seconds or an impossible date such as 20254202.
        private static string InstallDate(string raw)
        {
            raw = (raw ?? "").Trim();
            DateTime d;
            if (raw.Length == 8 && DateTime.TryParseExact(raw, "yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out d))
                return Fmt.Date(d);
            long seconds;
            if (raw.Length >= 9 && raw.Length <= 10 && long.TryParse(raw, out seconds))
            {
                d = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(seconds).ToLocalTime();
                if (d.Year >= 1995 && d <= DateTime.Now.AddDays(1)) return Fmt.Date(d);
            }
            return "";
        }

        private static void AddProgram(Dictionary<string, string[]> apps, RegistryKey k)
        {
            var display = k.GetValue("DisplayName") as string;
            if (string.IsNullOrWhiteSpace(display) || Convert.ToInt32(k.GetValue("SystemComponent", 0)) == 1) return;
            apps[display] = new[]
            {
                display, k.GetValue("DisplayVersion") as string ?? "", k.GetValue("Publisher") as string ?? "", InstallDate(k.GetValue("InstallDate") as string)
            };
        }
    }
}
