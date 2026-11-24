using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;

namespace Feverfew.Collectors
{
    /// <summary>
    /// Device filter drivers (UpperFilters and LowerFilters on device classes and on single devices), and which drivers keep
    /// memory integrity off. Read-only: Feverfew never removes drivers. The classification is in FilterDriverAudit.
    /// </summary>
    public static class FilterCollector
    {
        private const int MemoryIntegrityService = 2;
        private const int MaxRows = 60;

        // The classes where a broken filter does the most harm: input, USB, storage, network and cameras.
        private static readonly KeyValuePair<string, string>[] Classes =
        {
            Pair("{36fc9e60-c465-11cf-8056-444553540000}", "USB class"),
            Pair("{745a17a0-74d3-11d0-b6fe-00a0c91efb8b}", "HID class"),
            Pair("{4d36e96b-e325-11ce-bfc1-08002be10318}", "Keyboard class"),
            Pair("{4d36e96f-e325-11ce-bfc1-08002be10318}", "Mouse class"),
            Pair("{4d36e967-e325-11ce-bfc1-08002be10318}", "Disk drive class"),
            Pair("{71a27cdd-812a-11d0-bec7-08002be2092f}", "Volume class"),
            Pair("{4d36e965-e325-11ce-bfc1-08002be10318}", "CD/DVD drive class"),
            Pair("{4d36e972-e325-11ce-bfc1-08002be10318}", "Network adapter class"),
            Pair("{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}", "Camera class"),
            Pair("{6bdd1fc6-810f-11d0-bec7-08002be10318}", "Imaging device class"),
            Pair("{4d36e96c-e325-11ce-bfc1-08002be10318}", "Sound, video and game controller class"),
        };

        private static KeyValuePair<string, string> Pair(string k, string v) { return new KeyValuePair<string, string>(k, v); }

        public static void Collect(Report r)
        {
            var s = r.NewSection("Filter drivers and memory integrity");
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var drivers = new Dictionary<string, Row>(StringComparer.OrdinalIgnoreCase);
            Guard.Try(s, "Driver services", () =>
            {
                foreach (var d in Wmi.Cim("SELECT Name, PathName, StartMode, State FROM Win32_SystemDriver")) drivers[d.Str("Name")] = d;
            });

            Guard.Try(s, "Device filters", () => Filters(r, s, drivers, windows));
            Guard.Try(s, "Memory integrity blockers", () => Blockers(r, s, drivers, windows));
        }

        private static void Filters(Report r, Section s, Dictionary<string, Row> drivers, string windows)
        {
            var placements = new List<FilterDriverAudit.Placement>();
            foreach (var c in Classes)
                foreach (var upper in new[] { true, false })
                    foreach (var name in FilterDriverAudit.Names(Read(@"SYSTEM\CurrentControlSet\Control\Class\" + c.Key, upper ? "UpperFilters" : "LowerFilters")))
                        placements.Add(new FilterDriverAudit.Placement { Service = name, ClassWide = true, Where = c.Value, Upper = upper });

            foreach (var dev in Wmi.Cim("SELECT Name, PNPDeviceID FROM Win32_PnPEntity"))
            {
                var id = dev.Str("PNPDeviceID");
                if (id.Length == 0) continue;
                foreach (var upper in new[] { true, false })
                    foreach (var name in FilterDriverAudit.Names(Read(@"SYSTEM\CurrentControlSet\Enum\" + id, upper ? "UpperFilters" : "LowerFilters")))
                        placements.Add(new FilterDriverAudit.Placement { Service = name, ClassWide = false, Where = dev.Str("Name").Length > 0 ? dev.Str("Name") : id, Upper = upper });
            }

            var cache = new Dictionary<string, FilterDriverAudit.ServiceInfo>(StringComparer.OrdinalIgnoreCase);
            Func<string, FilterDriverAudit.ServiceInfo> lookup = name =>
            {
                FilterDriverAudit.ServiceInfo info;
                if (!cache.TryGetValue(name, out info)) cache[name] = info = Service(name, drivers, windows);
                return info;
            };
            var rows = FilterDriverAudit.Classify(placements, lookup);

            var t = s.Table("Third-party device filters", "Filter", "File", "Company", "Applies to", "Position", "Starts", "State");
            foreach (var row in rows.Take(MaxRows))
            {
                var p = row.Placement; var sv = row.Service;
                t.Rows.Add(new[]
                {
                    p.Service, sv.File != null ? System.IO.Path.GetFileName(sv.File) : "-", string.IsNullOrEmpty(sv.Company) ? "Unknown" : sv.Company,
                    p.ClassWide ? "Every device: " + p.Where : p.Where, p.Upper ? "Upper" : "Lower", string.IsNullOrEmpty(sv.StartMode) ? "-" : sv.StartMode,
                    FilterDriverAudit.State(row)
                });
            }
            if (rows.Count > MaxRows) s.Note("Only the first " + MaxRows + " of " + rows.Count + " third-party filters are listed.");
            s.Note("A filter driver sits above or below a device's own driver and sees everything it does. Mouse polling-rate tools, macro software, antivirus, backup, virtual drive and VPN software add them. Microsoft's own filters aren't listed.");

            var missing = FilterDriverAudit.MissingFinding(rows);
            if (missing != null) r.Findings.Add(missing);
            var idle = FilterDriverAudit.NotRunningFinding(rows);
            if (idle != null) r.Findings.Add(idle);
        }

        private static object Read(string key, string value)
        {
            try { return Reg.Machine(key, value); }
            catch (Exception) { return null; } // some Enum keys are locked even for administrators
        }

        private static FilterDriverAudit.ServiceInfo Service(string name, Dictionary<string, Row> drivers, string windows)
        {
            var key = @"SYSTEM\CurrentControlSet\Services\" + name;
            var info = new FilterDriverAudit.ServiceInfo { Exists = Reg.MachineKeyExists(key) };
            if (!info.Exists) return info;
            Row d;
            drivers.TryGetValue(name, out d);
            info.Running = d != null && d.Str("State") == "Running";
            info.StartMode = d != null ? d.Str("StartMode") : "";
            // A driver service without an ImagePath loads System32\drivers\<name>.sys.
            var image = Read(key, "ImagePath") as string;
            info.File = HardwareCollector.DriverPath(string.IsNullOrWhiteSpace(image) ? @"System32\drivers\" + name + ".sys" : image, windows);
            info.FileExists = info.File != null && System.IO.File.Exists(info.File);
            if (info.FileExists)
                try { info.Company = (System.Diagnostics.FileVersionInfo.GetVersionInfo(info.File).CompanyName ?? "").Trim(); }
                catch (Exception) { }
            return info;
        }

        private static void Blockers(Report r, Section s, Dictionary<string, Row> drivers, string windows)
        {
            bool? on = null;
            try
            {
                var d = Wmi.Query(@"root\Microsoft\Windows\DeviceGuard", "SELECT SecurityServicesRunning FROM Win32_DeviceGuard").FirstOrDefault();
                var running = d == null ? null : d.Raw("SecurityServicesRunning") as Array;
                if (d != null) on = running != null && running.Cast<object>().Any(x => Convert.ToInt32(x) == MemoryIntegrityService);
            }
            catch (Exception) { }
            if (on == true) return; // nothing blocks it

            var events = new List<KeyValuePair<DateTime, string>>();
            var ids = string.Join(" or ", FilterDriverAudit.BlockerEventIds.Select(i => "EventID=" + i));
            var q = new EventLogQuery("Microsoft-Windows-CodeIntegrity/Operational", PathType.LogName, "*[System[(" + ids + ")]]") { ReverseDirection = true };
            using (var reader = new EventLogReader(q))
            {
                EventRecord e; int n = 0;
                while (n++ < 2000 && (e = reader.ReadEvent()) != null)
                    using (e)
                    {
                        // Every version of these events has the module's path as its second value (%2).
                        if (e.TimeCreated == null || e.Properties.Count < 2) continue;
                        events.Add(new KeyValuePair<DateTime, string>(e.TimeCreated.Value, Convert.ToString(e.Properties[1].Value)));
                    }
            }

            var files = new HashSet<string>(drivers.Values.Select(d => System.IO.Path.GetFileName(HardwareCollector.DriverPath(d.Str("PathName"), windows) ?? "")).Where(f => f.Length > 0), StringComparer.OrdinalIgnoreCase);
            Func<string, bool> installed = path =>
            {
                var win32 = FilterDriverAudit.Win32Path(path, windows);
                return (win32 != null && System.IO.File.Exists(win32)) || files.Contains(FilterDriverAudit.FileName(path));
            };
            var blockers = FilterDriverAudit.Blockers(events, installed);

            s.Add("Memory integrity", on == null ? "Unknown" : "Off");
            if (blockers.Count > 0)
            {
                var t = s.Table("Drivers not compatible with memory integrity", "Driver", "Path", "Last reported", "Still installed");
                foreach (var b in blockers.Take(MaxRows)) t.Rows.Add(new[] { b.File, b.Path, Fmt.Time(b.Last), Fmt.YesNo(b.Installed) });
            }
            else
                s.Add("Drivers reported as blocking memory integrity", "None logged");
            s.Note("Windows logs a driver here (Code Integrity events 3072, 3073, 3087 and 3111) when it checks memory integrity compatibility, such as when you try to turn it on. A driver never checked isn't listed, and the log keeps only recent events, so an empty list doesn't prove nothing blocks it.");

            var finding = FilterDriverAudit.BlockersFinding(on, blockers);
            if (finding != null) r.Findings.Add(finding);
        }
    }
}
