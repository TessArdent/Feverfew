using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;

namespace Feverfew.Collectors
{
    public static class EventCollector
    {
        private const int Days = 30;
        private const int MaxEvents = 30000;
        private const int MaxShutdownRows = 40;
        private const int RepeatedCrashDays = 180;
        private const int NoisyDriverErrors = 100;
        private const int MaxNoisyDrivers = 3;

        private sealed class Group
        {
            public string Provider; public int Id; public int Count; public DateTime? Last; public byte Level; public string Message;
        }

        // Details gathered while reading the System log, so findings can name the disk, the boot and the driver.
        private sealed class Evidence
        {
            public readonly Dictionary<int, int> DiskErrors = new Dictionary<int, int>(); // disk number, or -1 when only the controller is named
            public readonly List<DateTime> Throttles = new List<DateTime>();
            public readonly List<uint> StopCodes = new List<uint>();
            public readonly List<string> SuspectDrivers = new List<string>();
            public readonly List<string> DumpDrivers = new List<string>(); // from crash dumps in the last Days days
            public readonly List<DateTime> Restarts = new List<DateTime>(); // Kernel-Power 41, newest first
            public readonly Dictionary<string, Whea> Whea = new Dictionary<string, Whea>(StringComparer.OrdinalIgnoreCase);
        }

        private sealed class Whea
        {
            public int Count; public DateTime? Last; public bool Fatal; public string Component, Source, Type, Device;
        }

        private static string Field(string text, string pattern)
        {
            var m = System.Text.RegularExpressions.Regex.Match(text, pattern + @":[ \t]*([^\r\n]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value.Trim() : "";
        }

        private static void TrackWhea(EventRecord e, Evidence ev)
        {
            string text = "";
            try { text = e.FormatDescription() ?? ""; } catch (Exception) { }
            var component = Field(text, @"(?:Reported by component|Component)");
            var source = Field(text, "Error Source");
            var type = Field(text, "Error Type");
            // PCIe errors name the device by hardware ID or by vendor and device numbers.
            var device = "";
            var id = System.Text.RegularExpressions.Regex.Match(text, @"VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (!id.Success) id = System.Text.RegularExpressions.Regex.Match(text, @"Vendor ID:Device ID:\s*0x([0-9A-F]{1,4}):0x([0-9A-F]{1,4})", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (id.Success) device = "VEN_" + id.Groups[1].Value.PadLeft(4, '0').ToUpperInvariant() + "&DEV_" + id.Groups[2].Value.PadLeft(4, '0').ToUpperInvariant();
            bool fatal = (e.Level ?? 3) <= 2;
            var key = e.Id + "|" + fatal + "|" + component + "|" + source + "|" + type + "|" + device;
            Whea w;
            if (!ev.Whea.TryGetValue(key, out w))
                ev.Whea[key] = w = new Whea { Last = e.TimeCreated, Fatal = fatal, Component = component, Source = source, Type = type, Device = device };
            w.Count++;
        }

        private static void WheaTable(Report r, Section s, Evidence ev, int corrected)
        {
            if (ev.Whea.Count == 0) return;
            var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var dev in ev.Whea.Values.Select(w => w.Device).Where(d => d.Length > 0).Distinct())
                try
                {
                    var match = Wmi.Cim("SELECT Name FROM Win32_PnPEntity WHERE PNPDeviceID LIKE '%" + dev + "%'").FirstOrDefault();
                    names[dev] = match != null && match.Str("Name").Length > 0 ? match.Str("Name") + " (" + dev + ")" : dev;
                }
                catch (Exception) { names[dev] = dev; }

            var t = s.Table("Hardware errors (WHEA)", "Count", "Last seen", "Kind", "Component", "Error source", "Error type", "Device");
            foreach (var w in ev.Whea.Values.OrderByDescending(w => w.Fatal).ThenByDescending(w => w.Count))
                t.Rows.Add(new[] { w.Count.ToString(), Fmt.Time(w.Last), w.Fatal ? "Fatal" : "Corrected", w.Component, w.Source, w.Type, w.Device.Length > 0 ? names[w.Device] : "" });

            var top = ev.Whea.Values.Where(w => !w.Fatal).OrderByDescending(w => w.Count).FirstOrDefault();
            if (corrected >= 10 && top != null)
            {
                string where = (top.Component + " " + top.Source).ToLowerInvariant();
                string advice = where.Contains("pci")
                    ? "Reseat " + (top.Device.Length > 0 ? names[top.Device] : "the graphics card and NVMe drive") + ". If errors continue, set that slot's PCIe generation one step lower in BIOS setup, and update the BIOS."
                    : where.Contains("memory")
                        ? "Turn off the memory profile (XMP or EXPO) to test, then check the memory with MemTest86."
                        : where.Contains("processor") || where.Contains("machine check")
                            ? "Remove any CPU overclock or undervolt, load the BIOS defaults, and update the BIOS."
                            : "Reseat the graphics card and NVMe drive, then update the BIOS.";
                r.Find(Severity.Warning, "Repeated corrected hardware errors", corrected + " corrected WHEA events, most from " + (top.Component.Length > 0 ? top.Component : "an unnamed component") + ". See 'Hardware errors (WHEA)'.", advice);
            }
        }

        private static readonly int[] DiskErrorIds = { 11, 51, 52, 153, 154 };
        private static readonly int[] ControllerErrorIds = { 11, 129 };

        private static bool Is(EventRecord e, string provider) { return string.Equals(e.ProviderName, provider, StringComparison.OrdinalIgnoreCase); }

        private static void Track(EventRecord e, Evidence ev)
        {
            if ((Is(e, "disk") && DiskErrorIds.Contains(e.Id)) || ((Is(e, "stornvme") || Is(e, "storahci")) && ControllerErrorIds.Contains(e.Id)))
            {
                int disk = -1;
                var values = string.Join(" ", e.Properties.Select(p => p.Value as string).Where(v => v != null));
                var m = System.Text.RegularExpressions.Regex.Match(values, @"Harddisk(\d+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (!m.Success && Is(e, "disk")) m = System.Text.RegularExpressions.Regex.Match(Describe(e), @"\bDisk (\d+)\b");
                if (m.Success) disk = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
                int c; ev.DiskErrors.TryGetValue(disk, out c); ev.DiskErrors[disk] = c + 1;
            }
            else if (Is(e, "Microsoft-Windows-WHEA-Logger"))
                TrackWhea(e, ev);
            else if (Is(e, "Microsoft-Windows-Kernel-Power") && e.Id == 41 && e.TimeCreated != null)
                ev.Restarts.Add(e.TimeCreated.Value);
            else if (Is(e, "Microsoft-Windows-Kernel-Processor-Power") && e.Id == 37 && e.TimeCreated != null)
                ev.Throttles.Add(e.TimeCreated.Value);
            else if (Is(e, "Microsoft-Windows-WER-SystemErrorReporting") && e.Id == 1001 || Is(e, "BugCheck") && e.Id == 1001)
            {
                var m = System.Text.RegularExpressions.Regex.Match(Describe(e), @"0x([0-9a-fA-F]{8})");
                uint code;
                if (m.Success && uint.TryParse(m.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out code)) ev.StopCodes.Add(code);
            }
            else if (Is(e, "Microsoft-Windows-WER-SystemErrorReporting") && e.Id == 1019)
            {
                var m = System.Text.RegularExpressions.Regex.Match(Describe(e), @"driver:\s*([\w.-]+\.sys)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (m.Success && !ev.SuspectDrivers.Contains(m.Groups[1].Value, StringComparer.OrdinalIgnoreCase)) ev.SuspectDrivers.Add(m.Groups[1].Value);
            }
        }

        private static string Query(string levels)
        {
            long ms = Days * 86400000L;
            return "*[System[(" + levels + ") and TimeCreated[timediff(@SystemTime) <= " + ms + "]]]";
        }

        private static string Describe(EventRecord e)
        {
            // Windows puts invisible direction marks around the dates in some messages.
            string text = "";
            try { text = (e.FormatDescription() ?? "").Replace("\u200e", "").Replace("\u200f", "").Trim(); }
            catch (Exception) { }
            if (text.Length == 0) text = RawData(e);
            return Fmt.Clip(text, 260);
        }

        // Some drivers (nvlddmkm, for one) ship no message text, so show the values the event carries instead.
        private static string RawData(EventRecord e)
        {
            try
            {
                var parts = e.Properties.Select(p => Convert.ToString(p.Value, CultureInfo.InvariantCulture)?.Trim())
                    .Where(v => !string.IsNullOrEmpty(v) && v.Length < 400).ToList();
                return parts.Count == 0 ? "" : "(no message text) " + string.Join(" \u00b7 ", parts);
            }
            catch (Exception) { return ""; }
        }

        private static List<Group> Scan(string log, Action<EventRecord> visit = null)
        {
            var groups = new Dictionary<string, Group>();
            var q = new EventLogQuery(log, PathType.LogName, Query("Level=1 or Level=2 or Level=3")) { ReverseDirection = true };
            using (var reader = new EventLogReader(q))
            {
                EventRecord e; int n = 0;
                while (n++ < MaxEvents && (e = reader.ReadEvent()) != null)
                {
                    using (e)
                    {
                        if (visit != null) visit(e);
                        var key = e.ProviderName + "|" + e.Id;
                        Group g;
                        if (!groups.TryGetValue(key, out g))
                        {
                            g = new Group { Provider = e.ProviderName, Id = e.Id, Level = e.Level ?? 0, Last = e.TimeCreated, Message = Describe(e) };
                            groups[key] = g;
                        }
                        g.Count++;
                    }
                }
            }
            return groups.Values.ToList();
        }

        public static void Collect(Report r)
        {
            var s = r.NewSection("Crashes and event logs (last " + Days + " days)");
            var dumps = new List<DumpFile>();
            try { dumps = ReadDumps(); } catch (Exception) { /* the Crash dumps step reports the problem */ }

            Guard.Try(s, "System log", () =>
            {
                var shutdowns = new List<string[]>();
                var evidence = new Evidence();
                foreach (var d in dumps.Where(d => d.Driver != null && d.File.LastWriteTime >= DateTime.Now.AddDays(-Days)))
                    if (!evidence.DumpDrivers.Contains(d.Driver, StringComparer.OrdinalIgnoreCase)) evidence.DumpDrivers.Add(d.Driver);
                var sys = Scan("System", e => { RecordShutdown(e, shutdowns); Track(e, evidence); });
                Fill(s.Table("Most frequent System errors", "Count", "Last seen", "Source", "ID", "Message"), sys);
                if (shutdowns.Count > 0)
                {
                    var t = s.Table("Unexpected shutdowns and blue screens", "Logged", "Event", "Details");
                    t.Rows.AddRange(shutdowns);
                    s.Note("Windows logs these when the PC starts again, so the crash itself came earlier. An 'improper shutdown' message gives Windows' last recorded time before the stop.");
                }
                Analyze(r, s, sys, evidence);
                Guard.Try(s, "Crash timelines", () => Timelines(s, evidence.Restarts));
            });

            Guard.Try(s, "Application log", () =>
            {
                var crashes = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
                var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                var app = Scan("Application", e =>
                {
                    if (e.ProviderName != "Application Error" || e.Id != 1000 || e.Properties.Count < 7) return;
                    var name = Convert.ToString(e.Properties[0].Value);
                    int c; counts.TryGetValue(name, out c); counts[name] = c + 1;
                    if (c == 0)
                        crashes[name] = new[] { name, Convert.ToString(e.Properties[3].Value), FormatCode(e.Properties[6].Value), Fmt.Time(e.TimeCreated) };
                });
                Fill(s.Table("Most frequent Application errors", "Count", "Last seen", "Source", "ID", "Message"), app);
                var t = s.Table("Program crashes", "Count", "Program", "Faulting module", "Exception", "Last crash");
                foreach (var kv in counts.OrderByDescending(k => k.Value).Take(20))
                    t.Rows.Add(new[] { kv.Value.ToString() }.Concat(crashes[kv.Key]).ToArray());
                var worst = counts.OrderByDescending(k => k.Value).FirstOrDefault();
                if (worst.Value >= 5)
                    r.Find(Severity.Warning, "A program keeps crashing: " + worst.Key, worst.Value + " crashes in the last " + Days + " days.", "Update or reinstall it. The 'Program crashes' table names the faulting module.");
            });

            Guard.Try(s, "Crash dumps", () => Dumps(r, s, dumps));
        }

        private const int MaxTimelines = 5;
        private const int MaxTimelineRows = 40;

        // For each unexpected restart, the warnings and errors from the last minutes before the PC stopped and from the restart itself,
        // so related events in different logs read as one story.
        private static void Timelines(Section s, List<DateTime> restarts)
        {
            var boots = Read("System", "*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and EventID=12 and TimeCreated[timediff(@SystemTime) <= " + Days * 86400000L + "]]]", 500)
                .Select(e => e.Time).OrderBy(t => t).ToList();
            foreach (var restart in restarts.Take(MaxTimelines))
            {
                var boot = boots.LastOrDefault(b => b <= restart.AddMinutes(1));
                if (boot == default(DateTime)) boot = restart.AddMinutes(-2);
                // The last thing the crashed session logged, at any level, marks roughly when it stopped.
                var last = Read("System", "*[System[TimeCreated[@SystemTime<'" + Utc(boot.AddSeconds(-1)) + "' and @SystemTime>='" + Utc(boot.AddDays(-2)) + "']]]", 1, true).FirstOrDefault();
                var stopped = last != null ? last.Time : boot.AddMinutes(-1);
                // Windows logs the blue screen and improper shutdown events within about 30 seconds of Kernel-Power 41.
                var end = (restart > boot ? restart : boot).AddSeconds(45);
                string window = "*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[@SystemTime>='" + Utc(stopped.AddMinutes(-15)) + "' and @SystemTime<='" + Utc(end) + "']]]";
                var all = Read("System", window, 200, true).Concat(Read("Application", window, 200, true))
                    .Where(e => !UsuallyHarmless(e.Source, e.Id)).ToList();
                // Keep the events nearest the stop, and the first ones after the restart.
                var before = all.Where(e => e.Time < boot).OrderByDescending(e => e.Time).Take(MaxTimelineRows - 12);
                var after = all.Where(e => e.Time >= boot).OrderBy(e => e.Time).Take(12);
                var events = before.Concat(after).OrderBy(e => e.Time).ToList();
                if (events.Count == 0) continue;
                var t = s.Table("Events around the restart at " + Fmt.Seconds(restart), "Time", "Log", "Level", "Source", "ID", "Message");
                foreach (var e in events)
                    t.Rows.Add(new[] { Fmt.Seconds(e.Time) + (e.Time >= boot ? " (after restart)" : ""), e.Log, e.Level, e.Source, e.Id, e.Message });
            }
            if (s.Tables.Any(t => t.Title.StartsWith("Events around the restart", StringComparison.Ordinal)))
                s.Note("Each timeline runs from 15 minutes before the last event Windows logged before it stopped, through the first minutes after the restart.");
        }

        private sealed class Line { public DateTime Time; public string Log, Level, Source, Id, Message; }

        // Events Windows logs on healthy PCs all the time. They're kept out of timelines and marked in the error lists.
        private static readonly HashSet<string> Harmless = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Microsoft-Windows-DistributedCOM|10010", "Microsoft-Windows-DistributedCOM|10016",
            "Microsoft-Windows-Windows Firewall With Advanced Security|2042", "Microsoft-Windows-DNS-Client|8048",
            "Microsoft-Windows-WMI|63", "Microsoft-Windows-Kernel-PnP|219"
        };

        private static bool UsuallyHarmless(string source, string id) { return Harmless.Contains(source + "|" + id); }

        private static string Utc(DateTime local) { return local.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture); }

        private static List<Line> Read(string log, string xpath, int max, bool newestFirst = false)
        {
            var list = new List<Line>();
            var q = new EventLogQuery(log, PathType.LogName, xpath) { ReverseDirection = newestFirst };
            using (var reader = new EventLogReader(q))
            {
                EventRecord e;
                while (list.Count < max && (e = reader.ReadEvent()) != null)
                    using (e)
                    {
                        if (e.TimeCreated == null) continue;
                        list.Add(new Line
                        {
                            Time = e.TimeCreated.Value, Log = log, Source = e.ProviderName, Id = e.Id.ToString(CultureInfo.InvariantCulture), Message = Describe(e),
                            Level = e.Level == 1 ? "Critical" : e.Level == 2 ? "Error" : e.Level == 3 ? "Warning" : "Information"
                        });
                    }
            }
            return list;
        }

        private static void RecordShutdown(EventRecord e, List<string[]> rows)
        {
            if (rows.Count >= MaxShutdownRows) return;
            if (e.ProviderName == "Microsoft-Windows-Kernel-Power" && e.Id == 41)
                rows.Add(new[] { Fmt.Seconds(e.TimeCreated), "Unexpected restart", UnexpectedRestartDetail(e) });
            else if (e.ProviderName == "EventLog" && e.Id == 6008)
                rows.Add(new[] { Fmt.Seconds(e.TimeCreated), "Improper shutdown", Describe(e) });
            else if ((e.ProviderName == "Microsoft-Windows-WER-SystemErrorReporting" || e.ProviderName == "BugCheck") && e.Id == 1001)
                rows.Add(new[] { Fmt.Seconds(e.TimeCreated), "Blue screen", Describe(e) });
            else if (e.ProviderName == "Microsoft-Windows-WER-SystemErrorReporting" && e.Id == 1019)
                rows.Add(new[] { Fmt.Seconds(e.TimeCreated), "Blue screen driver hint", Describe(e) });
        }

        private static string UnexpectedRestartDetail(EventRecord e)
        {
            try
            {
                var code = e.Properties.Count > 0 ? Convert.ToUInt32(e.Properties[0].Value) : 0;
                if (code != 0) return "Stop code " + FormatCode(code) + " (" + BugCheckName(code) + ").";
            }
            catch (Exception) { }
            return "No stop code recorded, so this may be power loss, a freeze or a forced restart.";
        }

        private static string FormatCode(object v)
        {
            try { return "0x" + Convert.ToUInt32(v).ToString("x8"); }
            catch (Exception) { return Convert.ToString(v); }
        }

        private static void Fill(Table t, List<Group> groups)
        {
            foreach (var g in groups.Where(g => g.Level <= 2).OrderByDescending(g => g.Count).Take(25))
                t.Rows.Add(new[] { g.Count.ToString(), Fmt.Time(g.Last), g.Provider, g.Id.ToString(), g.Message });
        }

        private static void Analyze(Report r, Section s, List<Group> sys, Evidence ev)
        {
            Func<string, int[], int> count = (provider, ids) =>
                sys.Where(g => string.Equals(g.Provider, provider, StringComparison.OrdinalIgnoreCase) && (ids == null || ids.Contains(g.Id))).Sum(g => g.Count);

            int kernelPower = count("Microsoft-Windows-Kernel-Power", new[] { 41 });
            int dirty = count("EventLog", new[] { 6008 });
            int bugcheck = count("Microsoft-Windows-WER-SystemErrorReporting", new[] { 1001 }) + count("BugCheck", new[] { 1001 });
            int wheaError = sys.Where(g => g.Provider == "Microsoft-Windows-WHEA-Logger" && g.Level <= 2).Sum(g => g.Count);
            int wheaWarn = sys.Where(g => g.Provider == "Microsoft-Windows-WHEA-Logger" && g.Level == 3).Sum(g => g.Count);
            int badBlock = count("disk", new[] { 7 });
            int diskErr = count("disk", new[] { 11, 51, 52, 153, 154 }) + count("stornvme", new[] { 11, 129 }) + count("storahci", new[] { 11, 129 });
            int ntfs = count("Microsoft-Windows-Ntfs", new[] { 55, 98, 130, 137 });
            // Windows logs a recovered driver timeout as Display 4101; NVIDIA's driver logs its own as nvlddmkm 153.
            int gpu = count("Display", new[] { 4101 }) + count("nvlddmkm", new[] { 153 });
            int throttle = count("Microsoft-Windows-Kernel-Processor-Power", new[] { 37 });

            s.Add("Unexpected restarts (Kernel-Power 41)", kernelPower);
            s.Add("Improper shutdowns (EventLog 6008)", dirty);
            s.Add("Blue screens (BugCheck 1001)", bugcheck);
            s.Add("Hardware errors (WHEA)", wheaError + " fatal, " + wheaWarn + " corrected");
            s.Add("Disk errors", badBlock + " bad block, " + diskErr + " I/O or timeout");
            s.Add("File system errors (NTFS)", ntfs);
            s.Add("Graphics driver resets (Display 4101, nvlddmkm 153)", gpu);
            s.Add("CPU speed limited by firmware (Processor-Power 37)", throttle);

            if (bugcheck > 0) BlueScreens(r, bugcheck, ev);
            NoisyDrivers(r, sys);
            if (kernelPower > bugcheck)
                r.Find(kernelPower >= 3 ? Severity.Critical : Severity.Warning, kernelPower + " unexpected restart" + (kernelPower == 1 ? "" : "s"), "The PC stopped without shutting down cleanly, and some of those restarts had no blue screen.", "Suspect the power supply, overheating, unstable overclocks, or someone holding the power button.");
            if (wheaError > 0)
                r.Find(Severity.Critical, "Fatal hardware errors logged", wheaError + " WHEA errors. The CPU, RAM, motherboard or a PCIe device reported a failure.", "Remove any overclock, test the RAM with MemTest86, and check which component reported it in 'Hardware errors (WHEA)'.");
            WheaTable(r, s, ev, wheaWarn);
            if (badBlock > 0)
                r.Find(Severity.Critical, "Bad blocks reported on a disk", badBlock + " bad block events.", "Back up now, then test the drive with its maker's tool.");
            if (diskErr >= 5) DiskErrors(r, diskErr, ev);
            if (ntfs > 0)
                r.Find(Severity.Warning, "File system errors", ntfs + " NTFS events.", "Run chkdsk /scan and check the drive's health.");
            if (gpu >= 3)
                r.Find(Severity.Warning, "Graphics driver keeps resetting", gpu + " resets logged.", "Do a clean driver install, remove GPU overclocks, and check temperature and power cables.");
            if (throttle >= 10) Throttling(r, throttle, ev);
        }

        private static void BlueScreens(Report r, int count, Evidence ev)
        {
            var codes = ev.StopCodes.Distinct().ToList();
            var detail = count == 1 ? "Windows recorded one stop error" : "Windows recorded " + count + " stop errors";
            if (codes.Count > 0) detail += ", with stop code" + (codes.Count == 1 ? " " : "s ") + string.Join(", ", codes.Take(4).Select(c => "0x" + c.ToString("X8", CultureInfo.InvariantCulture) + " (" + BugCheckName(c) + ")"));
            detail += ".";
            if (ev.DumpDrivers.Count > 0) detail += " The crash dump" + (ev.DumpDrivers.Count == 1 ? " shows" : "s show") + " the failure in " + string.Join(", ", ev.DumpDrivers.Take(3)) + ".";
            var others = ev.SuspectDrivers.Where(x => !ev.DumpDrivers.Contains(x, StringComparer.OrdinalIgnoreCase)).ToList();
            if (others.Count > 0) detail += " Windows names " + string.Join(", ", others.Take(3)) + " as possibly related.";
            bool named = ev.DumpDrivers.Count > 0 || ev.SuspectDrivers.Count > 0;

            string advice;
            if (count == 1)
                advice = "A single blue screen can be a one-off. If it happens again, update " + (named ? "the driver named above" : "the graphics, chipset and storage drivers") + " and check 'Recent crash dumps'.";
            else if (codes.Count > 1)
                advice = "Different stop codes usually point to RAM, power or an unstable overclock. Remove any overclock and test the memory.";
            else
                advice = "The same stop code each time usually points to a driver. " + (named ? "Update or reinstall the one named above." : "Check 'Recent crash dumps' and update the drivers it suggests.");
            r.Find(count >= 3 ? Severity.Critical : Severity.Warning, count + " blue screen" + (count == 1 ? "" : "s") + " in " + Days + " days", detail, advice);
        }

        private static void DiskErrors(Report r, int total, Evidence ev)
        {
            var disks = new Dictionary<long, Row>();
            try { foreach (var d in Wmi.Query(@"root\Microsoft\Windows\Storage", "SELECT Number, FriendlyName, BusType FROM MSFT_Disk")) if (d.Long("Number") != null) disks[d.Long("Number").Value] = d; }
            catch (Exception) { /* name the disks by number only */ }

            Func<int, string> bus = n => { Row d; return disks.TryGetValue(n, out d) ? StorageCollector.BusType(d.Long("BusType")) : null; };
            var parts = ev.DiskErrors.OrderByDescending(kv => kv.Value).Select(kv =>
            {
                if (kv.Key < 0) return kv.Value + " from the storage controller";
                Row d;
                return disks.TryGetValue(kv.Key, out d)
                    ? kv.Value + " on disk " + kv.Key + " (" + d.Str("FriendlyName") + ", " + bus(kv.Key) + ")"
                    : kv.Value + " on disk " + kv.Key + ", which isn't connected now";
            }).ToList();
            var detail = total + " events" + (parts.Count > 0 ? ": " + string.Join("; ", parts) + "." : ".");

            var worst = ev.DiskErrors.OrderByDescending(kv => kv.Value).Select(kv => (int?)kv.Key).FirstOrDefault();
            bool allGone = ev.DiskErrors.Count > 0 && ev.DiskErrors.Keys.All(k => k >= 0 && !disks.ContainsKey(k)) && disks.Count > 0;
            string b = worst != null && worst >= 0 ? bus(worst.Value) : null;
            string advice;
            if (allGone)
                advice = "The errors came from a disk that isn't connected now, often a USB drive or memory card, so the internal drive isn't affected. If you still use that disk, copy its files off and try another port or cable.";
            else if (b == "USB" || b == "SD")
                advice = "Try another USB port and cable. If the errors continue, the drive itself may be failing, so copy its files off.";
            else if (b == "NVMe" || b == "RAID")
                advice = "Back up first. Then update the storage driver (Intel RST on many laptops) and the SSD's firmware, and check the drive's temperature.";
            else if (b == "SATA" || b == "ATA")
                advice = "Check or replace the SATA cable, reseat the drive, and update the storage driver or firmware.";
            else
                advice = "Back up first, then update the storage driver and the drive's firmware. On a desktop, reseat the drive and its cable.";
            r.Find(allGone ? Severity.Info : Severity.Warning, "Disk I/O errors or timeouts", detail, advice);
        }

        private static void Throttling(Report r, int count, Evidence ev)
        {
            bool laptop = Machine.IsLaptop();

            var boots = new List<DateTime>();
            try
            {
                var q = new EventLogQuery("System", PathType.LogName,
                    "*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and EventID=12 and TimeCreated[timediff(@SystemTime) <= " + Days * 86400000L + "]]]");
                using (var reader = new EventLogReader(q))
                {
                    EventRecord e;
                    while ((e = reader.ReadEvent()) != null) using (e) if (e.TimeCreated != null) boots.Add(e.TimeCreated.Value);
                }
            }
            catch (Exception) { }
            boots.Sort();

            // Which start each event belongs to, and how long after that start it came.
            var placed = ev.Throttles.Select(t => new { Time = t, Boot = boots.LastOrDefault(b => b <= t) }).ToList();
            bool startupOnly = boots.Count > 0 && placed.Count > 0 && placed.All(p => p.Boot != default(DateTime) && (p.Time - p.Boot).TotalMinutes <= 5);
            int bootsHit = placed.Where(p => p.Boot != default(DateTime)).Select(p => p.Boot).Distinct().Count();
            var detail = count + " throttling events" + (boots.Count > 0 ? " across " + bootsHit + " of " + boots.Count + " starts in " + Days + " days" : "") + ".";

            if (startupOnly)
                r.Find(Severity.Info, "CPU speed limited by firmware at startup", detail + " All came within five minutes of Windows starting, which is common and usually harmless.",
                    "Nothing to do unless games or apps stutter later. If they do, check CPU temperatures with a tool such as HWiNFO.");
            else
                r.Find(Severity.Warning, "CPU speed is being limited by firmware", detail + (laptop ? " Usually heat or a weak power adapter." : " Usually heat or power limits."),
                    laptop ? "Clean the vents and fan, use the original charger, and check the power mode in Settings > System > Power."
                           : "Check that the CPU cooler is seated and its fan spins, clean out dust, and check the power supply and the BIOS power limits.");
        }

        private static void NoisyDrivers(Report r, List<Group> sys)
        {
            var covered = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "disk", "stornvme", "storahci" };
            var noisy = sys.Where(g => g.Level <= 2 && !covered.Contains(g.Provider))
                .GroupBy(g => g.Provider, StringComparer.OrdinalIgnoreCase)
                .Select(p => new { Provider = p.Key, Count = p.Sum(g => g.Count), Example = p.OrderByDescending(g => g.Count).First().Message })
                .Where(p => p.Count >= NoisyDriverErrors && IsDriver(p.Provider))
                .OrderByDescending(p => p.Count)
                .Take(MaxNoisyDrivers);
            foreach (var d in noisy)
                r.Find(Severity.Warning, "A driver keeps logging errors: " + d.Provider, d.Count + " errors in the last " + Days + " days. Most common: " + Fmt.Clip(d.Example, 140),
                    "Update or reinstall that device's driver from its maker's site. Errors like this can go along with dropouts or blue screens, but they don't prove the driver caused them.");
        }

        private static bool IsDriver(string provider)
        {
            const int kernelDriver = 1, fileSystemDriver = 2;
            var type = Reg.Machine(@"SYSTEM\CurrentControlSet\Services\" + provider, "Type");
            if (type is int && ((int)type == kernelDriver || (int)type == fileSystemDriver)) return true;
            var file = Reg.Machine(@"SYSTEM\CurrentControlSet\Services\EventLog\System\" + provider, "EventMessageFile") as string;
            return file != null && file.IndexOf(".sys", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static void RepeatedCrashes(Report r, List<KeyValuePair<DateTime, uint>> dumps)
        {
            var cutoff = DateTime.Now.AddDays(-RepeatedCrashDays);
            var worst = dumps.Where(d => d.Key >= cutoff).GroupBy(d => d.Value).OrderByDescending(g => g.Count()).FirstOrDefault();
            if (worst == null || worst.Count() < 2) return;
            r.Find(Severity.Warning, "The same blue screen keeps happening: " + BugCheckName(worst.Key),
                worst.Count() + " saved crash dumps since " + Fmt.Date(worst.Min(d => d.Key)) + " have stop code 0x" + worst.Key.ToString("X8", CultureInfo.InvariantCulture) + ". The times are in 'Recent crash dumps'.",
                worst.Key == 0x9F
                    ? "This code means a device driver stalled a sleep, shutdown or power change. Update the Wi-Fi, Bluetooth, chipset and graphics drivers, and try turning off Fast Startup. Opening a dump in Microsoft's WinDbg names the driver."
                    : "One repeated code usually points to a driver. Opening a dump in Microsoft's WinDbg names it.");
        }

        private sealed class DumpFile
        {
            public FileInfo File; public uint? Code; public string Driver;
        }

        private static List<DumpFile> ReadDumps()
        {
            var list = new List<DumpFile>();
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Minidump");
            if (!Scanner.IsElevated() || !Directory.Exists(dir)) return list;
            foreach (var f in new DirectoryInfo(dir).GetFiles("*.dmp").OrderByDescending(f => f.LastWriteTime).Take(15))
            {
                var d = new DumpFile { File = f };
                ReadDump(f.FullName, d);
                list.Add(d);
            }
            return list;
        }

        private static void Dumps(Report r, Section s, List<DumpFile> dumps)
        {
            // Without admin rights the folder just looks absent, which would read as "no crashes".
            if (!Scanner.IsElevated()) throw new UnauthorizedAccessException();
            var t = s.Table("Recent crash dumps", "Date", "File", "Size", "Stop code", "Meaning", "Faulting driver");
            var found = new List<KeyValuePair<DateTime, uint>>();
            foreach (var d in dumps)
            {
                if (d.Code != null) found.Add(new KeyValuePair<DateTime, uint>(d.File.LastWriteTime, d.Code.Value));
                t.Rows.Add(new[]
                {
                    Fmt.Seconds(d.File.LastWriteTime), d.File.Name, Fmt.Bytes(d.File.Length), d.Code == null ? "Unreadable" : "0x" + d.Code.Value.ToString("X8"),
                    d.Code == null ? "" : BugCheckName(d.Code.Value), d.Driver ?? ""
                });
            }
            if (dumps.Any(d => d.Driver != null))
                s.Note("The faulting driver is the one holding the code address the stop code reports. It's usually the cause, but a driver can also crash because another one corrupted memory.");
            RepeatedCrashes(r, found);
            if (t.Rows.Count > 0) s.Note("A crash dump's time is when Windows finished saving it, usually during the restart after the crash.");
            var full = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "MEMORY.DMP");
            if (File.Exists(full))
            {
                var info = new FileInfo(full);
                s.Add("Full memory dump", Fmt.Time(info.LastWriteTime) + ", " + Fmt.Bytes(info.Length));
            }
        }

        // Which stop code parameter holds the address of the code that failed. Others hold data addresses or status values.
        private static int? CodeAddressParameter(uint code)
        {
            switch (code)
            {
                case 0x50: return 3;
                case 0x0A: case 0xD1: case 0x100000D1: case 0xC5: return 4;
                case 0x1E: case 0x3B: case 0x7E: case 0x1000007E: case 0x8E: case 0x1000008E: case 0x116: return 2;
                default: return null;
            }
        }

        // Reads the stop code from the fixed header of a kernel dump and, for a small (triage) dump, which loaded driver holds the
        // failing code address. Layout: DUMP_HEADER64, then TRIAGE_DUMP64 at 0x2000 whose offsets are from the start of the file.
        // The dump's contents stay on the PC.
        private static void ReadDump(string path, DumpFile d)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var br = new BinaryReader(fs))
                {
                    var sig = new string(br.ReadChars(8));
                    if (sig == "PAGEDUMP") { fs.Position = 0x28; d.Code = br.ReadUInt32(); return; }
                    if (sig != "PAGEDU64") return;
                    fs.Position = 0x38; d.Code = br.ReadUInt32();
                    var param = CodeAddressParameter(d.Code.Value);
                    fs.Position = 0x40; var p = new ulong[4]; for (int i = 0; i < 4; i++) p[i] = br.ReadUInt64();
                    fs.Position = 0xF98; const uint triage = 4;
                    if (param == null || br.ReadUInt32() != triage) return;
                    d.Driver = DriverAt(fs, br, p[param.Value - 1]);
                }
            }
            catch (Exception) { /* keep whatever was read */ }
        }

        private static string DriverAt(FileStream fs, BinaryReader br, ulong address)
        {
            const long triageHeader = 0x2000, entrySize = 0x90, dllBase = 8 + 0x30, sizeOfImage = 8 + 0x40;
            fs.Position = triageHeader + 0x30;
            uint listOffset = br.ReadUInt32(), count = br.ReadUInt32();
            if (count == 0 || count > 4096 || listOffset + count * entrySize > fs.Length) return null;
            for (long i = 0; i < count; i++)
            {
                long entry = listOffset + i * entrySize;
                fs.Position = entry; uint nameOffset = br.ReadUInt32();
                fs.Position = entry + dllBase; ulong start = br.ReadUInt64();
                fs.Position = entry + sizeOfImage; uint size = br.ReadUInt32();
                if (address < start || address >= start + size) continue;
                if (nameOffset + 4 > fs.Length) return null;
                fs.Position = nameOffset; uint chars = br.ReadUInt32();
                if (chars == 0 || chars > 260 || nameOffset + 4 + chars * 2 > fs.Length) return null;
                return System.Text.Encoding.Unicode.GetString(br.ReadBytes((int)chars * 2));
            }
            return null;
        }

        private static string BugCheckName(uint code)
        {
            var names = new Dictionary<uint, string>
            {
                { 0x0A, "IRQL_NOT_LESS_OR_EQUAL" }, { 0x1A, "MEMORY_MANAGEMENT" }, { 0x1E, "KMODE_EXCEPTION_NOT_HANDLED" },
                { 0x3B, "SYSTEM_SERVICE_EXCEPTION" }, { 0x50, "PAGE_FAULT_IN_NONPAGED_AREA" }, { 0x7A, "KERNEL_DATA_INPAGE_ERROR" },
                { 0x7B, "INACCESSIBLE_BOOT_DEVICE" }, { 0x7E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED" }, { 0x7F, "UNEXPECTED_KERNEL_MODE_TRAP" },
                { 0x9F, "DRIVER_POWER_STATE_FAILURE" }, { 0xA0, "INTERNAL_POWER_ERROR" }, { 0xBE, "ATTEMPTED_WRITE_TO_READONLY_MEMORY" },
                { 0xC2, "BAD_POOL_CALLER" }, { 0xC4, "DRIVER_VERIFIER_DETECTED_VIOLATION" }, { 0xC5, "DRIVER_CORRUPTED_EXPOOL" },
                { 0xD1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL" }, { 0xEA, "THREAD_STUCK_IN_DEVICE_DRIVER" }, { 0xEF, "CRITICAL_PROCESS_DIED" },
                { 0xF4, "CRITICAL_OBJECT_TERMINATION" }, { 0xFC, "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY" }, { 0x101, "CLOCK_WATCHDOG_TIMEOUT" },
                { 0x109, "CRITICAL_STRUCTURE_CORRUPTION" }, { 0x116, "VIDEO_TDR_FAILURE" }, { 0x117, "VIDEO_TDR_TIMEOUT_DETECTED" },
                { 0x119, "VIDEO_SCHEDULER_INTERNAL_ERROR" }, { 0x124, "WHEA_UNCORRECTABLE_ERROR" }, { 0x133, "DPC_WATCHDOG_VIOLATION" },
                { 0x139, "KERNEL_SECURITY_CHECK_FAILURE" }, { 0x13A, "KERNEL_MODE_HEAP_CORRUPTION" }, { 0x154, "UNEXPECTED_STORE_EXCEPTION" },
                { 0x18B, "SECURE_KERNEL_ERROR" }, { 0x1000007E, "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M" }, { 0x1000008E, "KERNEL_MODE_EXCEPTION_NOT_HANDLED_M" },
                { 0x100000D1, "DRIVER_IRQL_NOT_LESS_OR_EQUAL_M" }
            };
            string name;
            return names.TryGetValue(code, out name) ? name : "Look up code 0x" + code.ToString("X", CultureInfo.InvariantCulture);
        }
    }
}
