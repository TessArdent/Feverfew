using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Feverfew.Collectors
{
    /// <summary>
    /// Classifies device filter drivers (UpperFilters and LowerFilters) and the drivers that keep memory integrity off.
    /// Pure: FilterCollector reads the registry, WMI and the event log and hands the values in, so the tests need none of them.
    /// </summary>
    public static class FilterDriverAudit
    {
        /// <summary>A filter named in a class key (every device of that class) or in one device's Enum key.</summary>
        public sealed class Placement
        {
            public string Service;
            public bool ClassWide;
            public string Where;   // "Keyboard class" or the device's name
            public bool Upper;     // UpperFilters, else LowerFilters
        }

        /// <summary>What the PC has for a filter's service.</summary>
        public sealed class ServiceInfo
        {
            public bool Exists;        // a Services key for it
            public string File;        // the resolved driver path, or null
            public bool FileExists;
            public string Company;     // from the file's version info
            public bool Running;
            public string StartMode;
        }

        public enum Problem { None, MissingService, MissingFile, NotRunning }

        public sealed class Row
        {
            public Placement Placement;
            public ServiceInfo Service;
            public Problem Problem;
        }

        /// <summary>A REG_MULTI_SZ (or a stray REG_SZ) as a list of service names.</summary>
        public static List<string> Names(object value)
        {
            IEnumerable<string> raw = value is string[] ? (string[])value : value is string ? new[] { (string)value } : new string[0];
            return raw.Select(v => (v ?? "").Trim()).Where(v => v.Length > 0).ToList();
        }

        public static bool IsMicrosoft(string company)
        {
            return (company ?? "").IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>The non-Microsoft filters, each with what's wrong with it. A filter whose driver is missing is always listed.</summary>
        public static List<Row> Classify(IEnumerable<Placement> placements, Func<string, ServiceInfo> lookup)
        {
            var rows = new List<Row>();
            foreach (var p in placements)
            {
                var s = lookup(p.Service) ?? new ServiceInfo();
                var problem = !s.Exists ? Problem.MissingService : !s.FileExists ? Problem.MissingFile : !s.Running ? Problem.NotRunning : Problem.None;
                if (problem != Problem.MissingService && problem != Problem.MissingFile && IsMicrosoft(s.Company)) continue;
                rows.Add(new Row { Placement = p, Service = s, Problem = problem });
            }
            return rows.OrderByDescending(r => r.Placement.ClassWide).ThenBy(r => r.Placement.Service, StringComparer.OrdinalIgnoreCase).ToList();
        }

        public static string State(Row r)
        {
            switch (r.Problem)
            {
                case Problem.MissingService: return "Driver not installed";
                case Problem.MissingFile: return "Driver file missing";
                case Problem.NotRunning: return "Not running";
                default: return "Running";
            }
        }

        private static string Describe(Row r)
        {
            return r.Placement.Service + " on " + (r.Placement.ClassWide ? "every device in the " + r.Placement.Where : r.Placement.Where);
        }

        public const string RemoveAdvice = "Remove the program that added it with its own uninstaller (Settings > Apps), and restart. Don't delete the driver file or its service by hand: while it's still listed as a filter, Windows can't start the devices it filters, and for a keyboard or mouse filter that leaves you without a keyboard or mouse.";

        /// <summary>The Warning for filters pointing at a missing driver, or null.</summary>
        public static Finding MissingFinding(List<Row> rows)
        {
            var missing = rows.Where(r => r.Problem == Problem.MissingService || r.Problem == Problem.MissingFile).ToList();
            if (missing.Count == 0) return null;
            bool classWide = missing.Any(r => r.Placement.ClassWide);
            return new Finding
            {
                Severity = Severity.Warning,
                Title = "A device filter points at a missing driver",
                Detail = string.Join("; ", missing.Take(4).Select(Describe)) + ". "
                    + (classWide ? "A filter listed for a whole class with no driver behind it can stop every device in that class from starting." : "The device can fail to start while its filter's driver is missing."),
                Advice = "Reinstall the program that added the filter, then remove it with its own uninstaller, which takes the filter entry out too. Editing the UpperFilters or LowerFilters values by hand can leave devices unusable, so leave that to a technician with a registry backup."
            };
        }

        /// <summary>The Info finding for filters that are installed but not running, or null.</summary>
        public static Finding NotRunningFinding(List<Row> rows)
        {
            var idle = rows.Where(r => r.Problem == Problem.NotRunning).ToList();
            if (idle.Count == 0) return null;
            return new Finding
            {
                Severity = Severity.Info,
                Title = "A device filter driver is installed but not running",
                Detail = string.Join("; ", idle.Take(4).Select(Describe)) + ". A filter that fails to start is often left over from removed software or doesn't suit this version of Windows, and it can keep memory integrity off.",
                Advice = "If you don't use the program it belongs to, " + char.ToLowerInvariant(RemoveAdvice[0]) + RemoveAdvice.Substring(1)
            };
        }

        // ---- Memory integrity ----

        /// <summary>CodeIntegrity/Operational events that name a module "not compatible with hypervisor enforcement".</summary>
        public static readonly int[] BlockerEventIds = { 3072, 3073, 3087, 3111 };

        public sealed class Blocker
        {
            public string File;        // the file name, such as hidusbf.sys
            public string Path;        // as the event gave it
            public DateTime Last;
            public bool Installed;     // still on disk or still a service now
        }

        /// <summary>One entry per driver file, newest report first. installed says whether the file is still there.</summary>
        public static List<Blocker> Blockers(IEnumerable<KeyValuePair<DateTime, string>> events, Func<string, bool> installed)
        {
            return events.Where(e => !string.IsNullOrWhiteSpace(e.Value))
                .GroupBy(e => FileName(e.Value), StringComparer.OrdinalIgnoreCase)
                .Select(g =>
                {
                    var newest = g.OrderByDescending(e => e.Key).First();
                    return new Blocker { File = FileName(newest.Value), Path = newest.Value.Trim(), Last = newest.Key, Installed = installed(newest.Value.Trim()) };
                })
                .OrderByDescending(b => b.Installed).ThenByDescending(b => b.Last).ToList();
        }

        public static string FileName(string path)
        {
            var p = (path ?? "").Trim().TrimEnd('\0');
            int slash = p.LastIndexOf('\\');
            return slash >= 0 ? p.Substring(slash + 1) : p;
        }

        /// <summary>Turns an event's kernel path into a Win32 path where it can: \SystemRoot\..., \??\C:\..., or ...\Windows\....</summary>
        public static string Win32Path(string path, string windows)
        {
            var p = (path ?? "").Trim().TrimEnd('\0');
            if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p.Substring(4);
            if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) return System.IO.Path.Combine(windows, p.Substring(12));
            if (p.Length > 2 && p[1] == ':') return p;
            int at = p.IndexOf(@"\Windows\", StringComparison.OrdinalIgnoreCase);
            if (p.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase) && at >= 0) return System.IO.Path.Combine(windows, p.Substring(at + 9));
            return null;
        }

        /// <summary>The Info finding naming the drivers that keep memory integrity off, or null when it's on or nothing is known.</summary>
        public static Finding BlockersFinding(bool? memoryIntegrityOn, List<Blocker> blockers)
        {
            if (memoryIntegrityOn != false) return null;
            var present = blockers.Where(b => b.Installed).ToList();
            if (present.Count == 0) return null;
            return new Finding
            {
                Severity = Severity.Info,
                Title = "Driver" + (present.Count == 1 ? "" : "s") + " keeping memory integrity off: " + string.Join(", ", present.Take(4).Select(b => b.File)),
                Detail = "Windows logged " + (present.Count == 1 ? "this driver" : "these drivers") + " as not compatible with memory integrity (Core isolation), which protects Windows from malicious drivers. Memory integrity can't be turned on while " + (present.Count == 1 ? "it's" : "they're") + " installed.",
                Advice = RemoveAdvice + " Then turn memory integrity on in Windows Security > Device security > Core isolation. If the driver belongs to hardware you use, look for an update from its maker instead."
            };
        }
    }
}
