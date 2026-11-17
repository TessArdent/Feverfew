using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace Feverfew.Collectors
{
    /// <summary>
    /// Checks for the AMD driver bug, found in late 2026, where the External Events Utility (atieclxx.exe) copies
    /// itself into the SYSTEM profile every second, writing tens of gigabytes a day to the Windows drive.
    /// AMD Software 26.11.1 fixes it. The fix in Fixes.All blocks that one copy, like the community workaround does.
    /// </summary>
    public static class AmdWritesCollector
    {
        public const string CopyPathForCommands = @"%SystemRoot%\System32\config\systemprofile\AppData\Local\AMD\atieclxx.exe";
        private static readonly string CopyPath = Environment.ExpandEnvironmentVariables(CopyPathForCommands);
        public static readonly Version FixedIn = new Version(26, 11, 1);
        private const string LocalSystem = "S-1-5-18";
        private const int SampleMs = 4000;
        // The copy happens every second while the bug is active, so an older change means it has stopped.
        private static readonly TimeSpan RecentChange = TimeSpan.FromSeconds(10);
        // Normal use writes almost nothing. Reports of the bug range from 300 KB/s to 5 MB/s.
        private const double HighWriteBytesPerSecond = 100 * 1024;

        public enum CopyState { Missing, Rewriting, Quiet, Blocked }

        public static void Collect(Report r)
        {
            var versions = GamingCollector.AmdAdapters().Where(a => a.SoftwareVersion != null).ToList();
            var before = Utility();
            if (versions.Count == 0 && before.Count == 0 && !File.Exists(CopyPath)) return;

            var s = r.NewSection("Graphics driver disk writes");
            Version installed = null;
            foreach (var a in versions)
            {
                s.Add("AMD Software version (" + a.Name + ")", a.SoftwareVersion);
                Version v;
                if (TryParseVersion(a.SoftwareVersion, out v) && (installed == null || v > installed)) installed = v;
            }
            bool fixedDriver = installed != null && installed >= FixedIn;

            double? rate = null;
            Guard.Try(s, "AMD External Events Utility", () =>
            {
                if (before.Count == 0) { s.Add("AMD External Events Utility (atieclxx.exe)", "Not running"); return; }
                Thread.Sleep(SampleMs);
                var after = Utility();
                foreach (var p in before)
                {
                    Row later = after.FirstOrDefault(x => x.Long("ProcessId") == p.Long("ProcessId"));
                    long? start = p.Long("WriteTransferCount"), end = later == null ? null : later.Long("WriteTransferCount");
                    if (start == null || end == null) { s.Add("AMD External Events Utility (atieclxx.exe)", "Running; its disk writes couldn't be read"); continue; }
                    double perSecond = (end.Value - start.Value) * 1000.0 / SampleMs;
                    rate = Math.Max(rate ?? 0, perSecond);
                    s.Add("atieclxx.exe writes during the scan", Fmt.Bytes((long)perSecond) + "/s");
                    var started = p.Date("CreationDate");
                    if (started != null && DateTime.Now > started.Value)
                        s.Add("atieclxx.exe writes since it started", Fmt.Bytes(end) + " in " + Fmt.Duration(DateTime.Now - started.Value));
                }
            });

            CopyState? copy = null;
            Guard.Try(s, "atieclxx.exe copy", () =>
            {
                copy = Copy();
                s.Add("Copy in the SYSTEM profile", Describe(copy.Value));
            });

            if (copy != null && copy != CopyState.Missing)
                Guard.Try(s, "Damage estimate", () => Assess(r, s, copy.Value, rate, DriverInstalled(before)));

            bool rewriting = copy == CopyState.Rewriting;
            bool heavy = rate != null && rate >= HighWriteBytesPerSecond;
            var update = installed == null
                ? "Update AMD Software to 26.11.1 or later, which fixes this."
                : "Update AMD Software from " + installed + " to 26.11.1 or later, which fixes this.";

            if (rewriting || heavy)
            {
                var detail = "AMD's External Events Utility (atieclxx.exe) "
                    + (rewriting ? "is copying itself over a file in the SYSTEM profile every second" : "is writing to the disk constantly")
                    + (rate != null ? ", at " + Fmt.Bytes((long)rate.Value) + "/s, which is about " + Fmt.Bytes((long)(rate.Value * 86400)) + " a day" : "")
                    + ". This known AMD driver bug wears out SSDs faster.";
                var advice = fixedDriver
                    ? "This driver should already include AMD's fix. Restart the PC, and if it continues, use Stop AMD's constant drive writes in Repair tools."
                    : update + " Until then, use Stop AMD's constant drive writes in Repair tools.";
                r.Find(Severity.Warning, "AMD graphics driver is writing to the drive nonstop", detail, advice);
            }
            else if (copy == CopyState.Blocked && fixedDriver)
                r.Find(Severity.Info, "Feverfew's block on AMD's constant drive writes is no longer needed", "AMD Software " + installed + " includes AMD's fix.", "Use Undo on Stop AMD's constant drive writes in Repair tools.");
            else if (installed != null && !fixedDriver)
                r.Find(Severity.Info, "AMD driver predates its fix for excessive drive writes", "AMD Software " + installed + " is installed. Version 26.11.1 fixes constant background writes and writes while moving or resizing windows.", "Update AMD Software if it's offered for your card.");

            if (rate == null && copy == null)
                s.Note("Run as administrator to check whether the AMD driver is writing to the drive constantly.");
            s.Note("A late-2026 AMD driver bug made atieclxx.exe copy itself to " + CopyPathForCommands + " every second. AMD Software 26.11.1 fixes it. Disabling the AMD External Events Utility service also stops it, but can affect FreeSync and frame pacing, so Feverfew blocks only that one copy instead.");
        }

        /// <summary>Status line for the Repair tools page.</summary>
        public static string Status()
        {
            if (!File.Exists(CopyPath) && Utility().Count == 0) return "Not needed: the AMD External Events Utility isn't running";
            CopyState state;
            try { state = Copy(); }
            catch (UnauthorizedAccessException) { return "Restart Feverfew as administrator to check this"; }
            switch (state)
            {
                case CopyState.Rewriting: return "Worth applying: the AMD driver is rewriting this file every second";
                case CopyState.Blocked: return "Already applied: the copy is blocked. Undo it once AMD Software 26.11.1 or later is installed";
                case CopyState.Missing: return "Not needed: this PC doesn't have the file";
                default: return "Not needed: the file isn't being rewritten";
            }
        }

        private static string Describe(CopyState state)
        {
            switch (state)
            {
                case CopyState.Missing: return "Not present";
                case CopyState.Rewriting: return "Being rewritten every few seconds";
                case CopyState.Blocked: return "Blocked by Feverfew";
                default: return "Not changing";
            }
        }

        private static List<Row> Utility()
        {
            return Wmi.Cim("SELECT ProcessId, CreationDate, WriteTransferCount, ExecutablePath FROM Win32_Process WHERE Name = 'atieclxx.exe'");
        }

        public static bool TryParseVersion(string text, out Version version)
        {
            version = null;
            if (string.IsNullOrWhiteSpace(text)) return false;
            var parts = text.Trim().Split('.', ' ', '-');
            var numbers = new List<int>();
            foreach (var p in parts)
            {
                int n;
                if (!int.TryParse(p, out n)) break;
                numbers.Add(n);
                if (numbers.Count == 3) break;
            }
            if (numbers.Count < 2) return false;
            version = new Version(numbers[0], numbers[1], numbers.Count > 2 ? numbers[2] : 0);
            return true;
        }

        private static CopyState Copy()
        {
            if (!File.Exists(CopyPath))
            {
                // File.Exists also returns false when the folder can't be read, which needs administrator rights.
                if (!Scanner.IsElevated()) throw new UnauthorizedAccessException();
                return CopyState.Missing;
            }
            if (Blocked()) return CopyState.Blocked;
            var changed = Times().ChangeTime;
            if (changed <= 0) return CopyState.Quiet;
            return DateTime.UtcNow - DateTime.FromFileTimeUtc(changed) < RecentChange ? CopyState.Rewriting : CopyState.Quiet;
        }

        private static bool Blocked()
        {
            var rules = File.GetAccessControl(CopyPath).GetAccessRules(true, false, typeof(SecurityIdentifier));
            return rules.Cast<FileSystemAccessRule>().Any(rule => rule.AccessControlType == AccessControlType.Deny
                && rule.IdentityReference.Value == LocalSystem
                && (rule.FileSystemRights & FileSystemRights.WriteData) != 0);
        }

        // CopyFile carries the source's last-write time over, so only NTFS's change time shows when the copy was last made.
        // Overwriting keeps the creation time, so that shows when the copying began.
        private static FileBasicInfo Times()
        {
            using (var handle = CreateFile(CopyPath, FileReadAttributes, ShareAll, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero))
            {
                if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                FileBasicInfo info;
                if (!GetFileInformationByHandleEx(handle, FileBasicInfoClass, out info, (uint)Marshal.SizeOf(typeof(FileBasicInfo))))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return info;
            }
        }

        /// <summary>
        /// Estimates what the bug has written to each drive and how much of each drive's wear that is. The copy only goes
        /// to the Windows drive, so other drives are listed to show they're untouched.
        /// </summary>
        private static void Assess(Report r, Section s, CopyState copy, double? measuredRate, DateTime? driverInstalledUtc)
        {
            var times = Times();
            long copySize = new FileInfo(CopyPath).Length;
            var created = DateTime.FromFileTimeUtc(times.CreationTime);
            var now = DateTime.UtcNow;
            var end = copy == CopyState.Rewriting ? now : DateTime.FromFileTimeUtc(times.ChangeTime);
            var start = created;
            // A creation time this recent means the file was replaced rather than overwritten, so it doesn't show when the bug began.
            // The installed driver's date is then the best guess, though the bug may have begun later.
            if (end - start < TimeSpan.FromHours(1) && copy == CopyState.Rewriting && driverInstalledUtc != null) start = driverInstalledUtc.Value;
            if (end - start < TimeSpan.FromHours(1))
            {
                s.Note("Damage estimate: the copy's dates don't show when the bug began, so no estimate is given.");
                return;
            }

            // While the bug runs, each copy rewrites the whole file once a second.
            double rate = measuredRate != null && measuredRate >= HighWriteBytesPerSecond ? Math.Max(measuredRate.Value, copySize) : copySize;
            string method;
            double hours = DriveWear.RunningHours(start, end, out method);
            double bugBytes = rate * hours * 3600;

            s.Add("Bug active", Fmt.Date(start.ToLocalTime()) + " to " + (copy == CopyState.Rewriting ? "now" : Fmt.Date(end.ToLocalTime())) + ", about " + Fmt.Num(hours, "0") + " hours of the PC running");
            s.Add("Running time", Fmt.Clip(method, 200));
            s.Add("Estimated writes from this bug", Fmt.Bytes((long)bugBytes) + " at " + Fmt.Bytes((long)rate) + "/s");

            var systemDisk = SystemDiskNumber();
            var t = s.Table("Estimated damage to each drive", "Drive", "Type", "Size", "Written by this bug", "Written in the drive's life", "Share from this bug", "Wear", "Wear from this bug");
            double worstShare = 0, worstWearPoints = 0;
            string worstDrive = null;
            foreach (var pair in Wmi.QueryRelated(StorageNs, "SELECT * FROM MSFT_PhysicalDisk", "MSFT_StorageReliabilityCounter"))
            {
                var d = pair.Key; var c = pair.Value;
                int number;
                if (!int.TryParse(d.Str("DeviceId"), out number)) continue;
                var name = d.Str("FriendlyName");
                bool hdd = d.Long("MediaType") == 3;
                long size = d.Long("Size") ?? 0;
                bool hit = number == systemDisk;

                var nvme = Guarded(() => DriveWear.ReadNvme(number));
                long? lifetime = nvme == null ? (long?)null : nvme.BytesWritten;
                int? wear = nvme != null ? nvme.PercentageUsed : c != null && c.Long("Wear") != null ? (int?)c.Long("Wear") : null;

                string written = hit ? Fmt.Bytes((long)bugBytes) : "Nothing";
                string share = "-", wearFromBug = "-";
                if (hit && hdd)
                    wearFromBug = "Hard drives don't wear out from writes the way SSDs do";
                else if (hit)
                {
                    double? points = null;
                    if (lifetime > 0)
                    {
                        double fraction = Math.Min(1, bugBytes / lifetime.Value);
                        share = Fmt.Num(fraction * 100, "0.#") + "%";
                        if (fraction > worstShare) { worstShare = fraction; worstDrive = name; }
                        if (wear != null) points = wear.Value * fraction;
                    }
                    if (points == null && size > 0)
                        // Without the drive's own total, compare with a typical rating of 600 TB written per TB of capacity.
                        points = bugBytes / (600.0 * size) * 100;
                    if (points != null)
                    {
                        wearFromBug = "About " + Fmt.Num(points.Value, points.Value < 1 ? "0.##" : "0.#") + " percentage points" + (lifetime > 0 && wear != null ? "" : " (typical rating)");
                        if (points.Value > worstWearPoints) { worstWearPoints = points.Value; worstDrive = name; }
                    }
                }
                t.Rows.Add(new[]
                {
                    name, hdd ? "HDD" : d.Long("MediaType") == 4 ? "SSD" : "Unknown", Fmt.Bytes(size), written,
                    lifetime == null ? "Not reported" : Fmt.Bytes(lifetime), share, wear == null ? "-" : wear + "%", wearFromBug
                });
            }

            if (worstDrive != null && (worstWearPoints >= 1 || worstShare >= 0.1))
                r.Find(copy == CopyState.Rewriting ? Severity.Warning : Severity.Info, "AMD driver bug has added wear to " + worstDrive,
                    "It wrote an estimated " + Fmt.Bytes((long)bugBytes) + (worstShare > 0 ? ", about " + Fmt.Num(worstShare * 100, "0") + "% of everything written to the drive," : "") + " costing about " + Fmt.Num(worstWearPoints, "0.#") + " points of its rated life.",
                    "The wear can't be undone, but stopping the bug stops it growing. Keep backups current if the drive's wear is high.");
            s.Note("Damage estimates assume the copy ran once a second whenever the PC was on, and that SSD wear grows with the amount written. Small repeated writes can wear an SSD faster than this suggests. 'Wear' is the drive's own percentage of rated life used; NVMe drives report their lifetime writes, other drives are compared with a typical rating.");
        }

        private const string StorageNs = @"root\Microsoft\Windows\Storage";

        private static int? SystemDiskNumber()
        {
            char letter = char.ToUpperInvariant(Path.GetPathRoot(Environment.SystemDirectory)[0]);
            foreach (var p in Wmi.Query(StorageNs, "SELECT DiskNumber, DriveLetter FROM MSFT_Partition"))
            {
                var raw = p.Raw("DriveLetter");
                if (raw != null && char.ToUpperInvariant(Convert.ToChar(raw)) == letter) return (int?)p.Long("DiskNumber");
            }
            return null;
        }

        private static T Guarded<T>(Func<T> read) where T : class
        {
            try { return read(); }
            catch (Exception) { return null; }
        }

        // The driver store folder is created when the driver is installed.
        private static DateTime? DriverInstalled(List<Row> processes)
        {
            foreach (var p in processes)
            {
                var path = p.Str("ExecutablePath");
                // Only a driver store folder dates the install; System32 itself dates from Windows' setup.
                if (path.IndexOf(@"\DriverStore\", StringComparison.OrdinalIgnoreCase) < 0) continue;
                var folder = Path.GetDirectoryName(path);
                if (Directory.Exists(folder)) return Directory.GetCreationTimeUtc(folder);
            }
            return null;
        }

        private const uint FileReadAttributes = 0x80;
        private const uint ShareAll = 0x7;
        private const uint OpenExisting = 3;
        private const int FileBasicInfoClass = 0;

        [StructLayout(LayoutKind.Sequential)]
        private struct FileBasicInfo
        {
            public long CreationTime, LastAccessTime, LastWriteTime, ChangeTime;
            public uint FileAttributes;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int infoClass, out FileBasicInfo info, uint size);
    }
}
