using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using Microsoft.Win32;

namespace Feverfew.Collectors
{
    public static class HardwareCollector
    {
        public static void Processor(Report r)
        {
            var s = r.NewSection("Processor");
            Guard.Try(s, "CPU", () =>
            {
                var cpus = Wmi.Cim("SELECT * FROM Win32_Processor");
                bool hypervisor = false;
                Guard.Try(s, "Hypervisor", () => { hypervisor = Wmi.Cim("SELECT HypervisorPresent FROM Win32_ComputerSystem").FirstOrDefault()?.Bool("HypervisorPresent") == true; });
                var live = SampleCpu();
                foreach (var c in cpus)
                {
                    s.Add("Model", c.Str("Name"));
                    s.Add("Socket", c.Str("SocketDesignation"));
                    s.Add("Cores / threads", c.Str("NumberOfCores") + " / " + c.Str("NumberOfLogicalProcessors"));
                    s.Add("Base speed", c.Str("MaxClockSpeed") + " MHz");
                    // Win32_Processor's CurrentClockSpeed and LoadPercentage are the base speed and often empty, so use the performance counters.
                    if (live != null && c.Long("MaxClockSpeed") > 0)
                        s.Add("Speed during scan", Fmt.Num(c.Long("MaxClockSpeed").Value * live.Item1 / 100.0, "0") + " MHz");
                    s.Add("L2 / L3 cache", Fmt.Bytes(c.Long("L2CacheSize") * 1024) + " / " + Fmt.Bytes(c.Long("L3CacheSize") * 1024));
                    if (live != null) s.Add("Load during scan", Fmt.Num(Math.Min(100, live.Item2), "0") + "%");
                    // With Windows' hypervisor running, Windows reports firmware virtualization as off even though it's in use.
                    s.Add("Virtualization on in firmware", hypervisor ? "Yes (in use by Windows' hypervisor)" : Fmt.YesNo(c.Bool("VirtualizationFirmwareEnabled")));
                }
                var first = cpus.First();
                r.AddSummary("CPU", first.Str("Name"));
                r.Signals.CpuCores = (int?)cpus.Sum(c => c.Long("NumberOfCores") ?? 0);
                r.Signals.CpuMhz = (int?)first.Long("MaxClockSpeed");
            });

            Guard.Try(s, "Temperature sensors", () =>
            {
                var zones = Wmi.Query(@"root\wmi", "SELECT InstanceName, CurrentTemperature FROM MSAcpi_ThermalZoneTemperature");
                var t = s.Table("Motherboard thermal zones", "Zone", "Temperature");
                foreach (var z in zones)
                {
                    var c = (z.Long("CurrentTemperature") ?? 0) / 10.0 - 273.15;
                    if (c < 1 || c > 125) continue; // many boards report placeholder values
                    t.Rows.Add(new[] { z.Str("InstanceName"), Fmt.Num(c, "0") + " °C" });
                    if (c >= 90)
                        r.Find(Severity.Warning, "Running hot", "A thermal zone reported " + Fmt.Num(c, "0") + " °C during the scan.", "Clean the dust out and check that the fans spin.");
                }
                if (t.Rows.Count == 0) s.Tables.Remove(t);
                s.Note("Windows only exposes motherboard thermal zones, so these aren't per-core CPU temperatures.");
            });
        }

        /// <summary>Performance as a percentage of base speed, and utility (Task Manager's CPU figure), averaged over about a second. Null if unavailable.</summary>
        private static Tuple<double, double> SampleCpu()
        {
            try
            {
                const string q = "SELECT PercentProcessorPerformance, PercentProcessorUtility FROM Win32_PerfFormattedData_Counters_ProcessorInformation WHERE Name='_Total'";
                Wmi.Cim(q); // the first read only primes the counters
                double perf = 0, util = 0;
                for (int i = 0; i < 2; i++)
                {
                    System.Threading.Thread.Sleep(500);
                    var row = Wmi.Cim(q).FirstOrDefault();
                    if (row == null || row.Long("PercentProcessorPerformance") == null) return null;
                    perf += row.Long("PercentProcessorPerformance").Value / 2.0;
                    util += (row.Long("PercentProcessorUtility") ?? 0) / 2.0;
                }
                return perf > 0 ? Tuple.Create(perf, util) : null;
            }
            catch (Exception) { return null; }
        }

        public static void Memory(Report r)
        {
            var s = r.NewSection("Memory");
            Guard.Try(s, "Memory modules", () =>
            {
                var sticks = Wmi.Cim("SELECT * FROM Win32_PhysicalMemory");
                var t = s.Table("Installed modules", "Slot", "Size", "Rated speed", "Running at", "Maker", "Part number", "Serial");
                long total = 0;
                foreach (var m in sticks)
                {
                    total += m.Long("Capacity") ?? 0;
                    var rated = RatedSpeed(m);
                    bool fromPart = rated > (m.Long("Speed") ?? 0);
                    t.Rows.Add(new[]
                    {
                        m.Str("DeviceLocator"), Fmt.Bytes(m.Long("Capacity")), rated + " MT/s" + (fromPart ? " (from part number)" : ""), m.Str("ConfiguredClockSpeed") + " MT/s",
                        m.Str("Manufacturer"), m.Str("PartNumber"), r.Private(m.Str("SerialNumber"))
                    });
                }
                s.Add("Total installed", Fmt.Bytes(total));
                r.Signals.RamGb = total / 1073741824.0;
                var speed = sticks.Select(m => m.Long("ConfiguredClockSpeed")).FirstOrDefault(v => v > 0);
                r.AddSummary("Memory", Fmt.Bytes(total) + " in " + sticks.Count + " module" + (sticks.Count == 1 ? "" : "s") + (speed != null ? " at " + speed + " MT/s" : ""));

                Guard.Try(s, "Memory slots", () =>
                {
                    var a = Wmi.Cim("SELECT MemoryDevices, MaxCapacityEx FROM Win32_PhysicalMemoryArray").FirstOrDefault();
                    if (a != null) s.Add("Slots used", sticks.Count + " of " + a.Str("MemoryDevices"));
                });

                if (sticks.Select(m => m.Long("Capacity")).Distinct().Count() > 1 || sticks.Select(m => m.Str("PartNumber")).Distinct().Count() > 1)
                    r.Find(Severity.Info, "Mixed memory modules", "The installed RAM sticks aren't an identical set.",
                        "Mixed kits usually work, but they're a common cause of random crashes when memory runs at higher speeds.");

                var slow = sticks.Where(m => RatedSpeed(m) > 0 && m.Long("ConfiguredClockSpeed") > 0 && m.Long("ConfiguredClockSpeed") < RatedSpeed(m) * 0.97).ToList(); // DDR5-5200 at its 4800 fallback is only 8% slow
                if (slow.Count > 0)
                    r.Find(Severity.Info, "Memory is running below its rated speed",
                        "Rated " + RatedSpeed(slow[0]) + " MT/s, running at " + slow[0].Str("ConfiguredClockSpeed") + " MT/s.",
                        "In BIOS setup, turn on the memory profile (XMP, EXPO, or D.O.C.P. on ASUS) and leave the other settings on Auto. It can help performance in games. Test with MemTest86 afterwards, and if the PC crashes with it on, turn it back off.");
            });
        }

        // Without XMP or EXPO on, Windows often reports the fallback speed as the rating.
        private static long RatedSpeed(Row stick)
        {
            return Math.Max(stick.Long("Speed") ?? 0, RatedFromPartNumber(stick.Str("PartNumber")) ?? 0);
        }

        /// <summary>Reads the speed out of part numbers like KHX3200C16D4/8GX, CMK16GX4M2B3200C16 or HX432C16FB3/8.</summary>
        private static long? RatedFromPartNumber(string part)
        {
            const System.Text.RegularExpressions.RegexOptions ignore = System.Text.RegularExpressions.RegexOptions.IgnoreCase;
            var full = System.Text.RegularExpressions.Regex.Match(part ?? "", @"(?<!\d)([2-8]\d{3})CL?\d{2}(?!\d)", ignore);
            if (full.Success) return long.Parse(full.Groups[1].Value);
            var hyperX = System.Text.RegularExpressions.Regex.Match(part ?? "", @"^K?HX4(\d{2})[CS]\d{2}", ignore);
            if (!hyperX.Success) return null;
            switch (hyperX.Groups[1].Value)
            {
                case "26": return 2666;
                case "29": return 2933;
                default: return long.Parse(hyperX.Groups[1].Value) * 100;
            }
        }

        public static void Graphics(Report r)
        {
            var s = r.NewSection("Graphics and displays");
            Guard.Try(s, "Graphics adapters", () =>
            {
                var gpus = Wmi.Cim("SELECT * FROM Win32_VideoController");
                var t = s.Table("Graphics adapters", "Name", "Memory", "Driver version", "Driver date", "Current mode", "Status");
                foreach (var g in gpus)
                {
                    var date = DriverDate(g.Str("PNPDeviceID")) ?? g.Date("DriverDate");
                    var mode = g.Long("CurrentHorizontalResolution") > 0
                        ? g.Str("CurrentHorizontalResolution") + " x " + g.Str("CurrentVerticalResolution") + " at " + g.Str("CurrentRefreshRate") + " Hz" : "Inactive";
                    bool isVirtual = IsVirtualDisplay(g.Str("Name"));
                    t.Rows.Add(new[] { g.Str("Name") + (isVirtual ? " (virtual)" : ""), Fmt.Bytes(VideoMemory(g.Str("Name")) ?? g.Long("AdapterRAM")), g.Str("DriverVersion"), DateText(date), mode, g.Str("Status") });

                    if (isVirtual) continue;
                    if (g.Str("Name").IndexOf("Basic Display", StringComparison.OrdinalIgnoreCase) >= 0)
                        r.Find(Severity.Warning, "No proper graphics driver", "Windows is using the Microsoft Basic Display Adapter.", "Install the driver from NVIDIA, AMD, Intel, or the PC maker.");
                    else if (date != null && !IsPlaceholder(date.Value) && (DateTime.Now - date.Value).TotalDays > 365 * 2)
                        r.Find(Severity.Info, "Old graphics driver", g.Str("Name") + " has a driver dated " + Fmt.Date(date) + ".", "Update it from the graphics card maker's site if games or video misbehave.");
                }
                var real = gpus.Where(g => !IsVirtualDisplay(g.Str("Name"))).ToList();
                r.AddSummary("Graphics", string.Join(", ", (real.Count > 0 ? real : gpus).Select(g => g.Str("Name"))));
            });

            Guard.Try(s, "Monitors", () =>
            {
                var displays = DisplayInfo.Active();
                if (displays.Count == 0)
                {
                    var old = s.Table("Connected monitors", "Maker code", "Model");
                    foreach (var m in Wmi.Query(@"root\wmi", "SELECT ManufacturerName, UserFriendlyName FROM WmiMonitorID"))
                        old.Rows.Add(new[] { Decode(m.Raw("ManufacturerName")), Decode(m.Raw("UserFriendlyName")) });
                    return;
                }
                var t = s.Table("Connected monitors", "Monitor", "Connected to", "Resolution", "Refresh rate", "Highest at this resolution", "Main display");
                foreach (var d in displays)
                    t.Rows.Add(new[] { d.Name, d.Adapter, d.Width + " x " + d.Height, d.Hz + " Hz", d.MaxHzAtResolution + " Hz", Fmt.YesNo(d.Primary) });

                // A desktop with a graphics card whose monitor is plugged into the motherboard runs games on the processor's graphics.
                bool hasCard = Wmi.Cim("SELECT Name FROM Win32_VideoController").Any(g => DisplayInfo.IsDiscrete(g.Str("Name")));
                var onBoard = displays.Where(d => !d.Internal && DisplayInfo.IsIntegrated(d.Adapter)).ToList();
                if (hasCard && onBoard.Count > 0 && !Machine.IsLaptop())
                    r.Find(Severity.Warning, "A monitor is plugged into the motherboard",
                        string.Join(", ", onBoard.Select(d => d.Name)) + " is connected to " + onBoard[0].Adapter + ", the processor's graphics, even though this PC has a graphics card.",
                        "Plug it into one of the graphics card's outputs (the lower ports on the back of the PC). Games shown on it run slower, and the graphics card may sit idle.");
            });

            Guard.Try(s, "Sound devices", () =>
            {
                var t = s.Table("Sound devices", "Name", "Status");
                foreach (var d in Wmi.Cim("SELECT Name, Status FROM Win32_SoundDevice"))
                    t.Rows.Add(new[] { d.Str("Name"), d.Str("Status") });
            });
        }

        // Display adapters that remote desktop, streaming and VM software add. They have no hardware, so driver age and refresh rate don't matter.
        private static readonly string[] VirtualDisplayNames =
        {
            "Parsec Virtual", "Remote Display", "Remote Desktop", "Virtual Display", "IddCx", "Indirect Display", "spacedesk", "Citrix",
            "VMware SVGA", "VirtualBox", "Hyper-V Video", "Hyper-V Display", "Meta Virtual Monitor", "Virtual Desktop Monitor", "GameViewer", "Sunshine", "Splashtop", "AnyDesk", "TeamViewer"
        };

        public static bool IsVirtualDisplay(string name)
        {
            return VirtualDisplayNames.Any(v => (name ?? "").IndexOf(v, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        // Win32_VideoController.AdapterRAM stops at 4 GB; the driver's registry entry has the true size.
        private static long? VideoMemory(string name)
        {
            const string cls = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";
            try
            {
                using (var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var key = root.OpenSubKey(cls))
                {
                    foreach (var sub in key.GetSubKeyNames().Where(n => n.All(char.IsDigit)))
                        using (var k = key.OpenSubKey(sub))
                        {
                            if (!string.Equals(k.GetValue("DriverDesc") as string, name, StringComparison.OrdinalIgnoreCase)) continue;
                            var v = k.GetValue("HardwareInformation.qwMemorySize");
                            if (v != null) return Convert.ToInt64(v);
                        }
                }
            }
            catch (Exception) { /* fall back to AdapterRAM */ }
            return null;
        }

        private static string Decode(object raw)
        {
            var codes = raw as ushort[];
            if (codes == null) return "";
            var b = new StringBuilder();
            foreach (var c in codes) if (c != 0) b.Append((char)c);
            return b.ToString();
        }

        public static void Devices(Report r)
        {
            var s = r.NewSection("Devices and drivers");
            Guard.Try(s, "Problem devices", () =>
            {
                var bad = Wmi.Cim("SELECT Name, PNPDeviceID, ConfigManagerErrorCode, Status FROM Win32_PnPEntity WHERE ConfigManagerErrorCode <> 0");
                var t = s.Table("Devices with problems", "Device", "Hardware ID", "Problem");
                foreach (var d in bad)
                    t.Rows.Add(new[] { d.Str("Name"), ShortId(d.Str("PNPDeviceID")), ProblemText(d.Long("ConfigManagerErrorCode")) });
                // Code 22 means someone disabled the device on purpose, and 45 means it's unplugged.
                var real = bad.Where(d => d.Long("ConfigManagerErrorCode") != 22 && d.Long("ConfigManagerErrorCode") != 45).ToList();
                if (real.Count > 0)
                    r.Find(Severity.Warning, real.Count + " device" + (real.Count == 1 ? " has" : "s have") + " a driver or hardware problem",
                        string.Join("; ", real.Take(6).Select(d => (d.Str("Name").Length > 0 ? d.Str("Name") : ShortId(d.Str("PNPDeviceID"))) + " (code " + d.Str("ConfigManagerErrorCode") + ")")) + (real.Count > 6 ? "; and more" : ""),
                        "Open the 'Devices with problems' table. The hardware ID identifies the right driver to look for.");
            });

            Guard.Try(s, "USB devices", () =>
            {
                var t = s.Table("USB devices", "Name", "Status");
                foreach (var d in Wmi.Cim("SELECT Name, Status FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB\\\\VID%'").OrderBy(d => d.Str("Name")))
                    t.Rows.Add(new[] { d.Str("Name"), d.Str("Status") });
            });
        }

        public static void Drivers(Report r)
        {
            var s = r.NewSection("Third-party drivers");
            Guard.Try(s, "Drivers", () =>
            {
                var t = s.Table("Non-Microsoft drivers", "Device", "Provider", "Version", "Date", "Signed");
                var rows = Wmi.Cim("SELECT DeviceName, DeviceID, DriverProviderName, DriverVersion, DriverDate, IsSigned FROM Win32_PnPSignedDriver")
                    .Where(d => d.Str("DriverProviderName").Length > 0 && d.Str("DriverProviderName").IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) < 0)
                    .OrderBy(d => d.Str("DriverProviderName")).ThenBy(d => d.Str("DeviceName"))
                    .ToList();
                foreach (var d in rows)
                    t.Rows.Add(new[] { d.Str("DeviceName"), d.Str("DriverProviderName"), d.Str("DriverVersion"), DateText(DriverDate(d.Str("DeviceID"))), Fmt.YesNo(d.Bool("IsSigned")) });
                var unsigned = rows.Where(d => d.Bool("IsSigned") == false).ToList();
                if (unsigned.Count > 0)
                    r.Find(Severity.Warning, "Unsigned drivers installed", string.Join(", ", unsigned.Take(5).Select(d => d.Str("DeviceName"))), "Replace them with signed drivers from the device maker.");
            });

            Guard.Try(s, "Other kernel drivers", () => KernelDrivers(s));
        }

        // Drivers that belong to no device, such as anti-cheat, antivirus, VPN and backup software. They run in the kernel,
        // so they're common causes of blue screens, but the device driver list above doesn't show them.
        private static void KernelDrivers(Section s)
        {
            var deviceServices = new HashSet<string>(Wmi.Cim("SELECT Service FROM Win32_PnPEntity").Select(d => d.Str("Service")).Where(v => v.Length > 0), StringComparer.OrdinalIgnoreCase);
            var t = s.Table("Other third-party kernel drivers", "Driver", "Name", "Company", "Version", "Kind", "Starts", "Running");
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            foreach (var d in Wmi.Cim("SELECT Name, DisplayName, PathName, StartMode, State FROM Win32_SystemDriver").OrderBy(d => d.Str("Name")))
            {
                var name = d.Str("Name");
                if (deviceServices.Contains(name)) continue;
                bool running = d.Str("State") == "Running";
                var start = d.Str("StartMode");
                // Windows ships dozens of storage and network drivers from other makers that never load; only list what's loaded or set to load.
                if (!running && start != "Boot" && start != "System" && start != "Auto") continue;
                if (d.Str("DisplayName").StartsWith("Microsoft ", StringComparison.OrdinalIgnoreCase)) continue;
                var path = DriverPath(d.Str("PathName"), windows);
                if (path == null || !System.IO.File.Exists(path)) continue;
                var info = System.Diagnostics.FileVersionInfo.GetVersionInfo(path);
                var company = (info.CompanyName ?? "").Trim();
                if (company.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0) continue;

                var kind = "Kernel driver";
                var altitude = Reg.Machine(@"SYSTEM\CurrentControlSet\Services\" + name + @"\Instances\" + (Reg.Machine(@"SYSTEM\CurrentControlSet\Services\" + name + @"\Instances", "DefaultInstance") as string ?? ""), "Altitude") as string;
                if (altitude != null) kind = "File system filter (altitude " + altitude + ")";
                t.Rows.Add(new[] { System.IO.Path.GetFileName(path), d.Str("DisplayName"), company.Length > 0 ? company : "Unknown", (info.FileVersion ?? "").Trim(), kind, d.Str("StartMode"), Fmt.YesNo(running) });
            }
            s.Note("Other third-party kernel drivers lists drivers that belong to no device, such as anti-cheat, antivirus, VPN and backup software. They're a common cause of blue screens, so compare them with a crash dump's faulting driver.");
        }

        private static string DriverPath(string raw, string windows)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;
            var p = raw.Trim().Trim('"');
            if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p.Substring(4);
            if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) p = System.IO.Path.Combine(windows, p.Substring(12));
            else if (p.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase) || p.StartsWith(@"SysWOW64\", StringComparison.OrdinalIgnoreCase)) p = System.IO.Path.Combine(windows, p);
            return System.IO.Path.IsPathRooted(p) ? p : null;
        }

        // Win32_PnPSignedDriver swaps the day and month of driver dates (DriverVer=09/03/2026 comes back as 9 March),
        // so both driver tables read the date Windows stored with the device's driver instead.
        private static DateTime? DriverDate(string deviceId)
        {
            if (string.IsNullOrEmpty(deviceId)) return null;
            try
            {
                using (var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var dev = root.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\" + deviceId))
                {
                    var driver = dev?.GetValue("Driver") as string;
                    if (string.IsNullOrEmpty(driver)) return null;
                    using (var k = root.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\" + driver))
                    {
                        if (k == null) return null;
                        var data = k.GetValue("DriverDateData") as byte[];
                        if (data != null && data.Length >= 8) return DateTime.FromFileTimeUtc(BitConverter.ToInt64(data, 0)).Date;
                        DateTime parsed;
                        if (DateTime.TryParseExact(k.GetValue("DriverDate") as string, "M-d-yyyy", CultureInfo.InvariantCulture, DateTimeStyles.None, out parsed))
                            return parsed;
                    }
                }
            }
            catch (Exception) { /* no date rather than a wrong one */ }
            return null;
        }

        // Intel chipset INFs use 1968-07-18 so any other driver outranks them, and drivers built into Windows carry 2006-06-21.
        private static bool IsPlaceholder(DateTime d)
        {
            return d.Date == new DateTime(1968, 7, 18) || d.Date == new DateTime(2006, 6, 21);
        }

        private static string DateText(DateTime? d)
        {
            return d != null && IsPlaceholder(d.Value) ? "Placeholder (" + Fmt.Date(d) + ")" : Fmt.Date(d);
        }

        // Keeps bus\vendor&product and drops the instance part, which can contain a device serial.
        private static string ShortId(string id)
        {
            var parts = id.Split('\\');
            return parts.Length >= 2 ? parts[0] + "\\" + parts[1] : id;
        }

        private static string ProblemText(long? code)
        {
            switch (code)
            {
                case 1: return "Not configured correctly (code 1)";
                case 3: return "Driver may be corrupted (code 3)";
                case 10: return "Device can't start (code 10)";
                case 12: return "Not enough free resources (code 12)";
                case 18: return "Drivers need reinstalling (code 18)";
                case 19: return "Registry entry is corrupted (code 19)";
                case 21: return "Being removed (code 21)";
                case 22: return "Disabled (code 22)";
                case 24: return "Not present or not working (code 24)";
                case 28: return "No driver installed (code 28)";
                case 31: return "Driver failed to load (code 31)";
                case 32: return "Driver is disabled (code 32)";
                case 37: return "Driver failed to initialize (code 37)";
                case 39: return "Driver is corrupted or missing (code 39)";
                case 43: return "Device reported a failure (code 43)";
                case 45: return "Not connected (code 45)";
                case 48: return "Driver blocked as incompatible (code 48)";
                case 52: return "Driver signature can't be verified (code 52)";
                default: return "Error code " + code;
            }
        }

        public static void Battery(Report r)
        {
            var batteries = Wmi.Cim("SELECT Name, EstimatedChargeRemaining, BatteryStatus FROM Win32_Battery");
            if (batteries.Count == 0) return;
            var s = r.NewSection("Battery");
            foreach (var b in batteries)
            {
                s.Add("Battery", b.Str("Name"));
                s.Add("Charge", b.Str("EstimatedChargeRemaining") + "%");
            }
            Guard.Try(s, "Battery wear", () =>
            {
                var design = Wmi.Query(@"root\wmi", "SELECT DesignedCapacity FROM BatteryStaticData").FirstOrDefault();
                var full = Wmi.Query(@"root\wmi", "SELECT FullChargedCapacity FROM BatteryFullChargedCapacity").FirstOrDefault();
                if (design == null || full == null || !(design.Long("DesignedCapacity") > 0)) return;
                var health = 100.0 * full.Long("FullChargedCapacity").Value / design.Long("DesignedCapacity").Value;
                s.Add("Capacity remaining", Fmt.Num(health, "0") + "% of original");
                if (health < 60)
                    r.Find(Severity.Warning, "Battery is badly worn", "It now holds " + Fmt.Num(health, "0") + "% of its original charge.", "Consider replacing it, and check it isn't swollen.");
            });
            Guard.Try(s, "Battery cycles", () =>
            {
                var c = Wmi.Query(@"root\wmi", "SELECT CycleCount FROM BatteryCycleCount").FirstOrDefault();
                if (c != null && c.Long("CycleCount") > 0) s.Add("Charge cycles", c.Str("CycleCount"));
            });
        }
    }
}
