using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace Feverfew.Collectors
{
    /// <summary>One active monitor: which graphics adapter drives it, and its current and best refresh rates.</summary>
    public sealed class Display
    {
        public string Adapter;      // e.g. "NVIDIA GeForce RTX 5070"
        public string Code;         // PnP code from the monitor's ID, e.g. "AOC2702"
        public string Name;         // friendly name, or "Built-in display"
        public bool Internal;
        public int Width, Height, Hz;
        public int MaxHzAtResolution;
        public bool Primary;
    }

    public static class DisplayInfo
    {
        private const int EnumCurrentSettings = -1;
        private const int AttachedToDesktop = 0x1, PrimaryDevice = 0x4;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DISPLAY_DEVICE
        {
            public int cb;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DeviceName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceString;
            public int StateFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceID;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceKey;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DEVMODE
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmDeviceName;
            public short dmSpecVersion, dmDriverVersion, dmSize, dmDriverExtra;
            public int dmFields;
            public int dmPositionX, dmPositionY, dmDisplayOrientation, dmDisplayFixedOutput;
            public short dmColor, dmDuplex, dmYResolution, dmTTOption, dmCollate;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmFormName;
            public short dmLogPixels;
            public int dmBitsPerPel, dmPelsWidth, dmPelsHeight, dmDisplayFlags, dmDisplayFrequency;
            public int dmICMMethod, dmICMIntent, dmMediaType, dmDitherType, dmReserved1, dmReserved2, dmPanningWidth, dmPanningHeight;
        }

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern bool EnumDisplayDevices(string lpDevice, int iDevNum, ref DISPLAY_DEVICE lpDisplayDevice, int dwFlags);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern bool EnumDisplaySettings(string deviceName, int modeNum, ref DEVMODE devMode);

        private static List<Display> cache;

        /// <summary>Active monitors. Empty when Windows reports none, for example in a remote session.</summary>
        public static List<Display> Active()
        {
            if (cache != null) return cache;
            var list = new List<Display>();
            var names = FriendlyNames();
            for (int i = 0; ; i++)
            {
                var adapter = new DISPLAY_DEVICE { cb = Marshal.SizeOf(typeof(DISPLAY_DEVICE)) };
                if (!EnumDisplayDevices(null, i, ref adapter, 0)) break;
                if ((adapter.StateFlags & AttachedToDesktop) == 0) continue;

                var current = new DEVMODE { dmSize = (short)Marshal.SizeOf(typeof(DEVMODE)) };
                if (!EnumDisplaySettings(adapter.DeviceName, EnumCurrentSettings, ref current)) continue;
                int best = current.dmDisplayFrequency;
                var mode = new DEVMODE { dmSize = (short)Marshal.SizeOf(typeof(DEVMODE)) };
                for (int m = 0; m < 5000 && EnumDisplaySettings(adapter.DeviceName, m, ref mode); m++)
                    if (mode.dmPelsWidth == current.dmPelsWidth && mode.dmPelsHeight == current.dmPelsHeight && mode.dmDisplayFrequency > best)
                        best = mode.dmDisplayFrequency;

                var monitor = new DISPLAY_DEVICE { cb = Marshal.SizeOf(typeof(DISPLAY_DEVICE)) };
                string code = "";
                if (EnumDisplayDevices(adapter.DeviceName, 0, ref monitor, 0))
                {
                    // MONITOR\AOC2702\{4d36e96e-...}\0001
                    var parts = (monitor.DeviceID ?? "").Split('\\');
                    if (parts.Length > 1) code = parts[1];
                }
                Tuple<string, bool> friendly;
                names.TryGetValue(code, out friendly);
                list.Add(new Display
                {
                    Adapter = adapter.DeviceString, Code = code,
                    Internal = friendly != null && friendly.Item2,
                    Name = friendly == null ? code : friendly.Item2 && friendly.Item1.Length == 0 ? "Built-in display" : friendly.Item1.Length > 0 ? friendly.Item1 : code,
                    Width = current.dmPelsWidth, Height = current.dmPelsHeight, Hz = current.dmDisplayFrequency, MaxHzAtResolution = best,
                    Primary = (adapter.StateFlags & PrimaryDevice) != 0
                });
            }
            cache = list;
            return list;
        }

        // PnP code → (name from the monitor's EDID, whether it's built into the PC).
        private static Dictionary<string, Tuple<string, bool>> FriendlyNames()
        {
            var map = new Dictionary<string, Tuple<string, bool>>(StringComparer.OrdinalIgnoreCase);
            try
            {
                var internals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                const long internalConnection = 0x80000000, displayPortEmbedded = 11, lvds = 6, udiEmbedded = 13;
                foreach (var c in Wmi.Query(@"root\wmi", "SELECT InstanceName, VideoOutputTechnology FROM WmiMonitorConnectionParams"))
                {
                    var tech = c.Long("VideoOutputTechnology") ?? -1;
                    if (tech == internalConnection || tech == displayPortEmbedded || tech == lvds || tech == udiEmbedded) internals.Add(Code(c.Str("InstanceName")));
                }
                foreach (var m in Wmi.Query(@"root\wmi", "SELECT InstanceName, UserFriendlyName FROM WmiMonitorID"))
                {
                    var code = Code(m.Str("InstanceName"));
                    if (code.Length == 0 || map.ContainsKey(code)) continue;
                    var codes = m.Raw("UserFriendlyName") as ushort[];
                    var name = codes == null ? "" : new string(codes.Where(x => x != 0).Select(x => (char)x).ToArray()).Trim();
                    map[code] = Tuple.Create(name, internals.Contains(code));
                }
            }
            catch (Exception) { /* fall back to PnP codes */ }
            return map;
        }

        // DISPLAY\AOC2702\5&1a2b3c&0&UID4352_0 → AOC2702
        private static string Code(string instance)
        {
            var parts = (instance ?? "").Split('\\');
            return parts.Length > 1 ? parts[1] : "";
        }

        public static bool IsDiscrete(string adapter)
        {
            var a = adapter ?? "";
            return a.IndexOf("NVIDIA", StringComparison.OrdinalIgnoreCase) >= 0
                || a.IndexOf("Radeon RX", StringComparison.OrdinalIgnoreCase) >= 0 || a.IndexOf("Radeon Pro", StringComparison.OrdinalIgnoreCase) >= 0
                || a.IndexOf("Intel(R) Arc(TM) A", StringComparison.OrdinalIgnoreCase) >= 0 || a.IndexOf("Intel(R) Arc(TM) B", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        public static bool IsIntegrated(string adapter)
        {
            var a = adapter ?? "";
            if (IsDiscrete(a)) return false;
            // AMD names its processor graphics "Radeon(TM) Graphics" or "Radeon Vega"; its cards carry a model number.
            return a.IndexOf("Intel", StringComparison.OrdinalIgnoreCase) >= 0
                || a.IndexOf("Radeon(TM) Graphics", StringComparison.OrdinalIgnoreCase) >= 0 || a.IndexOf("Radeon Graphics", StringComparison.OrdinalIgnoreCase) >= 0
                || a.IndexOf("Radeon Vega", StringComparison.OrdinalIgnoreCase) >= 0 || a.IndexOf("Radeon(TM) Vega", StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }
}
