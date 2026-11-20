using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Feverfew.Collectors
{
    /// <summary>The NVMe SMART / health log (log page 2), read straight from the drive.</summary>
    public sealed class NvmeLog
    {
        public byte CriticalWarning;
        public int TemperatureC;
        public int AvailableSpare, SpareThreshold, PercentUsed;
        public ulong PowerOnHours, UnsafeShutdowns, MediaErrors;
        public ulong DataUnitsWritten; // thousands of 512-byte units
    }

    public static class NvmeHealth
    {
        private const uint IoctlStorageQueryProperty = 0x002D1400;
        private const int StorageDeviceProtocolSpecificProperty = 50, PropertyStandardQuery = 0;
        private const int ProtocolTypeNvme = 3, NvmeDataTypeLogPage = 2, HealthLogPage = 2;
        private const int SpecificDataSize = 40, LogSize = 512;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(SafeFileHandle h, uint code, byte[] inBuffer, int inSize, byte[] outBuffer, int outSize, out int returned, IntPtr overlapped);

        /// <summary>Reads the health log of \\.\PhysicalDriveN. Null if the drive isn't NVMe or its driver doesn't pass the request on.</summary>
        public static NvmeLog Read(int disk)
        {
            const uint noAccess = 0, shareReadWrite = 3, openExisting = 3;
            try
            {
                // Querying a property needs no read access, so this works without admin rights.
                using (var h = CreateFile(@"\\.\PhysicalDrive" + disk, noAccess, shareReadWrite, IntPtr.Zero, openExisting, 0, IntPtr.Zero))
                {
                    if (h.IsInvalid) return null;
                    var buf = new byte[8 + SpecificDataSize + LogSize];
                    BitConverter.GetBytes(StorageDeviceProtocolSpecificProperty).CopyTo(buf, 0);
                    BitConverter.GetBytes(PropertyStandardQuery).CopyTo(buf, 4);
                    BitConverter.GetBytes(ProtocolTypeNvme).CopyTo(buf, 8);
                    BitConverter.GetBytes(NvmeDataTypeLogPage).CopyTo(buf, 12);
                    BitConverter.GetBytes(HealthLogPage).CopyTo(buf, 16);
                    BitConverter.GetBytes(SpecificDataSize).CopyTo(buf, 24); // where the log starts, after the request
                    BitConverter.GetBytes(LogSize).CopyTo(buf, 28);
                    int returned;
                    if (!DeviceIoControl(h, IoctlStorageQueryProperty, buf, buf.Length, buf, buf.Length, out returned, IntPtr.Zero)) return null;

                    // The reply is a STORAGE_PROTOCOL_DATA_DESCRIPTOR: Version, Size, then the request with the data offset filled in.
                    int offset = 8 + BitConverter.ToInt32(buf, 8 + 16);
                    int length = BitConverter.ToInt32(buf, 8 + 20);
                    if (length < LogSize || offset + LogSize > buf.Length || returned < offset + 192) return null;
                    int kelvin = BitConverter.ToUInt16(buf, offset + 1);
                    return new NvmeLog
                    {
                        CriticalWarning = buf[offset],
                        TemperatureC = kelvin > 0 ? kelvin - 273 : 0,
                        AvailableSpare = buf[offset + 3], SpareThreshold = buf[offset + 4], PercentUsed = buf[offset + 5],
                        DataUnitsWritten = BitConverter.ToUInt64(buf, offset + 48),
                        PowerOnHours = BitConverter.ToUInt64(buf, offset + 128),
                        UnsafeShutdowns = BitConverter.ToUInt64(buf, offset + 144),
                        MediaErrors = BitConverter.ToUInt64(buf, offset + 160)
                    };
                }
            }
            catch (Exception) { return null; }
        }
    }
}
