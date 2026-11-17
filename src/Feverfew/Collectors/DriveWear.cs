using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Feverfew.Collectors
{
    /// <summary>What a drive reports about its own lifetime, and how long Windows has been running, for estimating write wear.</summary>
    public static class DriveWear
    {
        public sealed class NvmeHealth
        {
            public long BytesWritten;
            public int PercentageUsed;
            public long PowerOnHours;
        }

        private const uint IoctlStorageQueryProperty = 0x2D1400;
        private const int StorageDeviceProtocolSpecificProperty = 50;
        private const int ProtocolTypeNvme = 3;
        private const int NvmeDataTypeLogPage = 2;
        private const int NvmeHealthLogPage = 2;
        private const int ProtocolSpecificDataSize = 40;
        private const int HealthLogSize = 512;
        // NVMe counts data in units of 1,000 sectors of 512 bytes.
        private const long NvmeDataUnit = 512000;

        /// <summary>Reads the NVMe SMART / health log of \\.\PhysicalDriveN. Returns null for other drives or without administrator rights.</summary>
        public static NvmeHealth ReadNvme(int diskNumber)
        {
            using (var handle = CreateFile(@"\\.\PhysicalDrive" + diskNumber, 0xC0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero))
            {
                if (handle.IsInvalid) return null;
                int inputSize = 8 + ProtocolSpecificDataSize + HealthLogSize;
                var buffer = new byte[inputSize];
                BitConverter.GetBytes(StorageDeviceProtocolSpecificProperty).CopyTo(buffer, 0);
                // buffer[4..8] stays 0: PropertyStandardQuery.
                int[] request = { ProtocolTypeNvme, NvmeDataTypeLogPage, NvmeHealthLogPage, 0, ProtocolSpecificDataSize, HealthLogSize, 0, 0, 0, 0 };
                for (int i = 0; i < request.Length; i++) BitConverter.GetBytes(request[i]).CopyTo(buffer, 8 + i * 4);

                uint returned;
                if (!DeviceIoControl(handle, IoctlStorageQueryProperty, buffer, (uint)buffer.Length, buffer, (uint)buffer.Length, out returned, IntPtr.Zero)) return null;
                // The reply is a STORAGE_PROTOCOL_DATA_DESCRIPTOR: Version, Size, then the protocol data header, whose offset is relative to it.
                int offset = 8 + BitConverter.ToInt32(buffer, 8 + 16);
                int length = BitConverter.ToInt32(buffer, 8 + 20);
                if (length < HealthLogSize || offset + HealthLogSize > returned) return null;

                return new NvmeHealth
                {
                    PercentageUsed = buffer[offset + 5],
                    BytesWritten = Low64(buffer, offset + 80) > long.MaxValue / NvmeDataUnit ? long.MaxValue : Low64(buffer, offset + 80) * NvmeDataUnit,
                    PowerOnHours = Low64(buffer, offset + 128)
                };
            }
        }

        // The log's counters are 128-bit; no real drive needs the upper half.
        private static long Low64(byte[] b, int at) { return (long)Math.Min(BitConverter.ToUInt64(b, at), long.MaxValue); }

        /// <summary>
        /// Estimates how many hours Windows was running (not off or asleep) between two times. Measured from the System
        /// event log where it reaches back far enough, and scaled from that share for older times the log no longer holds.
        /// </summary>
        public static double RunningHours(DateTime fromUtc, DateTime toUtc, out string method)
        {
            const double AssumedShare = 8.0 / 24;
            double total = (toUtc - fromUtc).TotalHours;
            if (total <= 0) { method = "none"; return 0; }

            var changes = PowerChanges();
            if (changes.Count < 2)
            {
                method = "assumes 8 hours of use a day, because the event log has no start and shutdown history";
                return total * AssumedShare;
            }

            DateTime logStart = changes[0].Key;
            DateTime measuredFrom = fromUtc > logStart ? fromUtc : logStart;
            double measured = 0;
            bool on = changes[0].Value;
            DateTime since = logStart;
            foreach (var c in changes.Skip(1).Concat(new[] { new KeyValuePair<DateTime, bool>(toUtc, !on) }))
            {
                if (c.Key > since && on)
                {
                    var a = since < measuredFrom ? measuredFrom : since;
                    var b = c.Key > toUtc ? toUtc : c.Key;
                    if (b > a) measured += (b - a).TotalHours;
                }
                if (c.Key > toUtc) break;
                since = c.Key;
                on = c.Value;
            }

            double measuredSpan = (toUtc - measuredFrom).TotalHours;
            if (fromUtc >= logStart)
            {
                method = "measured from Windows' start, shutdown and sleep history";
                return measured;
            }
            double share = measuredSpan >= 24 ? measured / measuredSpan : AssumedShare;
            method = "measured for the last " + (int)(measuredSpan / 24) + " days and scaled to the earlier part, which the event log no longer covers";
            return measured + (logStart - fromUtc).TotalHours * share;
        }

        // Kernel-General 12 and 13 mark Windows starting and shutting down; Kernel-Power 42 and 107 mark sleep and resume.
        private static List<KeyValuePair<DateTime, bool>> PowerChanges()
        {
            var changes = new List<KeyValuePair<DateTime, bool>>();
            const string query = "*[System[(Provider[@Name='Microsoft-Windows-Kernel-General'] and (EventID=12 or EventID=13)) or (Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=42 or EventID=107))]]";
            using (var reader = new EventLogReader(new EventLogQuery("System", PathType.LogName, query)))
            {
                EventRecord e;
                while ((e = reader.ReadEvent()) != null)
                    using (e)
                    {
                        if (e.TimeCreated == null) continue;
                        bool startsRunning = e.Id == 12 || e.Id == 107;
                        changes.Add(new KeyValuePair<DateTime, bool>(e.TimeCreated.Value.ToUniversalTime(), startsRunning));
                    }
            }
            return changes.OrderBy(c => c.Key).ToList();
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(SafeFileHandle device, uint code, byte[] input, uint inputSize, byte[] output, uint outputSize, out uint returned, IntPtr overlapped);
    }
}
