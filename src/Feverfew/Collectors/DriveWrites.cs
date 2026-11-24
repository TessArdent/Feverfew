using System;
using System.Globalization;

namespace Feverfew.Collectors
{
    /// <summary>
    /// A drive's lifetime writes, as shown next to its wear in "Physical drives", and when they're high enough to explain the wear.
    /// Pure, for the tests. Thresholds and units: docs/decisions/2026-11-24-drive-writes-column.md.
    /// </summary>
    public static class DriveWrites
    {
        // NVMe counts data in units of 1,000 sectors of 512 bytes.
        public const double NvmeDataUnit = 512000;

        /// <summary>Bytes from the NVMe health log's Data Units Written, or null when the drive reports 0 (not counted).</summary>
        public static double? FromNvme(ulong dataUnits)
        {
            return dataUnits == 0 ? (double?)null : dataUnits * NvmeDataUnit;
        }

        /// <summary>Decimal units (1 TB = 10^12 bytes), the way drive makers rate endurance in TBW.</summary>
        public static string Format(double bytes)
        {
            string[] units = { "B", "KB", "MB", "GB", "TB", "PB" };
            double v = bytes;
            int i = 0;
            while (v >= 1000 && i < units.Length - 1) { v /= 1000; i++; }
            return v.ToString(i == 0 || v >= 100 ? "0" : "0.#", CultureInfo.InvariantCulture) + " " + units[i];
        }

        /// <summary>Average written per power-on hour, or null when either value is missing.</summary>
        public static double? PerPowerOnHour(double? bytes, long? powerOnHours)
        {
            if (bytes == null || powerOnHours == null || powerOnHours <= 0) return null;
            return bytes.Value / powerOnHours.Value;
        }

        /// <summary>The Written cell: "31.8 TB (about 28 GB per power-on hour)", or "-" when the drive doesn't report it.</summary>
        public static string Cell(double? bytes, long? powerOnHours)
        {
            if (bytes == null) return "-";
            var rate = PerPowerOnHour(bytes, powerOnHours);
            // Below 24 power-on hours the average says little.
            return Format(bytes.Value) + (rate != null && powerOnHours >= 24 ? " (about " + Format(rate.Value) + " per power-on hour)" : "");
        }

        // Only a drive with this much history, wear and writing is flagged.
        public const long MinHours = 100;
        public const long MinWear = 3;
        public const double WearPer1000Hours = 2.0;            // a pace that uses the rated life in under 50,000 power-on hours
        public const double HighBytesPerHour = 10e9;           // 10 GB per power-on hour, 240 GB per power-on day

        /// <summary>True when the wear is high for the drive's power-on hours and its average write rate is unusually high.</summary>
        public static bool HeavyWriting(double? bytes, long? powerOnHours, long? wearPercent)
        {
            var rate = PerPowerOnHour(bytes, powerOnHours);
            if (rate == null || wearPercent == null || powerOnHours < MinHours || wearPercent < MinWear) return false;
            double pace = wearPercent.Value * 1000.0 / powerOnHours.Value;
            return pace >= WearPer1000Hours && rate.Value >= HighBytesPerHour;
        }
    }
}
