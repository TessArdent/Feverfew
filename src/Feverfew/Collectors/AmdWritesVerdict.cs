using System;

namespace Feverfew.Collectors
{
    /// <summary>
    /// Which finding the AMD drive-write check raises. Pure, so the headless tests can check it without an AMD card.
    /// The driver version alone never raises one: no source confirms which version brought the bug in
    /// (docs/decisions/2026-11-24-amd-writes-version-gate.md), so only writes or the copy the scan finds count as evidence.
    /// </summary>
    public static class AmdWritesVerdict
    {
        public enum CopyState { Missing, Rewriting, Quiet, Blocked }

        public enum Kind { None, NonstopWrites, BlockNoLongerNeeded, PredatesFix }

        public static readonly Version FixedIn = new Version(26, 11, 1);

        // Normal use writes almost nothing. Reports of the bug range from 300 KB/s to 5 MB/s.
        public const double HighWriteBytesPerSecond = 100 * 1024;

        /// <param name="installed">The newest AMD Software version installed, or null when unknown.</param>
        /// <param name="copy">The copy in the SYSTEM profile, or null when it couldn't be checked.</param>
        /// <param name="rate">atieclxx.exe's measured write rate in bytes a second, or null when not measured.</param>
        public static Kind Decide(Version installed, CopyState? copy, double? rate)
        {
            bool fixedDriver = installed != null && installed >= FixedIn;
            bool heavy = rate != null && rate >= HighWriteBytesPerSecond;
            if (copy == CopyState.Rewriting || heavy) return Kind.NonstopWrites;
            if (copy == CopyState.Blocked && fixedDriver) return Kind.BlockNoLongerNeeded;
            // The copy is there, so this driver has had the bug, even if it isn't rewriting it right now.
            if (installed != null && !fixedDriver && (copy == CopyState.Quiet || copy == CopyState.Blocked)) return Kind.PredatesFix;
            return Kind.None;
        }
    }
}
