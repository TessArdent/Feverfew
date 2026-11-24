using System;
using System.Collections.Generic;
using System.Linq;

namespace Feverfew.Collectors
{
    /// <summary>
    /// The Slot column of "Installed modules". Many AM5 boards (Gigabyte's B650 among them) repeat the DeviceLocator in each
    /// channel ("DIMM 1" twice) and tell the channels apart in BankLabel ("P0 CHANNEL A", "P0 CHANNEL B"). Pure, for the tests.
    /// </summary>
    public static class MemorySlots
    {
        /// <summary>One slot label per module, in order: "BankLabel / DeviceLocator" when the bank label adds something.</summary>
        public static string[] Labels(IList<string> locators, IList<string> banks)
        {
            var loc = locators.Select(l => (l ?? "").Trim()).ToList();
            var bank = Enumerable.Range(0, loc.Count).Select(i => i < banks.Count ? (banks[i] ?? "").Trim() : "").ToList();
            // A bank label repeated on every module ("BANK 0" on all of them) tells nothing apart.
            bool sameEverywhere = loc.Count > 1 && bank.Distinct(StringComparer.OrdinalIgnoreCase).Count() == 1;
            return Enumerable.Range(0, loc.Count).Select(i =>
            {
                bool adds = bank[i].Length > 0 && !sameEverywhere && !string.Equals(bank[i], loc[i], StringComparison.OrdinalIgnoreCase);
                if (!adds) return loc[i];
                return loc[i].Length == 0 ? bank[i] : bank[i] + " / " + loc[i];
            }).ToArray();
        }
    }
}
