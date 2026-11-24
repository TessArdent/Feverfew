# The AMD drive-write finding needs evidence, not just an old version (DI-12)

**Decision.** "AMD driver predates its fix for excessive drive writes" no longer fires on the version alone. `AmdWritesVerdict.Decide` raises a finding only when the scan sees the bug:
- atieclxx.exe writes at 100 KB/s or more, or its copy in the SYSTEM profile is being rewritten: "writing to the drive nonstop", whatever the version;
- the copy exists, quiet or blocked, on a driver older than 26.11.1: "predates its fix";
- Feverfew's block is still in place on 26.11.1 or later: "no longer needed".

There is no `BuggyFrom` version.

**Why.** The card asked for the first affected AMD Software version, and said not to guess if it can't be confirmed. As of 2026-11-24 it can't be:
- AMD's statements and the press (heise, 2026-11-12; Wccftech; TechPowerUp) name the fix (26.11.1) but no first affected version.
- The only version data is the community workaround's README (github.com/candygoogy/atieclxx-fix). It is built from user reports: the oldest is 26.5.1, and "26.3.1 and older still shipped the amdkmpfd files, so the change came between 26.3.1 and 26.5.1". It doesn't say 26.3.1 is free of the bug.

The copy file is direct evidence: a driver without the bug never makes it. So it is a safer gate than an inferred version.

**Cost.** A PC on an affected driver that hasn't made the copy yet (for example, Feverfew ran without administrator rights, so the copy couldn't be checked) gets no hint to update. The nonstop-writes check still runs without admin rights through the process's write counter.

**Revisit** if AMD publishes the first affected version. Then add `BuggyFrom` to `AmdWritesVerdict` and show "predates its fix" for `BuggyFrom <= installed < FixedIn`.

**Not settled here.** The same README says 26.11.1 fixed only RX 7000 and newer. RX 5000/6000 needed 26.11.2, and Polaris and Vega aren't fixed yet. Feverfew still treats 26.11.1 as fixed for every card. That is a separate card.
