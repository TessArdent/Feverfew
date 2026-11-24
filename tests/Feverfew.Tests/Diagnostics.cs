using System;
using System.Collections.Generic;
using Feverfew;
using Feverfew.Collectors;

// Checks of the collectors' pure logic, with synthetic inputs instead of the real event log, registry or WMI.
internal static partial class Program
{
    private static void Check(string name, bool pass, string got = null)
    {
        if (!pass) failures++;
        Console.WriteLine((pass ? "PASS" : "FAIL") + "  " + name + (!pass && got != null ? "  [got " + got + "]" : ""));
    }

    private static void Diagnostics()
    {
        FastStartupResumeTests();
        AmdWritesTests();
    }

    private static void AmdWritesTests()
    {
        var old = new Version(23, 20, 44);      // the user's January 2024 driver
        var affected = new Version(26, 5, 1);   // the oldest version reported with the bug
        var fixedVersion = new Version(26, 11, 1);
        double busy = 600 * 1024;
        Func<AmdWritesVerdict.Kind, string> name = k => k.ToString();
        var k1 = AmdWritesVerdict.Decide(old, AmdWritesVerdict.CopyState.Missing, 0);
        Check("an old driver with no writes and no copy raises no finding", k1 == AmdWritesVerdict.Kind.None, name(k1));
        var k2 = AmdWritesVerdict.Decide(old, null, null);
        Check("an old driver, not checked as administrator, raises no finding", k2 == AmdWritesVerdict.Kind.None, name(k2));
        var k3 = AmdWritesVerdict.Decide(affected, AmdWritesVerdict.CopyState.Quiet, 0);
        Check("an affected version whose copy is there but quiet says it predates the fix", k3 == AmdWritesVerdict.Kind.PredatesFix, name(k3));
        var k4 = AmdWritesVerdict.Decide(affected, AmdWritesVerdict.CopyState.Missing, 0);
        Check("an affected version with no writes and no copy raises no finding (no version gate: see the decision)", k4 == AmdWritesVerdict.Kind.None, name(k4));
        foreach (var v in new[] { null, old, affected, fixedVersion })
        {
            var k = AmdWritesVerdict.Decide(v, AmdWritesVerdict.CopyState.Missing, busy);
            Check("writes measured on " + (v == null ? "an unknown version" : v.ToString()) + " raise the nonstop-writes finding", k == AmdWritesVerdict.Kind.NonstopWrites, name(k));
        }
        var k5 = AmdWritesVerdict.Decide(old, AmdWritesVerdict.CopyState.Rewriting, null);
        Check("a copy being rewritten raises the nonstop-writes finding whatever the version", k5 == AmdWritesVerdict.Kind.NonstopWrites, name(k5));
        var k6 = AmdWritesVerdict.Decide(fixedVersion, AmdWritesVerdict.CopyState.Quiet, 0);
        Check("a fixed version with a quiet copy raises no finding", k6 == AmdWritesVerdict.Kind.None, name(k6));
        var k7 = AmdWritesVerdict.Decide(fixedVersion, AmdWritesVerdict.CopyState.Blocked, 0);
        Check("a fixed version with Feverfew's block says the block is no longer needed", k7 == AmdWritesVerdict.Kind.BlockNoLongerNeeded, name(k7));
    }

    private static void FastStartupResumeTests()
    {
        var restart = new DateTime(2026, 11, 22, 18, 4, 12);
        var resumes = new List<FastStartupResume.Failure>
        {
            new FastStartupResume.Failure { Time = restart.AddSeconds(-2), Status = "0xc00000d4" }
        };
        var match = FastStartupResume.Match(restart, resumes);
        Check("a Kernel-Power 41 two seconds after a Kernel-Boot 29 is a failed Fast Startup resume", match != null && match.Status == "0xc00000d4");
        Check("its detail says it isn't a crash and gives the status", match != null && FastStartupResume.Detail(match).Contains("isn't a crash") && FastStartupResume.Detail(match).Contains("0xc00000d4"));

        Check("a Kernel-Power 41 with no Kernel-Boot 29 stays an unexpected restart", FastStartupResume.Match(restart, new List<FastStartupResume.Failure>()) == null);
        var far = new List<FastStartupResume.Failure> { new FastStartupResume.Failure { Time = restart.AddMinutes(-10) } };
        Check("a Kernel-Power 41 whose Kernel-Boot 29 is ten minutes earlier stays an unexpected restart", FastStartupResume.Match(restart, far) == null);
        var later = new List<FastStartupResume.Failure> { new FastStartupResume.Failure { Time = restart.AddSeconds(5) } };
        Check("a Kernel-Boot 29 after the Kernel-Power 41 doesn't explain it", FastStartupResume.Match(restart, later) == null);

        // The user report: 4 Kernel-Power 41, 2 of them failed resumes, no blue screens.
        Check("2 real restarts of 4 logged are a Warning, not Critical", FastStartupResume.RestartSeverity(4 - 2, 0) == Severity.Warning);
        Check("3 real restarts are Critical", FastStartupResume.RestartSeverity(3, 0) == Severity.Critical);
        Check("only failed resumes raise no restart finding", FastStartupResume.RestartSeverity(0, 0) == null);
        Check("restarts all explained by blue screens raise no restart finding", FastStartupResume.RestartSeverity(2, 2) == null);
        Check("the restart fact keeps the raw count and names the failed resumes", FastStartupResume.RestartFact(4, 2) == "4 (2 were Fast Startup resume failures)", FastStartupResume.RestartFact(4, 2));
        Check("the restart fact is the plain count with no failed resumes", FastStartupResume.RestartFact(3, 0) == "3");

        var on = new Finding { Severity = Severity.Info, Title = FastStartupResume.Title, Detail = FastStartupResume.OnDetail, Advice = FastStartupResume.OnAdvice };
        Check("failed resumes extend the 'Fast Startup is on' finding instead of adding one", FastStartupResume.Advise(on, true, 2) == null && on.Detail.Contains("2 times") && on.Advice.StartsWith("Turn Fast Startup off"));
        var alone = FastStartupResume.Advise(null, null, 1);
        Check("failed resumes without that finding add an Info finding", alone != null && alone.Severity == Severity.Info && alone.Detail.Contains("once"));
        Check("no failed-resume finding once Fast Startup is off", FastStartupResume.Advise(null, false, 1) == null);
        Check("no failed-resume finding without failures", FastStartupResume.Advise(null, true, 0) == null);
    }
}
