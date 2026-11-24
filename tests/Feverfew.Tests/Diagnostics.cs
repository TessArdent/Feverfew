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
