using System;
using System.Collections.Generic;
using System.Linq;

namespace Feverfew.Collectors
{
    /// <summary>
    /// Tells a failed Fast Startup resume apart from a real unexpected restart. When Windows can't resume the session it saved at
    /// shutdown (Kernel-Boot 29), it starts fresh and logs Kernel-Power 41 a few seconds later, as if the saved session had crashed.
    /// Pure, so the headless tests can check it with synthetic times.
    /// </summary>
    public static class FastStartupResume
    {
        /// <summary>How long before a Kernel-Power 41 its Kernel-Boot 29 can come and still belong to the same boot.</summary>
        public const int PairSeconds = 30;

        public sealed class Failure
        {
            public DateTime Time;
            public string Status; // "0xc00000d4", or "" when the event didn't carry one
        }

        /// <summary>The resume failure from the same boot as this Kernel-Power 41, or null when it's a real unexpected restart.</summary>
        public static Failure Match(DateTime restart, IEnumerable<Failure> failures)
        {
            return failures.Where(f => f.Time <= restart && (restart - f.Time).TotalSeconds <= PairSeconds)
                .OrderByDescending(f => f.Time).FirstOrDefault();
        }

        public static string Detail(Failure f)
        {
            return "Windows couldn't resume the session saved at shutdown and started fresh. This isn't a crash."
                + (string.IsNullOrEmpty(f.Status) ? "" : " Error status " + f.Status + ".");
        }

        /// <summary>The unexpected-restart finding's severity, counting only real restarts, or null for no finding.</summary>
        public static Severity? RestartSeverity(int realRestarts, int blueScreens)
        {
            if (realRestarts <= blueScreens) return null;
            return realRestarts >= 3 ? Severity.Critical : Severity.Warning;
        }

        /// <summary>The "Unexpected restarts (Kernel-Power 41)" fact: the raw count, and how many of them were failed resumes.</summary>
        public static string RestartFact(int kernelPower41, int failedResumes)
        {
            if (failedResumes <= 0) return kernelPower41.ToString();
            return kernelPower41 + " (" + failedResumes + (failedResumes == 1 ? " was a" : " were") + " Fast Startup resume failure" + (failedResumes == 1 ? "" : "s") + ")";
        }

        public const string Title = "Fast Startup is on";
        public const string OnDetail = "Shut down saves Windows' core and drivers to disk instead of closing them, so it doesn't clear driver problems the way Restart does.";
        public const string OnAdvice = "When troubleshooting, use Restart rather than Shut down. If problems keep coming back after a shutdown, turn Fast Startup off in Control Panel > Power Options > Choose what the power buttons do.";
        private const string OffPath = "Control Panel > Power Options > Choose what the power buttons do";

        private static string FailedSentence(int failures)
        {
            return "Windows failed to resume the saved session " + (failures == 1 ? "once" : failures + " times") + " in the last 30 days and started fresh instead (Kernel-Boot 29). Windows logs each as an unexpected restart, but they aren't crashes.";
        }

        /// <summary>
        /// Adds the resume failures to the "Fast Startup is on" finding when there is one, so the report doesn't say it twice.
        /// Without one, returns a new Info finding, unless Fast Startup is known to be off now.
        /// </summary>
        public static Finding Advise(Finding fastStartupOn, bool? fastStartup, int failures)
        {
            if (failures <= 0) return null;
            if (fastStartupOn != null)
            {
                fastStartupOn.Detail = OnDetail + " " + FailedSentence(failures);
                fastStartupOn.Advice = "Turn Fast Startup off in " + OffPath + ". Until then, use Restart rather than Shut down when troubleshooting.";
                return null;
            }
            if (fastStartup == false) return null;
            return new Finding
            {
                Severity = Severity.Info, Title = "Fast Startup failed to resume", Detail = FailedSentence(failures),
                Advice = "Turn Fast Startup off in " + OffPath + "."
            };
        }
    }
}
