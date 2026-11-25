using System;
using System.Collections.Generic;
using Feverfew;

// Checks of the updater's pure logic: reading GitHub's release JSON and the launch-time decision.
internal static partial class Program
{
    private const string Digest = "sha256:ffa494a039976760c502a415a195bd33b569bfcd25f8007b13d32f2ec9a77fb6";

    private static Dictionary<string, object> Release(string tag, string url, string digest = Digest, string name = "setup.exe")
    {
        var asset = new Dictionary<string, object> { { "name", name }, { "browser_download_url", url } };
        if (digest != null) asset["digest"] = digest;
        return new Dictionary<string, object>
        {
            { "tag_name", tag },
            { "html_url", "https://github.com/TessArdent/Feverfew/releases/tag/" + tag },
            { "assets", new object[] { asset } }
        };
    }

    private static void UpdateTests()
    {
        var v150 = new Version(1, 5, 0);
        var real = UpdatePlan.ParseRelease(Release("v1.6.0", "https://github.com/TessArdent/Feverfew/releases/download/v1.6.0/setup.exe"), v150);
        Check("GitHub's own casing (TessArdent/Feverfew) gives a downloadable update", real.IsNewer && real.CanDownload && real.Sha256 == Digest.Substring(7), real.DownloadUrl ?? "no download");
        Check("the repository path matches whatever its case", UpdatePlan.ParseRelease(Release("v1.6.0", "https://github.com/tessardent/feverfew/releases/download/v1.6.0/setup.exe"), v150).CanDownload);

        Check("another repository's download is refused", !UpdatePlan.ParseRelease(Release("v1.6.0", "https://github.com/someone/Feverfew/releases/download/v1.6.0/setup.exe"), v150).CanDownload);
        Check("another host is refused", !UpdatePlan.ParseRelease(Release("v1.6.0", "https://example.com/TessArdent/Feverfew/releases/download/v1.6.0/setup.exe"), v150).CanDownload);
        Check("a look-alike host is refused", !UpdatePlan.ParseRelease(Release("v1.6.0", "https://github.com.evil.example/TessArdent/Feverfew/releases/download/v1.6.0/setup.exe"), v150).CanDownload);
        Check("plain http is refused", !UpdatePlan.ParseRelease(Release("v1.6.0", "http://github.com/TessArdent/Feverfew/releases/download/v1.6.0/setup.exe"), v150).CanDownload);
        Check("a path that climbs out of the releases is refused", !UpdatePlan.IsReleaseAsset("https://github.com/TessArdent/Feverfew/releases/download/../../../other/x/setup.exe"));
        Check("no digest: no download", !UpdatePlan.ParseRelease(Release("v1.6.0", "https://github.com/TessArdent/Feverfew/releases/download/v1.6.0/setup.exe", null), v150).CanDownload);
        Check("a non-sha256 digest: no download", !UpdatePlan.ParseRelease(Release("v1.6.0", "https://github.com/TessArdent/Feverfew/releases/download/v1.6.0/setup.exe", "md5:abc"), v150).CanDownload);
        Check("a differently named asset: no download", !UpdatePlan.ParseRelease(Release("v1.6.0", "https://github.com/TessArdent/Feverfew/releases/download/v1.6.0/other.exe", Digest, "other.exe"), v150).CanDownload);
        Check("the same version isn't newer", !UpdatePlan.ParseRelease(Release("v1.5.0", "https://github.com/TessArdent/Feverfew/releases/download/v1.5.0/setup.exe"), new Version(1, 5, 0, 0)).IsNewer);

        var stale = UpdatePlan.ParseRelease(Release("v1.5.0", "https://github.com/TessArdent/Feverfew/releases/download/v1.5.0/setup.exe"), v150);
        var noDownload = UpdatePlan.ParseRelease(Release("v1.6.0", "https://example.com/setup.exe"), v150);
        Check("both toggles off: nothing happens at launch", UpdatePlan.Decide(false, false, real, true) == LaunchAction.Nothing);
        Check("no newer version: nothing happens at launch", UpdatePlan.Decide(true, true, stale, true) == LaunchAction.Nothing);
        Check("a failed check: nothing happens at launch", UpdatePlan.Decide(true, true, null, true) == LaunchAction.Nothing);
        Check("notify only: the user is told", UpdatePlan.Decide(true, false, real, true) == LaunchAction.Notify);
        Check("automatic: it installs", UpdatePlan.Decide(false, true, real, true) == LaunchAction.Install && UpdatePlan.Decide(true, true, real, true) == LaunchAction.Install);
        Check("automatic but not the per-user install: the user is told instead", UpdatePlan.Decide(false, true, real, false) == LaunchAction.Notify);
        Check("automatic but no verifiable download: the user is told instead", UpdatePlan.Decide(false, true, noDownload, true) == LaunchAction.Notify);
        Check("the silent install asks the installer to reopen Feverfew", UpdatePlan.SilentArguments.Contains("/SILENT") && UpdatePlan.SilentArguments.Contains("/relaunch=yes"));
    }
}
