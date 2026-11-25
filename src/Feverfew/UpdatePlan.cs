using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace Feverfew
{
    public sealed class UpdateInfo
    {
        public Version Current;
        public Version Latest;
        public string PageUrl;
        public string DownloadUrl;
        public string Sha256;
        public bool IsNewer { get { return Latest > Current; } }
        public bool CanDownload { get { return DownloadUrl != null && Sha256 != null; } }
    }

    public enum LaunchAction { Nothing, Notify, Install }

    /// <summary>The updater's pure logic: reading GitHub's release JSON and deciding what to do at launch. No network, registry or UI.</summary>
    public static class UpdatePlan
    {
        public const string Repository = "TessArdent/Feverfew";
        public const string AssetName = "setup.exe";
        private static readonly string DownloadPrefix = "https://github.com/" + Repository + "/releases/download/";

        /// <summary>Arguments for an unattended update: no wizard, no message boxes, and the installer reopens Feverfew (installer\setup.iss).</summary>
        public const string SilentArguments = "/SILENT /SUPPRESSMSGBOXES /NORESTART /relaunch=yes";

        public static Version Normalize(Version v) { return new Version(v.Major, v.Minor, Math.Max(v.Build, 0)); }

        /// <summary>
        /// True only for this repository's release downloads on github.com. GitHub owner and repository names are
        /// case-insensitive, and the API returns the repository's own casing, so the prefix is compared ignoring case.
        /// </summary>
        public static bool IsReleaseAsset(string url)
        {
            return url != null && url.StartsWith(DownloadPrefix, StringComparison.OrdinalIgnoreCase) && url.IndexOf("..", StringComparison.Ordinal) < 0;
        }

        /// <summary>Reads a deserialized GitHub "latest release" object. The download is offered only with a sha256 digest.</summary>
        public static UpdateInfo ParseRelease(IDictionary<string, object> release, Version current)
        {
            var info = new UpdateInfo
            {
                Current = Normalize(current),
                Latest = Normalize(new Version(((string)release["tag_name"]).TrimStart('v', 'V'))),
                PageUrl = (string)release["html_url"]
            };

            object list;
            if (!release.TryGetValue("assets", out list) || !(list is IEnumerable)) return info;
            var setup = ((IEnumerable)list).OfType<IDictionary<string, object>>().FirstOrDefault(a => a.ContainsKey("name") && (string)a["name"] == AssetName);
            if (setup == null) return info;

            object url, digest;
            if (setup.TryGetValue("browser_download_url", out url) && IsReleaseAsset(url as string)
                && setup.TryGetValue("digest", out digest) && digest is string && ((string)digest).StartsWith("sha256:", StringComparison.Ordinal))
            {
                info.DownloadUrl = (string)url;
                info.Sha256 = ((string)digest).Substring("sha256:".Length);
            }
            return info;
        }

        /// <summary>
        /// What to do with a launch-time check. Automatic install needs a verifiable download and the per-user install;
        /// otherwise it falls back to telling the user. Automatic updates imply the launch check.
        /// </summary>
        public static LaunchAction Decide(bool notifyOnLaunch, bool autoUpdate, UpdateInfo info, bool canInstallInPlace)
        {
            if (info == null || !info.IsNewer || !(notifyOnLaunch || autoUpdate)) return LaunchAction.Nothing;
            if (autoUpdate && info.CanDownload && canInstallInPlace) return LaunchAction.Install;
            return LaunchAction.Notify;
        }
    }
}
