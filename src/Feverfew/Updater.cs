using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web.Script.Serialization;

namespace Feverfew
{
    /// <summary>A downloaded update that failed a check. It has been deleted; the message says why.</summary>
    public sealed class UpdateRefusedException : Exception
    {
        public readonly string PageUrl;
        public UpdateRefusedException(string message, string pageUrl) : base(message) { PageUrl = pageUrl; }
    }

    /// <summary>Checks the project's GitHub releases: when the user asks, or at launch if they turned that on (<see cref="UpdateSettings"/>).</summary>
    public static class Updater
    {
        public const string Repository = UpdatePlan.Repository;
        private const string AssetName = UpdatePlan.AssetName;
        private static readonly string LatestApi = "https://api.github.com/repos/" + Repository + "/releases/latest";

        public static Version CurrentVersion()
        {
            return Normalize(Assembly.GetExecutingAssembly().GetName().Version);
        }

        private static Version Normalize(Version v) { return UpdatePlan.Normalize(v); }

        private static WebClient Client()
        {
            var client = new WebClient { Encoding = Encoding.UTF8 };
            client.Headers[HttpRequestHeader.UserAgent] = "Feverfew/" + CurrentVersion();
            return client;
        }

        public static UpdateInfo Check(Version current)
        {
            string body;
            using (var client = Client())
            {
                client.Headers[HttpRequestHeader.Accept] = "application/vnd.github+json";
                body = client.DownloadString(LatestApi);
            }

            var release = (Dictionary<string, object>)new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.DeserializeObject(body);
            return UpdatePlan.ParseRelease(release, current);
        }

        /// <summary>
        /// Downloads the installer to a new private temp folder and rejects it unless its hash matches and it is
        /// Authenticode-signed by a certificate that chains to a pinned root (see <see cref="PinnedRoots"/>).
        /// </summary>
        public static string Download(UpdateInfo info)
        {
            var folder = Path.Combine(Path.GetTempPath(), "Feverfew-update-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(folder);
            var path = Path.Combine(folder, AssetName);
            try
            {
                using (var client = Client()) client.DownloadFile(info.DownloadUrl, path);

                string actual;
                using (var sha = SHA256.Create())
                using (var file = File.OpenRead(path))
                    actual = BitConverter.ToString(sha.ComputeHash(file)).Replace("-", "");
                if (!string.Equals(actual, info.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new UpdateRefusedException("The downloaded installer failed its integrity check and was deleted.", info.PageUrl);

                string reason;
                if (!SignatureCheck.Verify(path, PinnedRoots(), out reason))
                    throw new UpdateRefusedException("The downloaded installer was deleted because " + reason + ". Feverfew only installs updates signed by its publisher.", info.PageUrl);
                return path;
            }
            catch
            {
                try { Directory.Delete(folder, true); } catch { }
                throw;
            }
        }

        /// <summary>The publisher's code-signing root certificates, embedded from Trust\*.cer (public certificates only).</summary>
        public static List<X509Certificate2> PinnedRoots()
        {
            var assembly = Assembly.GetExecutingAssembly();
            var roots = new List<X509Certificate2>();
            foreach (var name in assembly.GetManifestResourceNames().Where(n => n.StartsWith("Feverfew.Trust.", StringComparison.Ordinal) && n.EndsWith(".cer", StringComparison.OrdinalIgnoreCase)))
            using (var stream = assembly.GetManifestResourceStream(name))
            using (var memory = new MemoryStream())
            {
                stream.CopyTo(memory);
                roots.Add(new X509Certificate2(memory.ToArray()));
            }
            return roots;
        }

        /// <summary>True when this copy is the per-user install, so running setup as this user replaces it.</summary>
        public static bool CanInstallInPlace()
        {
            var expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Feverfew") + "\\";
            return Assembly.GetExecutingAssembly().Location.StartsWith(expected, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// The update toggles, kept per user under HKCU\Software\Feverfew. Both start off, so Feverfew contacts GitHub
    /// only when asked until the user turns one on. Automatic updates imply the launch check.
    /// </summary>
    public static class UpdateSettings
    {
        private const string Key = @"Software\Feverfew";

        public static bool NotifyOnLaunch { get { return Read("NotifyOnLaunch"); } set { Write("NotifyOnLaunch", value); } }
        public static bool AutoUpdate { get { return Read("AutoUpdate"); } set { Write("AutoUpdate", value); } }

        private static bool Read(string name)
        {
            try
            {
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(Key))
                    return key != null && key.GetValue(name) is int && (int)key.GetValue(name) != 0;
            }
            catch (Exception) { return false; }
        }

        private static void Write(string name, bool value)
        {
            using (var key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(Key))
                key.SetValue(name, value ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);
        }
    }
}
