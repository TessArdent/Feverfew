using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Feverfew;

// Headless checks for the updater's signature check (and, in Diagnostics.cs, the collectors' pure logic). Prints PASS or FAIL per case and overall.
// Certificates are made in memory for this run and handed to signtool as PFX files in a temp folder:
// nothing is added to a certificate store.
internal static partial class Program
{
    private const string SignTool = @"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe";
    private static int failures;

    private static int Main()
    {
        var work = Path.Combine(Path.GetTempPath(), "feverfew-sigtest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(work);
        try
        {
            Diagnostics();
        }
        catch (Exception e)
        {
            Console.WriteLine("FAIL  diagnostics tests crashed: " + e);
            failures++;
        }
        try
        {
            Run(work);
        }
        catch (Exception e)
        {
            Console.WriteLine("FAIL  test run crashed: " + e);
            failures++;
        }
        finally
        {
            try { Directory.Delete(work, true); } catch { }
        }
        Console.WriteLine(failures == 0 ? "PASS" : "FAIL (" + failures + " failed)");
        return failures == 0 ? 0 : 1;
    }

    private static void Run(string work)
    {
        if (!File.Exists(SignTool)) throw new FileNotFoundException("signtool not found", SignTool);

        var rootA = MakeRoot("CN=Feverfew Test Root A");
        var rootB = MakeRoot("CN=Feverfew Test Root B");
        var leafA = MakeLeaf(rootA, "CN=Feverfew Test Signer A", true);
        var leafB = MakeLeaf(rootB, "CN=Feverfew Test Signer B", true);
        var leafNoEku = MakeLeaf(rootA, "CN=Feverfew Test Signer A no EKU", false);
        var pinned = new List<X509Certificate2> { new X509Certificate2(rootA.RawData) };

        var unsigned = Path.Combine(work, "unsigned.exe");
        File.Copy(Assembly.GetExecutingAssembly().Location, unsigned);

        string good = Sign(work, "good.exe", unsigned, leafA, null);
        Expect("accepts a file signed by the pinned root (signature holds the leaf only)", good, pinned, true);
        Expect("accepts a file signed by the pinned root (signed with /ac adding the root)", Sign(work, "good-with-root.exe", unsigned, leafA, rootA), pinned, true);
        Expect("refuses an unsigned file", unsigned, pinned, false);
        Expect("refuses a file signed under another root", Sign(work, "other-root.exe", unsigned, leafB, null), pinned, false);
        Expect("refuses another root even when signed with /ac adding it", Sign(work, "other-root-embedded.exe", unsigned, leafB, rootB), pinned, false);

        var tampered = Path.Combine(work, "tampered.exe");
        File.Copy(good, tampered);
        var bytes = File.ReadAllBytes(tampered);
        bytes[0x300] ^= 0xFF; // inside the first section, which the signature's hash covers
        File.WriteAllBytes(tampered, bytes);
        Expect("refuses a file changed after signing", tampered, pinned, false);

        Expect("refuses a leaf without the Code Signing EKU", Sign(work, "no-eku.exe", unsigned, leafNoEku, null), pinned, false);
        Expect("refuses everything when no root is pinned", good, new List<X509Certificate2>(), false);

        var trust = Path.Combine(AppContext.BaseDirectory, "Trust");
        var shipped = Directory.Exists(trust) ? Directory.GetFiles(trust, "*.cer") : new string[0];
        if (shipped.Length == 0) { Console.WriteLine("FAIL  no pinned root in src\\Feverfew\\Trust"); failures++; }
        foreach (var file in shipped)
        {
            var cert = new X509Certificate2(file);
            bool ok = !cert.HasPrivateKey && cert.Subject == cert.Issuer && cert.Subject.Contains("TessArdent Code Signing Root CA");
            Console.WriteLine((ok ? "PASS" : "FAIL") + "  pinned root " + Path.GetFileName(file) + " is a public root certificate: " + cert.Subject + " " + cert.Thumbprint);
            if (!ok) failures++;
        }
    }

    private static void Expect(string name, string path, IList<X509Certificate2> pinned, bool accept)
    {
        string reason;
        bool ok = SignatureCheck.Verify(path, pinned, out reason);
        bool pass = ok == accept;
        if (!pass) failures++;
        Console.WriteLine((pass ? "PASS" : "FAIL") + "  " + name + (reason != null ? "  [" + reason + "]" : ""));
    }

    private static X509Certificate2 MakeRoot(string subject)
    {
        var key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(5));
    }

    private static X509Certificate2 MakeLeaf(X509Certificate2 issuer, string subject, bool codeSigning)
    {
        var key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        // No EKU extension at all on the second kind: Windows reads that as "any purpose", so only an explicit check refuses it.
        if (codeSigning) request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(SignatureCheck.CodeSigningOid) }, false));
        var serial = new byte[8];
        using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(serial);
        serial[0] &= 0x7F;
        using (var cert = request.Create(issuer, DateTimeOffset.Now.AddHours(-1), DateTimeOffset.Now.AddYears(1), serial))
            return cert.CopyWithPrivateKey(key);
    }

    /// <summary>
    /// Signs with signtool's digest flow: /dg hashes the file using only the public certificate, this process signs
    /// the digest with the in-memory key, and /di embeds the signature. No key is ever imported, so no key container
    /// or store is touched (signtool /f with a PFX leaves a persisted key behind for every call).
    /// </summary>
    private static string Sign(string work, string name, string source, X509Certificate2 leaf, X509Certificate2 includeRoot)
    {
        var folder = Path.Combine(work, Path.GetFileNameWithoutExtension(name));
        Directory.CreateDirectory(folder);
        var target = Path.Combine(work, name);
        File.Copy(source, target);
        var cer = Path.Combine(folder, "leaf.cer");
        File.WriteAllBytes(cer, leaf.Export(X509ContentType.Cert));
        var extra = "";
        if (includeRoot != null)
        {
            var root = Path.Combine(folder, "root.cer");
            File.WriteAllBytes(root, includeRoot.Export(X509ContentType.Cert));
            extra = " /ac \"" + root + "\"";
        }

        SignToolRun(name, "sign /q /fd sha256 /f \"" + cer + "\"" + extra + " /dg \"" + folder + "\" \"" + target + "\"");
        var digestFile = Path.Combine(folder, name + ".dig");
        var digest = Convert.FromBase64String(File.ReadAllText(digestFile).Trim());
        byte[] signature;
        using (var key = leaf.GetRSAPrivateKey())
            signature = key.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        File.WriteAllText(digestFile + ".signed", Convert.ToBase64String(signature));
        SignToolRun(name, "sign /q /di \"" + folder + "\" \"" + target + "\"");
        return target;
    }

    private static void SignToolRun(string name, string arguments)
    {
        var start = new ProcessStartInfo(SignTool, arguments)
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true
        };
        using (var process = Process.Start(start))
        {
            var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
            process.WaitForExit();
            if (process.ExitCode != 0) throw new InvalidOperationException("signtool failed for " + name + ": " + output.Trim());
        }
    }
}
