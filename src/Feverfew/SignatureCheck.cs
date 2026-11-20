using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Feverfew
{
    /// <summary>
    /// Checks a file's Authenticode signature against pinned roots. Users' PCs don't trust the private
    /// code-signing root, so Windows only checks the signature itself and the chain is checked here.
    /// </summary>
    public static class SignatureCheck
    {
        public const string CodeSigningOid = "1.3.6.1.5.5.7.3.3";

        private const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);
        // The signature may carry only the leaf. Without the root in a store Windows then can't finish the chain.
        private const int CERT_E_CHAINING = unchecked((int)0x800B010A);
        private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);

        /// <summary>True when the file is validly signed by a code-signing certificate that chains to one of the roots.</summary>
        public static bool Verify(string path, IList<X509Certificate2> pinnedRoots, out string reason)
        {
            if (pinnedRoots == null || pinnedRoots.Count == 0) { reason = "this version has no trusted signing certificate to check against"; return false; }

            var signer = Trust(path, out reason);
            if (signer == null) return false;

            using (var chain = new X509Chain())
            {
                var policy = chain.ChainPolicy;
                policy.RevocationMode = X509RevocationMode.NoCheck; // the private CA publishes no revocation list
                policy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                policy.VerificationTime = signer.VerifyAsOf;
                policy.ApplicationPolicy.Add(new Oid(CodeSigningOid));
                policy.ExtraStore.AddRange(pinnedRoots.ToArray());
                foreach (var cert in signer.Chain) policy.ExtraStore.Add(cert);

                if (!chain.Build(signer.Leaf))
                {
                    reason = "its signing certificate isn't valid: " + string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation.Trim()).Distinct());
                    return false;
                }

                var root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                if (!pinnedRoots.Any(p => p.Thumbprint == root.Thumbprint && p.RawData.SequenceEqual(root.RawData)))
                {
                    reason = "it isn't signed by the Feverfew publisher (signer: " + signer.Leaf.Subject + ", root: " + root.Subject + ")";
                    return false;
                }
            }

            var eku = signer.Leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            if (eku == null || !eku.EnhancedKeyUsages.Cast<Oid>().Any(o => o.Value == CodeSigningOid))
            {
                reason = "its signing certificate isn't for code signing";
                return false;
            }

            reason = null;
            return true;
        }

        private sealed class Signer
        {
            public X509Certificate2 Leaf;
            public List<X509Certificate2> Chain = new List<X509Certificate2>();
            public DateTime VerifyAsOf;
        }

        /// <summary>Runs WinVerifyTrust. Returns the signer when the signature is intact and only the root's trust is missing.</summary>
        private static Signer Trust(string path, out string reason)
        {
            var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2
            var pathPtr = Marshal.StringToHGlobalUni(path);
            var fileInfo = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)), pcwszFilePath = pathPtr };
            var filePtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
            Marshal.StructureToPtr(fileInfo, filePtr, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                dwUIChoice = 2,            // WTD_UI_NONE
                fdwRevocationChecks = 0,   // WTD_REVOKE_NONE
                dwUnionChoice = 1,         // WTD_CHOICE_FILE
                pFile = filePtr,
                dwStateAction = 1,         // WTD_STATEACTION_VERIFY
                dwProvFlags = 0x10 | 0x1000 // WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
            };
            try
            {
                int result = WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                if (result != 0 && result != CERT_E_UNTRUSTEDROOT && result != CERT_E_CHAINING)
                {
                    reason = result == TRUST_E_NOSIGNATURE ? "it isn't signed" : "its signature is invalid (" + new System.ComponentModel.Win32Exception(result).Message.Trim() + ", 0x" + result.ToString("X8") + ")";
                    return null;
                }
                var signer = ReadSigner(data.hWVTStateData);
                reason = signer == null ? "its signer couldn't be read" : null;
                return signer;
            }
            finally
            {
                data.dwStateAction = 2; // WTD_STATEACTION_CLOSE
                WinVerifyTrust(IntPtr.Zero, ref action, ref data);
                Marshal.FreeHGlobal(filePtr);
                Marshal.FreeHGlobal(pathPtr);
            }
        }

        private static Signer ReadSigner(IntPtr state)
        {
            if (state == IntPtr.Zero) return null;
            var provider = WTHelperProvDataFromStateData(state);
            if (provider == IntPtr.Zero) return null;
            var sgnr = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
            if (sgnr == IntPtr.Zero) return null;

            // CRYPT_PROVIDER_SGNR: DWORD cbStruct; FILETIME sftVerifyAsOf (the timestamp's time when there is one);
            // DWORD csCertChain; CRYPT_PROVIDER_CERT* pasCertChain (offset 16 on x86 and x64).
            var signer = new Signer { VerifyAsOf = DateTime.FromFileTimeUtc(Marshal.ReadInt64(sgnr, 4)).ToLocalTime() };
            int count = Marshal.ReadInt32(sgnr, 12);
            var certs = Marshal.ReadIntPtr(sgnr, 16);
            for (int i = 0; i < count && certs != IntPtr.Zero; i++)
            {
                // CRYPT_PROVIDER_CERT: DWORD cbStruct; PCCERT_CONTEXT pCert; ...
                int size = Marshal.ReadInt32(certs);
                var context = Marshal.ReadIntPtr(certs, IntPtr.Size);
                if (context != IntPtr.Zero) signer.Chain.Add(new X509Certificate2(context));
                certs += size;
            }
            if (signer.Chain.Count == 0) return null;
            signer.Leaf = signer.Chain[0];
            return signer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll")]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

        [DllImport("wintrust.dll")]
        private static extern IntPtr WTHelperProvDataFromStateData(IntPtr state);

        [DllImport("wintrust.dll")]
        private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provider, uint signerIndex, [MarshalAs(UnmanagedType.Bool)] bool counterSigner, uint counterSignerIndex);
    }
}
