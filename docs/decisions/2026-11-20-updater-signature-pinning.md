# Updates must be signed under a pinned private root (DI-5)

**Decision.** `Updater.Download` keeps the SHA-256 check and adds an Authenticode check (`SignatureCheck`):
- WinVerifyTrust must find the signature intact;
- an `X509Chain` built with the embedded root in `ExtraStore` must end at that root, byte for byte;
- the leaf must have the Code Signing EKU;
- validity is checked at the signature's timestamp, if there is one.

**Why.** The GitHub digest protects only the transfer: anyone who can change the release can change the file and its digest. The signing keys live on the user's YubiKeys, so only a signature from them proves the source. The root is private and not in Windows' trust store, so trust comes from pinning, not from Windows. .NET Framework 4.8 has no `CustomTrustStore`, so we compare roots ourselves.

**WinVerifyTrust results allowed.** `0`, `CERT_E_UNTRUSTEDROOT` and `CERT_E_CHAINING`.
- The card allowed only untrusted-root. But on a PC without the root in a store, the tests' correctly signed files get `CERT_E_CHAINING` (0x800B010A). That holds even when signtool's `/ac` adds the root to the signature. Allowing only untrusted-root would refuse every genuine update.
- Both results are about trust in the chain, which our pinned-root check settles. Digest and signature errors (`TRUST_E_BAD_DIGEST`, `TRUST_E_NOSIGNATURE` and the rest) still refuse.

**Validity time.** It comes from WinVerifyTrust's own signer data (`CRYPT_PROVIDER_SGNR.sftVerifyAsOf`): the time of the timestamp it verified, or now. We don't parse it from the file ourselves.

**Revocation.** Off, because the private CA publishes no CRL. To withdraw a key, ship a release that pins a new root.
