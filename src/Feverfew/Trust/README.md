# Pinned code-signing roots

Public root certificates (`.cer`, DER or Base64) of the publisher's code-signing CA. Each `.cer` here is embedded in Feverfew.exe, and updates must be Authenticode-signed under one of them. Never put a `.pfx` or a private key here. See `AGENTS.md` at the project root.
