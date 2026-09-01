# Security policy

Encrypted VHD Boot Bridge is experimental, security-sensitive pre-boot
software. The tested configurations are listed in the README. No release has
received an independent security audit, and support for a Windows build or
VeraCrypt configuration must not be interpreted as a security certification.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to
[riodaa@proton.me](mailto:riodaa@proton.me). Include the affected release,
hardware/firmware context, reproduction steps, and the least sensitive logs or
artifacts needed to investigate. Do not include passwords, keys, encrypted VHDs,
or other secrets.

Please avoid opening a public issue until the report has been assessed and a
coordinated disclosure date has been agreed where appropriate.

## Operational limits

- Keep independent, recoverable backups of every VHD used for testing.
- Verify release hashes before installation.
- Secure Boot is not supported; current EFI binaries are unsigned.
- Only the compatibility matrix and limitations documented for the current
  release have been exercised end to end.
