# MSI SecureRepairWhitelist Auditor

A PowerShell script to audit installed MSI packages listed in the Windows `SecureRepairWhitelist` registry key for privilege escalation.

## Why

The `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer\SecureRepairWhitelist` registry key allows standard users to trigger repair operations (`msiexec /fa`) on specific MSI packages without an UAC prompt (which was allowed by default for years before the recent patch by MS).

## Features

This script automates the entire audit process:
-   Enumerates all installed MSI products on a system.
-   Cross-references them with the `SecureRepairWhitelist`.
-   For **each** whitelisted package, it performs three key security checks:
    -   **Digital Signature:** Verifies if the cached MSI is digitally signed using the `WinVerifyTrust` API. If unsigned, the integrity of the package cannot be verified and you could modify its binaries for privesc.
    -   **File Permissions:** Checks if the MSI file in `C:\Windows\Installer` is writable. If so, you could modify it to add a Custom Action or anything else you need for privesc.
    -   **Custom Action Analysis:** Scans for potentially dangerous `CustomActions` (those running with `NoImpersonate` between `InstallInitialize` and `InstallFinalize` that run with elevated privileges).
-   Generates a comprehensive audit report in both **TXT** and **HTML** formats.

- This script could also be useful if your target system is older and doesn't have the MS patch installed. Just remove the part where the registry whitelist is cross-referenced and include all MSI packages.

## Sample Report

The script generates an HTML report for easy analysis of potential vulnerabilities.

![HTML Report Screenshot](./img/html_report.png)

## Usage

```powershell
.\auditMSIWhitelist.ps1 "C:\ReportPath"
```

## Disclaimer

This script is intended for security auditing and educational purposes. Always test scripts in a controlled environment. The author is not responsible for any misuse or damage.
