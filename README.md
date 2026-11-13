# Damn Vulnerable Windows Driver (DVWD)
This is an intentionally vulnerable Windows driver. It has been tested on Windows 11. Currently, the driver only presents vulnerabilities exploited in BYOVD attacks. More vulnerabilities will be added in the future.

DVWD is a software-only, non-PnP driver that comes in both the legacy Windows Driver Model (WDM) and the modern Kernel-Mode Driver Framework (KMDF) varieties.

## Table of Contents

- [Building the Drivers](#building-the-drivers)
- [Loading the Drivers](#loading-the-drivers)
- [BYOVD Attacks](#byovd-attacks)
  - [Arbitrary Process Termination](#arbitrary-process-termination)
  - [Arbitrary Memory Read](#arbitrary-memory-read)
  - [Arbitrary Memory Write](#arbitrary-memory-write)
- [Feedback](#feedback)

## Building the Drivers
<p align="right"><a href="#damn-vulnerable-windows-driver-dvwd">back to top</a></p>

The build for both WMD and KMDR drivers is tested using Visual Studio 2026. The following needs to be added in the Visual Studio Installer:

- `Desktop development in C++` workload
- Individual components:
    - C++ Spectre-migrated Spectre-mitigated libs for x64/x86 (Latest MSVC)
    - C++ Spectre-migrated Spectre-mitigated libs for ARM64/ARM64EC (Latest MSVC)
    - C++ ATL with Spectre Mitigations for x86/x64 (Latest MSVC)
    - C++ ATL with Spectre Mitigations for ARM64/ARM64EC (Latest MSVC)
    - C++ MFC with Spectre Mitigations for x86/x64 (Latest MSVC)
    - C++ MFC with Spectre Mitigations for ARM64/ARM64EC (Latest MSVC)
    - Windows 11 SDK (10.0.28000.2526 or latest version)
    - Windows Driver Kit (WDK)
    - MSVC Build Tools for ARM64/ARM64EC (Latest)

Also, download and install the Windows Driver Key (WDK) full package from https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk. Choose the same version as the Windows 11 SDK above, e.g. 10.0.28000.2526.

Right-click on the Visual Studio project, open the Properties and navigate to Driver Signing. Ensure that `Sign Mode` is set to `Test Sign`. Build the project using Visual Studio and it will sign the `.sys` driver file with a test certificate.

## Loading the Drivers
<p align="right"><a href="#damn-vulnerable-windows-driver-dvwd">back to top</a></p>

Because Windows by default requires kernel-mode drivers to be signed and we can't sign the vulnerable drivers here with a valid code-signing certificate authority, we need to disable Secure Boot and enable Test Mode to relax the driver-signing requirement. This should be done on a test Windows machine to avoid the adverse side effects of disabling Secure Mode and enabling Test Mode.

1. Restart the machine and disable Secure Boot in the BIOS or the VM settings.
2. Enable Test Mode using `bcdedit /set testsigning on` and restart the machine again.
3. You should see a `Test Mode` watermark in the lower right-hand corner of your desktop.

Non-PnP drivers are loaded using the Service Control Manager:

    sc.exe create DVWD_WDM type=kernel binPath= <path-to-repo>\damn-vulnerable-windows-driver\DVWD_WDM\x64\Debug\DVWD_WDM.sys
    sc.exe start DVWD_WDM

    sc.exe create DVWD_KMDF type=kernel binPath= <path-to-repo>\damn-vulnerable-windows-driver\DVWD_KMDF\x64\Debug\DVWD_KMDF.sys
    sc.exe start DVWD_KMDF

When done testing, the Service Control Manager can unload and remove the drivers:

    sc.exe stop DVWD_WDM
    sc.exe delete DVWD_WDM

    sc.exe stop DVWD_KMDF
    sc.exe delete DVWD_KMDF

## BYOVD Attacks
<p align="right"><a href="#damn-vulnerable-windows-driver-dvwd">back to top</a></p>
Bring-your-own-vulnerable-driver (BYOVD) attacks exploit vulnerabilities in signed Windows drivers. Ransomware and other cybercrime groups use often use vulnerable drivers to disrupt the endpoint agents of AV/EDR security tools and evade detection.

### Arbitrary Process Termination
<p align="right"><a href="#damn-vulnerable-windows-driver-dvwd">back to top</a></p>
An arbitrary process termination vulnerability exposes an unauthenticated IOCTL that takes a process ID (PID) as an argument and has a source code path, at the end of which it passes the PID to a Windows process termination API, such az `ZwTerminateProcess`.

### Arbitrary Memory Read
<p align="right"><a href="#damn-vulnerable-windows-driver-dvwd">back to top</a></p>
An arbitrary memory read vulnerability exposes an unauthenticated IOCTL that allows user processes to read arbitrary memory locations.

### Arbitrary Memory Write
<p align="right"><a href="#damn-vulnerable-windows-driver-dvwd">back to top</a></p>
An arbitrary memory write vulnerability exposes an unauthenticated IOCTL that allows user processes to write to arbitrary memory locations.

## Feedback
<p align="right"><a href="#damn-vulnerable-windows-driver-dvwd">back to top</a></p>

If you liked this project or have feedback or ideas for development, I would love to hear them! Create a GitHub issue or contact me directly at @herebedragonsio on X.