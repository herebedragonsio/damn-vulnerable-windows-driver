# Damn Vulnerable Windows Driver (DVWD)
This is an intentionally vulnerable Windows driver. It has been tested on Windows 11. Currently, the driver only presents vulnerabilities exploited in BYOVD attacks. More attacks will be added in the future.

## BYOVD Attacks
Bring-your-own-vulnerable-driver (BYOVD) attacks exploit vulnerabilities in signed Windows drivers. Ransomware and other cybercrime groups use often use vulnerable drivers to disrupt the endpoint agents of AV/EDR security tools and evade detection.

### Arbitrary Process Termination
An arbitrary process termination vulnerability exposes an unauthenticated IOCTL that takes a process ID (PID) as an argument and has a source code path, at the end of which it passes the PID to a Windows process termination API, such az `ZwTerminateProcess`.

### Arbitrary Memory Read
An arbitrary memory read vulnerability exposes an unauthenticated IOCTL that allows user processes to read arbitrary memory locations.

### Arbitrary Memory Write
An arbitrary memory write vulnerability exposes an unauthenticated IOCTL that allows user processes to write to arbitrary memory locations.
