# Malware Analysis Writeups

Reports from my malware analysis practice: static and dynamic analysis, reverse engineering, configuration extraction and threat intelligence.

| Report | Type | Highlights |
|---|---|---|
| [Remcos](remcos/) | PE x64 RAT | RC4 config extraction, IDA analysis |
| [VIP Keylogger via RGBLoader](vip-keylogger/) | .NET, multi-stage | steganography, process hollowing, UAC bypass, config decryption |
| [JS ScreenConnect loader](js-screenconnect/) | JScript (WSH) | javascript-obfuscator, RMM abuse |

Lab configuration: FLARE-VM on Windows 10, Remnux acting as a fake network via INetSim. Virtual machines connected using VirtualBox's Internal Network.

All samples were obtained from public sources (MalwareBazaar). No samples are included in this repository; hashes only.
Credentials found in samples are not included in the reports.
