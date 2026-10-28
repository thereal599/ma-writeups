# Analyzed file
ZoomInstallerFull.js, e050ddccbdac97dfc8eb41760a76b1ae7f0c9e22a44034304462ea20c3ed51f5, MalwareBazaar tags: ConnectWise, HUN, js

# Contents 
330 lines of code, all strings are heavily obfuscated. The code can be separated into 3 parts:
1. Function Z(L, Q) - decryptor, where L - encrypted text, Q - key. This function declares two nested functions:

    1.1. D(X) - Base64 decoder with a non-standard alphabet (a-zA-Z0-9+/=). Converts the string to binary, then each byte to %XX and returns UTF-8 through decodeURIComponent.
    
    1.2. e(X, V) - RC4, X is input, V is the key.

2. Function J() - on first call creates a local array i containing Base64-like strings and redefines itself to return i.

3. Main function - contains a lot of strings like ```var Q = 'http://107' + Z(450, 'S)CX') + ':443/Bin/S' + Z(370, '#c^P') + 'ct.ClientS' + ...```, which are decoded in runtime. Contains the main malware functionality.

The code was deobfuscated by performing all Z functions, concatenating strings, renaming variables, and leaving only the main part of code. The obfuscator has been identified as javascript-obfuscator (obfuscator.io).

# Functionality
1) Requests administrator privileges through ShellExecute runas, prompting the user to accept the level elevation
2) sends a request to 107[.]174[.]19[.]11:443, downloads "ScreenConnect.ClientSetup.msi" (but saves it as "LogMeInResolve_Unattended.msi"; in any case, both programs provide remote access functionality), 
3) installs the downloaded .msi package. 

Each step runs inside a try...catch block, on error the script exits. All actions and their results are logged to C:\Windows\Temp\LogMeIn_Install.log. 

There are no configuration settings for the remote access software present in the code. Possible reason: the IP it downloads the .msi from could be the attacker's personal ScreenConnect server, and they might already be embedded within the installer.

# Conclusion
The analyzed file is a loader, downloading and installing remote access software. Next actions - downloading the .msi installer, checking the hypothesis about embedded settings.

### IOC
- ScreenConnect installed without the user's knowledge, 
- execution chain of wscript.exe -> msiexec.exe, 
- requests to the specified IP,
- files C:\Windows\Temp\LogMeIn_Install.log and \LogMeInResolve_Unattended.msi

### ATT&CK
- T1059.007 - Command and Scripting Interpreter: JavaScript
- T1219.002 - Remote Access Tools: Remote Desktop Software
- T1571 - Non-Standard Port (HTTP over port 443)
- T1027.010 - Obfuscated Files or Information: Command Obfuscation
- T1140 - Deobfuscate/Decode Files or Information
- T1105 - Ingress Tool Transfer
- T1218.007 - System Binary Proxy Execution: Msiexec
- T1036.005 - Masquerading: Match Legitimate Resource Name or Location
- T1566 - Phishing (possibly, the delivery method)


