# Analyzed file
remcos_sample_small.exe, 3797d5082f3612a2493ce6430ed09a61922573f6871401f95b0d2e735a12ada1, 645KB (660,480b), PE64 executable, x64, AMD64, GUI

# Static analysis

### Packing 
No packing detected: section entropy is <6.5, no sections are encrypted.

### Strings
Mostly present in .rdata, some of them include:
- directories for different browsers (Chrome, Firefox, Opera, etc.) and strings like "Login Data", "StoredLogins", "Cookies";
- Remcos version - "7.3.1 Pro"; log messages, for example " { User has been idle for" and " minutes }";
- ASCII logo,
- LDAP/X.500 field names, such as "/userid=", "/emailAddress=", "/favouriteDrink=", "/serialNumber=", "/UID=" and others;
- non-printable keys for the keylogger ("[Space]", "[BckSp]", "[Tab]", etc.)
- link to pro[.]ip-api[.]com (IP geolocation service) with a "?key=" field

### Imports
- KERNEL32: 169 imports, system functions for memory, threads, mutexes, strings, files functionality, etc.
- USER32: access to clipboard, open windows, mouse and keyboard; setting up and calling hooks
- ADVAPI32: access to registry
- SHELL32: ShellExecute
- WINMM: sound recording
- urlmon: downloading files
- WININET: internet access

### Resources
There is a non-standard resource present named SETTINGS of type RCDATA. It is encrypted using RC4, and was decrypted using that same algorithm: the byte of index 0 is the key lengh n, bytes [1-n] are the key itself and the rest is the encrypted data. Decryption was done using CyberChef.

Discoveries made during the analysis of the SETTINGS resource: C2, "godofeste" string, possibly, the campaign name or a username, names for the mutex, log file, Screenshots and MicRecords directories, hex-string (presumably a license) and a binary sequence possibly related to TLS (certificate with issuing date and keys).

### IDA
All resource-related functions are referenced only once in a single function, which has been renamed to "loadres". It performs a simple check via FindResourceA looking for a resource named "SETTINGS", and, if it is found, it gets loaded, returning a pointer to it via LockResource.

After loadres, j__malloc_base is called, allocating a buffer for a copy of the resource.

Next follows a call to a function acting as KSA in RC4, which can be determined by loops and modulo of 256. The function has been restored to pseudocode, and, after renaming the variables, is:
```c
v3 = 0;
  i = 0;
  arr = sbox;
  do
  {
    v7 = _mm_cvtsi32_si128(i);
    i += 4;
    *sbox++ = _mm_add_epi32(_mm_shuffle_epi32(v7, 0), shuffle_vector);
  }
  while ( i < 256 );
  j = 0;
  v9 = arr;
  do
  {
    v3 = (v9->m128i_i32[0] + *(j % keylen + keyptr) + v3) % 256;
    v10 = v9->m128i_u8[0];
    ++j;
    result = arr->m128i_u32[v3];
    v9->m128i_i32[0] = result;
    v9 = (v9 + 4);
    arr->m128i_i32[v3] = v10;
  }
  while ( j < 256 );
  return result;
```

Next call is the second part of RC4, PRGA. Same process was applied to get the following:

```c
i = 0;
  j = 0;
  result = memcpy(&statearr, a1, 0x400u);
  len = a3 + 1;
  if ( len )
  {
    len1 = len;
    do
    {
      i = (i + 1) % 256;
      sbox = statearr.m128i_i32[i];
      j = (sbox + j) % 256;
      statearr.m128i_i32[i] = statearr.m128i_i32[j];
      statearr.m128i_i32[j] = sbox;
      result = (sbox + statearr.m128i_i32[i]) % 256;
      *data++ ^= statearr.m128i_u8[4 * result];
      --len1;
    }
    while ( len1 );
  }
  return result;
```

The output is the decrypted config. 

Additionally, a check for the "-l" command line argument was found in WinMain - a detail that was missed during the initial analysis. When the program is launched with this flag, a license_code.txt file is created, containing the same license as the one found in the config: 0B5D0E6217D2FCD0E17BB6AD49338B4B.

# Dynamic analysis

Malware is contained within one process.

1) A log file is created in user\AppData\Roaming\remcos,
2) requests are sent to a C2 server,
3) registry entries are created in \SOFTWARE\Rmc-WEPADL for values exepath, license, time and UID;

after analysis using autoruns no persistence functionality was found, neither through \Microsoft\Windows\CurrentVersion\Run, nor any other method. The analyzed sample is the payload, so there is a possibility that persistence is delegated to the loader.

# Conclusion

The analyzed sample is a multifunctional RAT that may act as the final payload in an attack chain. It has remote access/RCE functionality and capabillities for information collection (keylogger, microphone, screenshots, browser passwords/cookies).

### IoC
- SHA-256: 3797d5082f3612a2493ce6430ed09a61922573f6871401f95b0d2e735a12ada1
- Log file C:\Users\user\AppData\Roaming\remcos\logs.dat
- Registry entries at \SOFTWARE\Rmc-WEPADL
- Mutex BaseNamedObjects\Rmc-WEPADL
- Network: requests to catground1957[.]casacam[.]net:7788

### TI
- C2 server: catground1957[.]casacam[.]net,
- Remcos license: 0B5D0E6217D2FCD0E17BB6AD49338B4B
- ip-api.com pro version key, will not be shared here
- possible campaign/botnet name: godofeste
- JA3: 1ea4d3e85aed6aee54c91caf6c291471
- JA4: t13i010400_0f2cb44170f4_ac742885cf85

### ATT&CK
Collection:
- T1056.001 Keylogging - logs.dat
- T1113 Screen Capture - config, Screenshots folder
- T1123 Audio Capture - config, MicRecords folder, WINMM imports
- T1115 Clipboard Data - USER32 imports

Credential Access:
- T1555.003 Credentials from Web Browsers - Login Data strings, browser directories
- T1539 Steal Web Session Cookie - Cookies strings

Discovery:
- T1010 Application Window Discovery - application window titles
- T1614 System Location Discovery - requests to ip-api

Defense Evasion:
- T1140 Deobfuscate/Decode Files or Information - config decryption using RC4 in runtime
- T1112 Modify Registry - Rmc-WEPADL section

Command and Control:
- T1573.002 Encrypted Channel: Asymmetric Cryptography - TLS in the config
- T1571 Non-Standard Port - port 7788
