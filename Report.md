# Surface-Level Malware Analysis Report

## 1. Initial Identification
- **VirusTotal Check:** The malware was identified by VirusTotal. A screenshot of the results was taken.
- **Hash Extraction:** The hashes were obtained using PEStudio for further verification.
- **Executable Name Analysis:** The malware mimics a company invoice PDF file, suggesting a phishing attempt.

## 2. Static Analysis (Without Execution)
### **PEStudio Analysis:**
- **URLs and IP Addresses:** Found a suspicious URL: `corect.com`.
- **Sections Analysis:**
  - `.text` section raw size: ~46K
  - `.text` section virtual size: ~46K
  - Since raw and virtual sizes are similar, the binary is likely **not packed**.
- **Strings Analysis:**
  - Found API calls like `GetCapture` (used for taking screenshots) flagged as malicious.
  - Key DLLs used: `KERNEL32.DLL`, `USER32.DLL`.
  - Functions of interest: `KERNEL32.DLL.CREATEFILE` (used to create files on the filesystem).
- **DLL Imports:**
  - Identified three key DLLs: `KERNEL32.DLL`, `USER32.DLL`, `SHLWAPI.DLL`.
- **Executable Verification:**
  - The first few bytes show `M.Z`, confirming it as a PE executable.

### **FLOSS Analysis:**
- Extracted strings, including obfuscated function names.
- Found `corect.com` again.

### **CAPA Analysis:**
- Detected **virtualization evasion techniques**.
- Running `capa -vv` revealed specific binary sections responsible for these techniques.

### **Historical Investigation of corect.com:**
- Searched `corect.com` in VirusTotal – no significant results.
- Used the Wayback Machine – found that in 2013, it was a Romanian news site. Possible malware origin.

### **PEStudio and API Calls:**
- Found unusual API calls like `GetAsyncState`, indicating the ability to interact with user input and create files.
- Identified obfuscated function names likely used to conceal malicious actions.

## 3. Advanced Static Analysis
### **Cutter Analysis (Assembly Visualization):**
- Identified **entry point** of execution.
- Key API calls found: `GetSysColor`, `AllowSetForegroundWindow`, `GetTickCount` (used to measure system uptime).
- Graph view mapped execution flow.
- Identified suspicious strings that did not appear as expected function calls, suggesting **obfuscation**.
- Close proximity of `KERNEL32.CREATEFILE` to obfuscated strings supports the obfuscation hypothesis.

## 4. Dynamic Analysis
### **Execution in FLARE VM (Isolated Environment):**
- **Precautions:** Host-only networking and system snapshot taken before execution.
- **Monitoring Tools:** Process Monitor (`procmon`) and REMnux for DNS impersonation.
- **Execution Observations:**
  - Binary **self-deleted** after execution.
  - **Process Tree Analysis:**
    - Parent: `invoice.exe`
    - Child processes: `cmd.exe` and `conhost.exe` (in **suspended** state).
    - `conhost.exe 0xfffffff -ForceV1` command suggests stealth execution.
  - **Procmon Filtering:**
    - Found altered files: `msimg32.dll` and `InstallFlashPlayer.exe` (likely malicious DLLs/executables).
    - **Registry Modifications:** `RegSetValue` operation modified Google Update keys.
    - Found `Google Update` running in a **suspended state** with child processes, suggesting **persistence** via execution during Google Update runs.

## 5. Network Indicators of Compromise (IOC)
### **Wireshark Analysis:**
- **Restored VM** before execution due to self-deletion of malware.
- **DNS Configuration Validation:** Confirmed via `google.com` request.
- **Packet Capture:**
  - Found **GET request** for `GetFlashPlayer.exe` (malware download site).
  - Other connections: YouTube, Wikipedia, `msftconnecttest.com`.
  - TLS encryption used to **obfuscate malicious traffic**.
- **Further Analysis:**
  - Extracted domain names/IPs from packets.
  - Checked domains in VirusTotal and WHOIS for ownership details.

## 6. Secondary Sample Analysis
- Uploaded `msimg32.dll` and `InstallFlashPlayer.exe` to VirusTotal – **confirmed malicious**.
- Observation: Legitimate Adobe installer but with **malicious DLL sideloading**.

## Conclusion
- The malware is **not packed** but employs **obfuscation techniques**.
- **Static Analysis Findings:** Identified API calls and obfuscation.
- **Dynamic Analysis Findings:** 
  - Malware exhibits **self-deletion** and **persistence via Google Update hijacking**.
  - Uses `conhost.exe` for stealth execution.
- **Network Analysis Findings:**
  - Contacted `corect.com`, likely a **C2 server**.
  - Attempts to download malicious Flash Player installer.
  - Utilizes **TLS encryption** to evade detection.
- **Mitigation Strategies:**
  - Block `corect.com` at network level.
  - Remove Google Update persistence mechanism.
  - Investigate compromised hosts for additional threats.

