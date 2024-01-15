# Procsrv Triage
The goal of this is to triage a computer infected by a malicious file and create a report based on CISA standards. Showcasing indicators and technical details, executive summary, technical summary, findings and analysis, and remediation's. 

## Indicators and Technical Details
![indicators1](https://i.imgur.com/OeVG5Cy.png)
![indicators2](https://i.imgur.com/aBiq8bF.png)

##

## Executive Summary
On January 14, 2024, at approximately 6:00 am the security operations team was notified of suspicious activity on a network computer. The malicious file performed discovery of computer hardware information and established a successful internet connection with an outside network. The malicious file did not steal any company data or information. No company user information was impacted and no other computers on the network were affected by this. 

##

## Technical Summary
On January 14 2024, at approximately 6:00 am the security operations team was notified of suspicious activity on a network computer with the IP Address of **10.10.3.5**. Upon initial investigation, persistence was placed inside the **HKCU\Run** hive with a key  of **Local Network Manager** having  an error of file not found. Inside the registry, the value of **Local Network Manager** was **C:\Windows\System32\rundll32.exe C:\Windows\System32\lanman.dll**.

Inside the **C:\Windows\System32** directory was 3 files: **lanman.dll, lanman.pfx, and procsrv.exe**. The strings and hashes of each file were dumped. **Procsrv.exe** is a trojan that was calling lanman.dll, performing system discovery of information by utilizing **root\cimv2**, which is a WMI namespace that contains classes for computer hardware and configuration, and querying SQL databases for UserAccount name and Processor information.
 
**Procsrv.exe** was running with a **PID** of **5332** and had no parent or child processes. The trojan had established a **HTTPS** connection with IP Address **162.125.6.18**. **Procsrv.exe** was reading registry hives, specifically **HKCU\InprocServer32** and **HKCR\InprocServer32**. 

##

## Findings and Analysis
![table](https://i.imgur.com/bpdAxAQ.png)

Upon initial investigation, a registry key was discovered in Autoruns being set to **Local Network Manager**, in the **HKEY_CURRENT_USER** hive with a **File Not Found** error. (Figure 1)
![autoruns](https://i.imgur.com/9pliXBR.png)

When viewing the registry in question (HKCU\Run), we see **Local Network Manager** with a value of **C:\Windows\system32\rundll32.exe C:\Windows\System32\lanman.dll, Register**. (Figure 2)
![registry](https://i.imgur.com/vD9FeCn.png)

When we navigate to the directory in question (C:\Windows\System32) and sort by date modified, we see 3 files: **procsrv.exe, lanman.dll, and lanman.pfx**. (Figure 3)

![directory](https://i.imgur.com/AYtBx3v.png)

The cmdlet of **Get-FileHash** was used to get the **SHA256 hash** of **procsrv.exe** (Figure 4.1 and 4.2)
![cmdlet1](https://i.imgur.com/XLlzfvN.png)

The SHA256 hash of **procsrv.exe** was uploaded to Virus Total returning a score of **30/68** (Figure 5.1). We can gather a lot of information from this. The **Popular threat label** is listed as **trojan.startun/tedy** (Figure 5.4), **Threat categories** is **trojan** (Figure 5.5), and **Family labels** are **startun, tedy, and msil**. (Figure 5.6)
![vt1](https://i.imgur.com/ihS8auh.png)

The cmdlet of **Get-FileHash** was used to get the **SHA256 hash** of **procsrv.exe** (Figure 6.1 and Figure 6.2)
![cmdlet2](https://i.imgur.com/YICPxSb.png)

The SHA256 hash of **lanman.dll** was uploaded to Virus Total returning a score of **21/68** (Figure 7.1). We can gather a lot of information from this. The **Popular threat label** is listed as **trojan.startun/msil** (Figure 7.4), **Threat categories** is **trojan** (Figure 7.5), and **Family labels** are **startun, msil, and tedy**. (Figure 7.6)
![vt2](https://i.imgur.com/qGjH7vT.png)

The cmdlet of **Get-FileHash** was used to get the **SHA256 hash** of **procsrv.exe** (Figure 8.1 and 8.2)
![cmdlet3](https://i.imgur.com/EvsQ4vF.png)

The SHA256 hash of **lanman.pfx** was uploaded to Virus Total returning a score of **0/40** (Figure 9.1)
![vt3](https://i.imgur.com/9vPHSMI.png)

The strings of **procsrv.exe** were dumped using the **cmdlet** of strings and exporting to a text document. Listed here is the **HKCU\Run** hive (Figure 10.1), the registry key name of **Local Network Manager** (Figure 10.2), the registry value **C:\Windows\system32\rundll32.exe C:\Windows\System32\lanman.dll** (Figure 10.3), **root\CIMV2** (Figure 10.4), **system discovery** (10.5), and finally the website of **https://www[.]dropbox[.]com** (Figure 10.6). 

**root\CIMV2** is a WMI namespace that contains classes for computer hardware and configuration. **procsrv.exe** has a history and behavior of querying sensitive operating system information (MITRE T1082). In Figure 10.5, the trojan is querying system information from an SQL database of **UserAccount names**, and **ComputerSystem Processors**.  

This trojan also has a behavior of **Persistence** by creating an autostart registry key pointing to binary in C:\Windows (MITRE T1547.001), and **Defense Evasion** of running a DLL by calling functions (MITRE T1218.011). 

Finally, there is history of contacting **dropbox** via an **IP address** range of **162.125.X.X**. (Figure 11.1 and 11.2)
![strings1](https://i.imgur.com/eBFyB2M.png)
![network1](https://i.imgur.com/vUGLZck.png)

The strings of **lanman[.]dll** was dumped and we can see it calling **procsrv[.]exe** (Figure 12.1)

![strings2](https://i.imgur.com/T5e01FR.png)

When viewing the current running processes using Process Explorer, we see **procsrv[.]exe** with no parent or child processes. **Procsrv[.]exe** has a **PID** of **5332**. (Figure 13.1)

![procexp](https://i.imgur.com/zrKtdQK.png)

Inside the properties of **procsrv[.]exe** under the TCP/IP tab is an established connection to IP Address **162[.]125[.]6[.]8** using protocol **443**. (Figure 14.1)

![procexp2](https://i.imgur.com/tX4n8VS.png)

When viewing real-time system, registry, and process/thread activity using Process Monitor and filtering for PID 5332, we can see it reading various registry hives including **HKCR\InprocServer32** and **HKCU\InprocServer32**. (Figure 15.1)
Next, we can see that **PID 5332** is connecting with IP Address **162[.]125[.]6[.]18**. (Figure 16.1)

![procmon1](https://imgur.com/QCVFuwe.png)
![procmon2](https://i.imgur.com/4h3kXq1.png)

Finally, inside Wireshark we can see communication with IP Address 162[.]125[.]6[.]18. (Figure 17.1)
![wireshark](https://i.imgur.com/r71rPi5.png)

##

## Remediations
1. Remove computer from network to prevent spread of infection
2. Kill procsrv inside Process Explorer
3. Delete Local Network Manager from HKCU\Run hive
4. Delete the following files from C:\Windows\System32 : lanman.dll, lanman.pfx, and procsrv.exe
5. Block IP Address 162.125.6.18 and known IP Addresses of procsrv: 162.125.11.1, 162.125.67.1, and 162.125.7.18
6. Block www[.]dropbox[.]com
7. Block known DNS resolutions: WIN-5307COS9ALR, www[.]dropbox-dns[.]com, and www[.]dropbox[.]com
8. Block all 3rd party cloud storage sites, only use native windows cloud storage, OneDrive
9. Computer should be reimaged, updated and moved to its own VLAN to prevent any future infection to network computers
