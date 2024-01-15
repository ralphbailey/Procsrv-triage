# Procsrv Triage
The goal of this is to triage a computer infected by a malicious file and create a report based on CISA standards. Showcasing indicators and technical details, executive summary, technical summary, findings and analysis, and remediation's. 

## Indicators and Technical Details
![indicators1](https://i.imgur.com/OeVG5Cy.png)
![indicators2](https://i.imgur.com/aBiq8bF.png)

##

## Executive Summary
On January 14, 2024, at approximately 6:00 am the security operations team was notified that a network computer was had been potentially compromised by malware. After further investigation, it was determed that the machine in question had likely been compromised by a trojan - a piece of malware that would potentially give an adversary unauthorized access to the compromised machine, the ability to move throughout the network, perform reconnaissance activities, and potentially exfiltrate data out of the network. The security operations team is confident that the malicious file did not steal any company data or information. No company user information was impacted and no other computers on the network were affected by this. 

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

Finally, there is history of contacting **dropbox** via an **IP address** range of **162.125.X.X**. (Figure 13.1 and 13.2)
![strings1](https://i.imgur.com/eBFyB2M.png)
![network1](https://i.imgur.com/vUGLZck.png)

Using the cmdlet of Get-CimInstance -ClassName Win32_UserAccount -Property * (Figure 14.1), we can see what the trojan was querying (Figure 14.2). When we change the cmdlet to Win32_ComputerSystem, again we can see a ton of information here in regards to our system. (Figure 15)

![useraccount](https://i.imgur.com/bgD6p0V.png)
![processor](https://i.imgur.com/wQ7aWRS.png)

The strings of **lanman[.]dll** was dumped and we can see it calling **procsrv[.]exe** (Figure 16.1)

![strings2](https://i.imgur.com/T5e01FR.png)

When viewing the current running processes using Process Explorer, we see **procsrv[.]exe** with no parent or child processes. **Procsrv[.]exe** has a **PID** of **5332**. (Figure 17.1)

![procexp](https://i.imgur.com/zrKtdQK.png)

Inside the properties of **procsrv[.]exe** under the TCP/IP tab is an established connection to IP Address **162[.]125[.]6[.]8** using protocol **443**. (Figure 18.1)

![procexp2](https://i.imgur.com/tX4n8VS.png)

When viewing real-time system, registry, and process/thread activity using Process Monitor and filtering for PID 5332, we can see it reading various registry hives including **HKCR\InprocServer32** and **HKCU\InprocServer32**. (Figure 19.1)
Next, we can see that **PID 5332** is connecting with IP Address **162[.]125[.]6[.]18**. (Figure 20.1)

![procmon1](https://imgur.com/QCVFuwe.png)
![procmon2](https://i.imgur.com/4h3kXq1.png)

Inside Wireshark we can see communication with IP Address 162[.]125[.]6[.]18. (Figure 21.1)

![wireshark](https://i.imgur.com/r71rPi5.png)

When performing a **nslookup** and **whois** of the IP Address, it returns as being a **non-existent** domain. (Figure 22.2)

![whois](https://i.imgur.com/LZTaFDd.png)

While viewing domain information using **Domain Dossier**, the domain in question is registered to **Dropbox**, (Figure 21.2). Next, we can see the certificate information, again, is also registered to **Dropbox**. (Figure 23.1)

![dd1](https://i.imgur.com/MaPJycE.png)
![dd2](https://i.imgur.com/iW7cQGX.png)

Finally, when viewing the website of the IP Address, it shows as **Dropbox** (Figure 23.1) returning an error of **404** (Figure 24.2)
![web](https://i.imgur.com/KIbJKMV.png)
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
