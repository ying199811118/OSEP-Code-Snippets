# Payload Generation


# Network 

## Chisel Tunnel
```bash
#Server Side
./chisel server -p 8001 --reverse

#Client Side
./chisel client <Server IP Address>:8001 R:1080:socks

#Server Side
proxychains4 nmap <IP Address>
```
