# Erebos C2
A simple C2 framework built from scratch as a personal research project, exploring implant development, evasion techniques, and C2 architecture.

## Architecture
- **Beacon** - C implant using WinINet for HTTPS communication
- **Server** - Go HTTP/S listener with interactive command dispatch

## Features
- HTTPS encrypted communications (TLS)
- XOR encrypted strings (IP, endpoint, user-agent)
- Jitter sleep to blend beacon timing
- Unique agent ID per implant
- Command execution with output exfiltration

## Evasion Techniques
- **ETW patching** - `EtwEventWrite` overwritten with `0xC3` to blind event tracing
- **ntdll unhooking** - clean `.text` section restored from disk to remove EDR hooks
- **AMSI bypass** - `AmsiScanBuffer` patched to return `E_INVALIDARG`
- **String encryption** - sensitive strings XOR encrypted at rest, decrypted only at runtime
- **Silent execution** - no console window spawned

## Roadmap
- [ ] Reflective DLL injection
- [ ] PPID spoofing for child process spawning
- [ ] Sleep obfuscation (Ekko)
- [ ] Staged payload delivery
- [ ] Qt GUI for operator interface

## Disclaimer
Erebos C2 is intended for authorized penetration testing, red team operations, and educational research only. Use of this tool against systems without explicit written permission is illegal. The author assumes no liability for misuse.

## Usage
### Server
Generate a self-signed certificate first:
```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
```
Then run the server:
```bash
go run server.go
```

### Beacon
Compile with MinGW:
```bash
gcc beacon.c -o beacon.exe -lwininet -mwindows "-Wl,--entry=mainCRTStartup"
```

## License
MIT
