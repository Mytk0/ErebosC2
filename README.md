# Erebos C2

A custom command and control framework built for authorized penetration testing and red team operations.

## Architecture

- **Beacon** - C implant using WinINet for HTTPS communication
- **Server** - Go HTTP/S listener with interactive command dispatch

## Features

- HTTPS encrypted communications (TLS)
- XOR encrypted strings (IP, endpoint, user-agent)
- Jitter sleep to blend beacon timing
- Unique agent ID per implant
- Command execution with output exfiltration

## Disclaimer

Erebos C2 is intended for authorized penetration testing, red team operations, and educational research only. Use of this tool against systems without explicit written permission is illegal. The authors assume no liability for misuse.

## Usage

### Server
```bash
go run server.go
```

### Beacon
Compile with MinGW:
```bash
gcc beacon.c -o beacon.exe -lwininet
```

## License

MIT
