# GoProxy

**Version 3.0**

GoProxy is a high-performance proxy server written in Go. It provides:

- **HTTP(S) proxy** with CONNECT support
- **SOCKS5 proxy** (RFC 1928 / RFC 1929)
- **Auto-detect mode** — HTTP and SOCKS5 on the same port
- **TCP port forwarding** (with optional TLS)
- **UDP port forwarding**
- **NAT traversal (tunnel)** — expose internal services through a relay bridge
- **Authentication** — file-based, CLI-based, or external HTTP API with caching
- **Smart routing** — blocked/direct domain lists with intelligent detection
- **Upstream proxy chaining** — per-user upstream via auth API
- **Connection pooling** with auto-refill
- **TLS encryption** for local listeners and parent connections
- **Traffic accounting** — per-user bytes in/out tracking
- **Rate limiting** at the I/O level
- **Concurrent connection limits**

## Documentation

- [Full Manual](docs/manual/manual.md)

---

## Installation

Requires Go 1.16+:

```bash
go build -o proxy
```

Generate TLS certificates (requires OpenSSL):

```bash
proxy keygen
```

---

## Quick Start

### HTTP Proxy

```bash
proxy http -p :8080
```

### HTTP Proxy with Authentication

```bash
proxy http -p :8080 -a user1:pass1 -a user2:pass2
```

### HTTP Proxy with External API Auth

```bash
proxy http -p :8080 --auth-url http://auth-server/check
```

### Auto-Detect Proxy (HTTP + SOCKS5 on same port)

```bash
proxy auto -p :33080
```

### TCP Port Forwarding

```bash
proxy tcp -p :3389 -P 10.0.0.5:3389 -T tcp
```

### UDP Port Forwarding

```bash
proxy udp -p :53 -P 8.8.8.8:53 -T udp
```

### NAT Traversal (Tunnel)

```bash
# On public server (bridge):
proxy tbridge -p :33080 -C proxy.crt -K proxy.key

# On server side (expose local port 8080):
proxy tserver -p :8080 -P bridge:33080 -k mykey -C proxy.crt -K proxy.key

# On client side (forward to local service on port 80):
proxy tclient -p :80 -P bridge:33080 -k mykey -C proxy.crt -K proxy.key
```

---

## Available Commands

| Command | Description |
|---------|-------------|
| `http` | HTTP(S) forward proxy |
| `auto` | Auto-detect proxy (HTTP + SOCKS5 on same port) |
| `tcp` | TCP port forwarding |
| `udp` | UDP port forwarding |
| `tserver` | Tunnel server (NAT traversal) |
| `tclient` | Tunnel client (NAT traversal) |
| `tbridge` | Tunnel bridge (NAT traversal relay) |
| `keygen` | Generate TLS certificate and key |

## Global Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--parent` | `-P` | *(empty)* | Parent/upstream proxy address |
| `--local` | `-p` | `:33080` | Local ip:port to listen on |
| `--cert` | `-C` | `proxy.crt` | TLS certificate file |
| `--key` | `-K` | `proxy.key` | TLS key file |

---

## Authentication

Three authentication backends are supported:

1. **CLI args**: `-a user1:pass1 -a user2:pass2`
2. **Auth file**: `-F auth.txt` (one `user:pass` per line)
3. **External API**: `--auth-url http://server/check` (GET with `user`, `pass`, `ip`, `local_ip`, `target` params; returns 200/204 on success)

The external auth API can return an `upstream` response header to route the user through a specific upstream proxy.

Auth results can be cached with `--auth-cache-ttl <seconds>`.

---

## Project Structure

```
main.go              - Entry point, signal handling
config.go            - CLI argument parsing (kingpin)
config/types.go      - Configuration structs
services/            - Service implementations (http, auto, tcp, udp, tunnel)
proxy/               - Protocol handlers (HTTP, SOCKS5, auto-detect)
server/              - Unified server with connection management
auth/                - Authentication (basic, API, cache)
traffic/             - Per-user traffic accounting
transport/           - Dialer, listener, connection pool
utils/               - Shared utilities (I/O, TLS, checker, etc.)
```

## License

Licensed under GPLv3.
