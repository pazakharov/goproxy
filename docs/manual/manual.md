# GoProxy Manual

**Version: 3.0**

GoProxy is a high-performance proxy server written in Go. It supports HTTP(S) proxy, SOCKS5 proxy, TCP/UDP port forwarding, and NAT traversal (tunnel) with TLS encryption, authentication, connection pooling, and smart routing.

---

## Table of Contents

- [Installation](#installation)
- [Certificate Generation](#certificate-generation)
- [Global Flags](#global-flags)
- [Commands](#commands)
  - [HTTP Proxy (`http`)](#http-proxy)
  - [Auto-Detect Proxy (`auto`)](#auto-detect-proxy)
  - [TCP Port Forwarding (`tcp`)](#tcp-port-forwarding)
  - [UDP Port Forwarding (`udp`)](#udp-port-forwarding)
  - [Tunnel Server (`tserver`)](#tunnel-server)
  - [Tunnel Client (`tclient`)](#tunnel-client)
  - [Tunnel Bridge (`tbridge`)](#tunnel-bridge)
- [Authentication](#authentication)
  - [Basic Auth (File / CLI)](#basic-auth)
  - [External API Auth](#external-api-auth)
  - [Auth Cache](#auth-cache)
- [Smart Routing](#smart-routing)
- [Upstream Proxy Chaining](#upstream-proxy-chaining)
- [Connection Pool](#connection-pool)
- [Rate Limiting](#rate-limiting)
- [Traffic Accounting](#traffic-accounting)
- [TLS Encryption](#tls-encryption)
- [Max Connections Limit](#max-connections-limit)

---

## Installation

Build from source (requires Go 1.16+):

```bash
go build -o proxy
```

## Certificate Generation

Generate self-signed TLS certificates (requires OpenSSL):

```bash
proxy keygen
```

This creates `proxy.crt` and `proxy.key` in the current directory. These are required for TLS modes and tunnel functionality.

---

## Global Flags

These flags apply to all commands:

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--parent` | `-P` | *(empty)* | Parent/upstream proxy address (e.g. `23.32.32.19:28008`) |
| `--local` | `-p` | `:33080` | Local ip:port to listen on |
| `--cert` | `-C` | `proxy.crt` | TLS certificate file |
| `--key` | `-K` | `proxy.key` | TLS key file |

---

## Commands

### HTTP Proxy

```bash
proxy http [flags]
```

Full HTTP and HTTPS (CONNECT) proxy server. Supports direct connections, parent proxy forwarding, smart domain routing, authentication, and connection pooling.

#### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--local-type` | `-t` | `tcp` | Local listener protocol: `tls` or `tcp` |
| `--parent-type` | `-T` | — | Parent protocol: `tls` or `tcp` |
| `--always` | — | `false` | Always use parent proxy (skip smart routing) |
| `--timeout` | — | `2000` | TCP timeout (ms) when connecting to target or parent |
| `--http-timeout` | — | `3000` | HTTP request timeout (ms) for domain block checking |
| `--interval` | — | `10` | Domain block-check interval (seconds) |
| `--blocked` | `-b` | `blocked` | Blocked domains file (one domain per line) |
| `--direct` | `-d` | `direct` | Direct domains file (one domain per line) |
| `--auth-file` | `-F` | — | Auth file with `username:password` per line |
| `--auth` | `-a` | — | Auth credentials `user:pass` (repeatable) |
| `--auth-url` | — | — | External auth API URL |
| `--auth-timeout` | — | `3000` | Auth API request timeout (ms) |
| `--auth-cache-ttl` | — | `60` | Auth result cache TTL (seconds), `0` to disable |
| `--pool-size` | `-L` | `20` | Connection pool size (0 = disabled) |
| `--check-parent-interval` | `-I` | `3` | Parent health-check interval (seconds), `0` = disabled |
| `--debug` | — | `false` | Enable debug logging |
| `--max-conns` | — | `10000` | Max concurrent connections (`0` = unlimited) |

#### Examples

Basic HTTP proxy on port 8080:

```bash
proxy http -p :8080
```

HTTP proxy with parent via TLS:

```bash
proxy http -p :8080 -T tls -P 1.2.3.4:443
```

HTTP proxy with basic auth:

```bash
proxy http -p :8080 -a user1:pass1 -a user2:pass2
```

HTTP proxy with auth file:

```bash
proxy http -p :8080 -F /path/to/auth.txt
```

HTTP proxy with external API auth:

```bash
proxy http -p :8080 --auth-url http://auth-server/check
```

HTTP proxy with always-use-parent and blocked domains:

```bash
proxy http -p :8080 -P 1.2.3.4:8080 --always -b blocked_domains.txt
```

HTTP proxy listening on TLS:

```bash
proxy http -p :8443 -t tls -C proxy.crt -K proxy.key
```

---

### Auto-Detect Proxy

```bash
proxy auto [flags]
```

Listens on a single port and automatically detects whether the incoming connection is HTTP or SOCKS5 by inspecting the first byte. SOCKS5 connections start with `0x05`; everything else is treated as HTTP.

Accepts the same flags as the `http` command. Internally creates both an HTTP handler and a SOCKS5 handler.

#### Examples

Auto-detect proxy on port 33080:

```bash
proxy auto -p :33080
```

Auto-detect with authentication:

```bash
proxy auto -p :33080 -a user1:pass1
```

Auto-detect with external API auth and caching:

```bash
proxy auto -p :33080 --auth-url http://auth-server/check --auth-cache-ttl 120
```

---

### TCP Port Forwarding

```bash
proxy tcp [flags]
```

Forwards TCP connections from the local port to a parent address. Requires a parent (`-P`).

#### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--timeout` | `-t` | `2000` | TCP timeout (ms) |
| `--parent-type` | `-T` | — | Parent protocol: `tls`, `tcp`, or `udp` |
| `--tls` | — | `false` | Listen with TLS |
| `--pool-size` | `-L` | `20` | Connection pool size |
| `--check-parent-interval` | `-I` | `3` | Parent health-check interval (seconds) |

#### Examples

TCP port forwarding:

```bash
proxy tcp -p :3389 -P 10.0.0.5:3389 -T tcp
```

TCP forwarding with TLS encryption:

```bash
proxy tcp -p :3389 -P 10.0.0.5:3389 -T tls --tls
```

---

### UDP Port Forwarding

```bash
proxy udp [flags]
```

Forwards UDP packets from the local port to a parent address. Requires a parent (`-P`).

#### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--timeout` | `-t` | `2000` | Timeout (ms) |
| `--parent-type` | `-T` | — | Parent protocol: `tls`, `tcp`, or `udp` |
| `--pool-size` | `-L` | `20` | Connection pool size |
| `--check-parent-interval` | `-I` | `3` | Parent health-check interval (seconds) |

#### Examples

UDP forwarding:

```bash
proxy udp -p :53 -P 8.8.8.8:53 -T udp
```

UDP over TCP (parent is TCP):

```bash
proxy udp -p :53 -P 1.2.3.4:5353 -T tcp
```

---

### Tunnel Server

```bash
proxy tserver [flags]
```

NAT traversal server side. Listens on a local port (TCP or UDP) and forwards connections through a TLS tunnel via the bridge. Requires TLS certificates and a parent (bridge address).

#### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--timeout` | `-t` | `2000` | Timeout (ms) |
| `--udp` | — | `false` | UDP tunnel mode |
| `--k` | — | `default` | Shared key (must match tclient) |

#### Example

Expose local port 8080 through tunnel:

```bash
proxy tserver -p :8080 -P bridge-server:33080 -k mykey -C proxy.crt -K proxy.key
```

---

### Tunnel Client

```bash
proxy tclient [flags]
```

NAT traversal client side. Connects to the bridge and forwards traffic to the local target. Requires TLS certificates and a parent (bridge address).

#### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--timeout` | `-t` | `2000` | Timeout (ms) |
| `--udp` | — | `false` | UDP tunnel mode |
| `--k` | — | `default` | Shared key (must match tserver) |

#### Example

Forward tunnel to local service on port 80:

```bash
proxy tclient -p :80 -P bridge-server:33080 -k mykey -C proxy.crt -K proxy.key
```

---

### Tunnel Bridge

```bash
proxy tbridge [flags]
```

NAT traversal relay. Listens on TLS and relays connections between tunnel servers and clients matched by key. Requires TLS certificates.

#### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--timeout` | `-t` | `2000` | Timeout (ms) |

#### Example

Start bridge:

```bash
proxy tbridge -p :33080 -C proxy.crt -K proxy.key
```

### Tunnel Architecture

```
[External Client] --> [tserver :8080] --TLS--> [tbridge :33080] <--TLS-- [tclient] --> [Internal Service :80]
```

1. **tbridge** runs on a public server, listens for TLS connections.
2. **tserver** exposes a local port and connects to the bridge.
3. **tclient** connects to the bridge and forwards to an internal service.
4. All three must use the same TLS cert/key and matching `-k` key.

---

## Authentication

### Basic Auth

Provide credentials via CLI or file.

**CLI:**

```bash
proxy http -p :8080 -a user1:pass1 -a user2:pass2
```

**File** (`-F`): one `username:password` per line. Lines starting with `#` are comments.

```
user1:pass1
user2:pass2
# this is a comment
```

Both HTTP (Basic Auth) and SOCKS5 (username/password auth per RFC 1929) are supported.

---

### External API Auth

Use `--auth-url` to delegate authentication to an external HTTP service.

The proxy sends a GET request:

```
GET <auth-url>?user=<user>&pass=<pass>&ip=<client_ip>&local_ip=<proxy_ip>&target=<target_host>
```

**Expected responses:**

| Status Code | Meaning |
|-------------|---------|
| `200` or `204` | Authentication success |
| Any other | Authentication failure |

**Response headers:**

| Header | Description |
|--------|-------------|
| `upstream` | *(Optional)* Upstream proxy URL for this user (enables per-user proxy chaining) |

---

### Auth Cache

When `--auth-cache-ttl` is set to a value greater than 0, successful authentication results are cached in memory for the specified number of seconds. This reduces load on the external auth API.

A background cleanup goroutine removes expired entries at half the TTL interval.

---

## Smart Routing

When a parent proxy is configured (without `--always`), the HTTP proxy uses smart domain routing:

1. Domains in the **blocked** file → always use parent proxy.
2. Domains in the **direct** file → always connect directly.
3. Unknown domains → periodically checked. If a direct connection fails more often than it succeeds, traffic is routed through the parent.

Domain matching supports subdomains: adding `example.com` to the blocked list also matches `sub.example.com`.

---

## Upstream Proxy Chaining

When the external auth API returns an `upstream` header, the proxy chains through that upstream proxy:

- **HTTPS targets**: sends a `CONNECT` request to the upstream proxy, then tunnels data.
- **HTTP targets**: forwards the request with the upstream's `Proxy-Authorization` header (original client auth header is replaced).

The upstream URL format: `http://user:pass@proxy-host:port`

This enables per-user routing to different upstream proxies based on the auth API response.

---

## Connection Pool

When `--pool-size` (or `-L`) is set to a value greater than 0 and a parent proxy is configured, the proxy maintains a pool of pre-established connections to the parent.

- Connections are created on startup and refilled automatically when the pool drops below 50%.
- The `--check-parent-interval` flag controls how often the parent is health-checked.
- Pool max capacity is `pool-size * 2`.

---

## Rate Limiting

I/O rate limiting is available at the transport level. When configured, data transfer between client and target is throttled to the specified bytes-per-second rate using a token bucket algorithm (`golang.org/x/time/rate`).

---

## Traffic Accounting

The `auto` mode includes per-user traffic accounting:

- **Bytes in** (received from client) and **bytes out** (sent to client) are tracked per authenticated user.
- Data is stored in an in-memory counter using atomic operations for thread safety.
- Traffic snapshots can be retrieved via the `Server.GetTrafficSnapshot()` method.

---

## TLS Encryption

TLS is used in multiple places:

- **Local listener**: use `--local-type tls` (or `--tls` for TCP mode) to accept TLS connections.
- **Parent connection**: use `--parent-type tls` to connect to parent via TLS.
- **Tunnel**: all tunnel components (tserver, tclient, tbridge) communicate over mutual TLS (client certificate verification is required).

Certificates are loaded from `proxy.crt` and `proxy.key` (configurable via `-C` and `-K`).

---

## Max Connections Limit

Use `--max-conns` to limit concurrent connections. When the limit is reached, new connections receive an `HTTP 503 Service Unavailable` response (for HTTP) or are immediately closed (for other protocols).

Default: `10000`. Set to `0` for unlimited.

---

## Traffic Reporting

The proxy's HTTP(S), SOCKS5, TCP, and UDP proxy functions support traffic reporting. Use `--traffic-url` to set an HTTP interface address where the proxy will report traffic usage for connections.

### Reporting Modes

Use `--traffic-mode` to specify the reporting mode:

- **normal** (default): Report traffic when the connection is released
- **fast**: Report traffic at regular intervals while the connection is active
- **fast-global**: Use a single reporter for all connections (see below)

### Fast Mode Configuration

When using `--traffic-mode=fast`, you can configure the reporting interval:

- `--traffic-interval <seconds>`: Reporting interval (default: 5 seconds)

### Fast Global Mode

Use `--fast-global` to enable fast global mode (only valid with `--traffic-mode=fast`). In this mode:

- Only one reporter runs regardless of concurrent connections
- Reporting interval is 5 seconds
- Request method is POST with `Content-Type: application/json`
- Body is a JSON array of traffic objects

Example POST body:
```json
[{}, {}]
```

### HTTP Request Format (Normal/Fast Mode)

The proxy sends an HTTP GET request to the `--traffic-url` with these query parameters:

```
http://127.0.0.1:33088/user/traffic?bytes=337&client_addr=127.0.0.1%3A51035&id=http&server_addr=127.0.0.1%3A33088&target_addr=myip.ipip.net%3A80&username=a&sniff_domain=myip.ipip.net
```

### Request Parameters

| Parameter | Description |
|-----------|-------------|
| `id` | Service ID flag |
| `server_addr` | Proxy address requested by client (IP:port) |
| `client_addr` | Client address (IP:port) |
| `target_addr` | Target address (IP:port), empty for TCP/UDP proxy |
| `username` | Proxy authentication username, empty for TCP/UDP proxy |
| `bytes` | Number of traffic bytes used by the user |
| `out_local_addr` | Outgoing TCP connection's local address (IP:port) |
| `out_remote_addr` | Outgoing TCP connection's remote address (IP:port) |
| `upstream` | Upstream used by outgoing TCP connection, empty if none |
| `sniff_domain` | Sniffed domain name (only with SPS and `--sniff-domain`), format: domain or domain:port |

### Response Requirements

The `--traffic-url` must respond with HTTP status code `204` for the report to be considered successful. Any other status code is considered a failure and will be logged.

### Usage with Authentication

Traffic reporting works well with API authentication to control user traffic usage in real-time:
1. Traffic is reported to the interface
2. Interface writes traffic data to database
3. Authentication API queries database to check traffic usage
4. Authentication decision is based on remaining traffic allowance

---

## Dead Loop Detection

The HTTP proxy detects routing loops by comparing the local listen address with the target address. If the target resolves to the same IP and port as the proxy listener, the connection is rejected.

---

## Signal Handling

The proxy handles OS signals (`SIGINT`, `SIGTERM`, `SIGHUP`, `SIGQUIT`) for graceful shutdown. On receiving a signal, all services are cleaned up (connection pools released, listeners closed) before exit.
