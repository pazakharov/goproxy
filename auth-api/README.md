# GoProxy Auth API Service (TypeScript)

External HTTP API authentication service for [goproxy](https://github.com/snail007/goproxy) with **per-user upstream proxy** support.

## Features

- **HTTP Basic Auth** via external API
- **Per-user upstream proxy** - each user can have their own upstream proxy
- **Dynamic user loading** from CSV file
- **TypeScript** for type safety

## Quick Start

### 1. Install Dependencies

```bash
cd auth-api
npm install
```

### 2. Build TypeScript

```bash
npm run build
```

### 3. Start the Auth Service

```bash
npm start
```

Or run in development mode:
```bash
npm run dev
```

Server runs on port 8080 by default.

### 4. Configure goproxy to use Auth API

```bash
proxy.exe http -p :33080 --auth-url "http://localhost:8080/auth"
```

### 5. Test with curl

```bash
# Valid credentials (user:pass) with upstream
curl -x http://user:pass@localhost:33080 http://ipinfo.io

# Invalid credentials
curl -x http://wrong:bad@localhost:33080 http://ipinfo.io
```

## Configuration

### Environment Variables
- `PORT` - Server port (default: 8080)

### Users File (users.csv)

Format: `username,password,upstream`

```csv
# users.csv - User credentials and upstream proxies
# Format: username,password,upstream

admin,admin123,http://admin:pass@proxy.example.com:8080
user,pass,http://some_test_subaccount:password@p2.mangoproxy.com:2333
test,test123,
john,secret,socks5://john:secret@socks.example.com:1080
```

**Fields:**
- `username` - login name
- `password` - password  
- `upstream` - (optional) upstream proxy URL for this user

**Response behavior:**
- If `upstream` is set → returns HTTP 200 with upstream URL in body
- If `upstream` is empty → returns HTTP 204 No Content

## API Specification

- **Method:** GET
- **Query Parameters:** `user`, `pass`, `ip`, `local_ip`, `target`
- **Auth Success with upstream:** HTTP 200 OK + upstream URL in body
- **Auth Success without upstream:** HTTP 204 No Content
- **Auth Failed:** HTTP 401 Unauthorized
