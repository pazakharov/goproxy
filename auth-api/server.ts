import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import * as url from 'url';

const PORT: number = parseInt(process.env.PORT || '8080', 10);
const USERS_FILE: string = path.join(__dirname, 'users.csv');
const TRAFFIC_FILE: string = path.join(__dirname, 'traffic.csv');

// ANSI color codes
const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
  white: '\x1b[97m',
};

type LogLevel = 'info' | 'success' | 'error' | 'warn' | 'request' | 'upstream';

function formatTime(): string {
  const now = new Date();
  return `${C.gray}${now.toLocaleTimeString('en-US', { hour12: false })}${C.reset}`;
}

function log(level: LogLevel, message: string, meta?: Record<string, string>) {
  const time = formatTime();
  const icons: Record<LogLevel, string> = {
    info: '●', success: '✓', error: '✗', warn: '⚠', request: '→', upstream: '⇡',
  };
  const colors: Record<LogLevel, string> = {
    info: C.cyan, success: C.green, error: C.red, warn: C.yellow, request: C.blue, upstream: C.magenta,
  };
  const icon = colors[level] + icons[level] + C.reset;
  let output = `${time} ${icon} ${message}`;
  if (meta) {
    output += '\n' + Object.entries(meta).map(([k, v]) => {
      if (k === 'pass') v = '*'.repeat(v.length || 4);
      return `   ${C.dim}${k}:${C.reset} ${C.cyan}${v}${C.reset}`;
    }).join('\n');
  }
  console.log(output);
}

function logStartup(message: string) {
  console.log(`${C.cyan}►${C.reset} ${message}`);
}

function logDivider() {
  console.log(C.dim + '─'.repeat(50) + C.reset);
}

interface UserRecord {
  username: string;
  password: string;
  upstream: string;
}

interface AuthRequestQuery {
  user?: string;
  pass?: string;
  ip?: string;
  local_ip?: string;
  target?: string;
}

interface TrafficRequestQuery {
  bytes?: string;
  client_addr?: string;
  id?: string;
  server_addr?: string;
  target_addr?: string;
  username?: string;
  out_local_addr?: string;
  out_remote_addr?: string;
  upstream?: string;
  sniff_domain?: string;
}

interface TrafficRecord {
  timestamp: string;
  bytes: number;
  clientAddr: string;
  id: string;
  serverAddr: string;
  targetAddr: string;
  username: string;
  outLocalAddr: string;
  outRemoteAddr: string;
  upstream: string;
  sniffDomain: string;
}

// Load users from CSV file
function loadUsers(): Map<string, UserRecord> {
  try {
    if (!fs.existsSync(USERS_FILE)) {
      log('error', `Users file not found: ${USERS_FILE}`);
      return new Map();
    }

    const content = fs.readFileSync(USERS_FILE, 'utf8');
    const users = new Map<string, UserRecord>();

    content.split('\n').forEach((line, index) => {
      line = line.trim();
      if (!line || line.startsWith('#')) return;

      const parts = line.split(',');
      if (parts.length >= 3) {
        const username = parts[0].trim();
        const password = parts[1].trim();
        const upstream = parts[2].trim();
        if (username && password) {
          users.set(username, { username, password, upstream });
        }
      } else if (parts.length === 2) {
        const username = parts[0].trim();
        const password = parts[1].trim();
        if (username && password) {
          users.set(username, { username, password, upstream: '' });
        }
      } else {
        log('warn', `Invalid line ${index + 1}: ${line}`);
      }
    });

    log('info', `Loaded ${C.bold}${users.size}${C.reset} users`, { file: USERS_FILE });
    return users;
  } catch (err) {
    log('error', 'Error loading users:', { error: (err as Error).message });
    return new Map();
  }
}

// Save traffic record to CSV file
function saveTraffic(record: TrafficRecord): void {
  try {
    // Create file with headers if it doesn't exist
    if (!fs.existsSync(TRAFFIC_FILE)) {
      const headers = 'timestamp,bytes,client_addr,id,server_addr,target_addr,username,out_local_addr,out_remote_addr,upstream,sniff_domain\n';
      fs.writeFileSync(TRAFFIC_FILE, headers, 'utf8');
      log('info', `Created traffic file: ${TRAFFIC_FILE}`);
    }

    // Append the traffic record
    const line = [
      record.timestamp,
      record.bytes,
      record.clientAddr,
      record.id,
      record.serverAddr,
      record.targetAddr,
      record.username,
      record.outLocalAddr,
      record.outRemoteAddr,
      record.upstream,
      record.sniffDomain,
    ].map(v => {
      // Escape values containing commas or quotes
      const s = String(v || '');
      if (s.includes(',') || s.includes('"') || s.includes('\n')) {
        return `"${s.replace(/"/g, '""')}"`;
      }
      return s;
    }).join(',') + '\n';

    fs.appendFileSync(TRAFFIC_FILE, line, 'utf8');
  } catch (err) {
    log('error', 'Error saving traffic:', { error: (err as Error).message });
  }
}
function authenticate(username: string, password: string, users: Map<string, UserRecord>): UserRecord | null {
  if (!username || !password) return null;
  const user = users.get(username);
  if (user && user.password === password) {
    return user;
  }
  return null;
}

const server = http.createServer((req: http.IncomingMessage, res: http.ServerResponse) => {
  const parsedUrl = url.parse(req.url || '', true);
  const pathname = parsedUrl.pathname || '';

  // Handle /traffic endpoint (GET requests from proxy traffic reporter)
  if (pathname.startsWith('/traffic')) {
    const query = parsedUrl.query as TrafficRequestQuery;

    // Create traffic record
    const record: TrafficRecord = {
      timestamp: new Date().toISOString(),
      bytes: parseInt(query.bytes || '0', 10),
      clientAddr: query.client_addr || '',
      id: query.id || '',
      serverAddr: query.server_addr || '',
      targetAddr: query.target_addr || '',
      username: query.username || '',
      outLocalAddr: query.out_local_addr || '',
      outRemoteAddr: query.out_remote_addr || '',
      upstream: query.upstream || '',
      sniffDomain: query.sniff_domain || '',
    };

    // Save to CSV
    saveTraffic(record);

    // Log traffic (brief format)
    log('info', `Traffic report`, {
      user: record.username || '(none)',
      bytes: String(record.bytes),
      target: record.targetAddr || '(none)',
    });

    // Return 204 No Content (as per spec)
    res.writeHead(204);
    res.end();
    return;
  }

  // Handle /auth endpoint
  if (req.method !== 'GET' || !pathname.startsWith('/auth')) {
    res.writeHead(404);
    res.end('Not Found');
    return;
  }

  const query = parsedUrl.query as AuthRequestQuery;

  // Log request with formatting
  logDivider();
  log('request', `Auth request`, {
    user: query.user || '(none)',
    ip: query.ip || '(unknown)',
    target: query.target || '(none)',
  });

  // Reload users on each request (to support dynamic updates)
  const users = loadUsers();

  // Extract credentials from query parameters
  const { user, pass } = query;

  // Validate credentials
  const userRecord = authenticate(user || '', pass || '', users);
  
  if (userRecord) {
    log('success', `Authentication ${C.bold}SUCCESS${C.reset}`, { 
      user: user!, 
      upstream: userRecord.upstream || '(none)' 
    });
    
    const headers: Record<string, string> = {};
    
    if (userRecord.upstream) {
      log('upstream', 'Returning upstream proxy', { 
        proxy: userRecord.upstream.replace(/:\/\/[^:]+:/, '://***:***@')
      });
      headers['upstream'] = userRecord.upstream;
    }
    
    res.writeHead(204, headers);
    res.end();
  } else {
    log('error', `Authentication ${C.bold}FAILED${C.reset}`, { 
      user: user || '(empty)',
      reason: !user ? 'missing username' : !pass ? 'missing password' : 'invalid credentials'
    });
    res.writeHead(401, { 'Content-Type': 'text/plain' });
    res.end('Unauthorized');
  }
});

server.listen(PORT, () => {
  logDivider();
  logStartup(`${C.bold}${C.green}Auth API Server${C.reset} running on ${C.cyan}http://localhost:${PORT}${C.reset}`);
  logStartup(`Auth endpoint: ${C.dim}http://localhost:${PORT}/auth${C.reset}`);
  logStartup(`Traffic endpoint: ${C.dim}http://localhost:${PORT}/traffic${C.reset}`);
  logStartup(`Users file: ${C.dim}${USERS_FILE}${C.reset}`);
  logStartup(`Traffic file: ${C.dim}${TRAFFIC_FILE}${C.reset}`);
  
  // Initial load to check file
  const users = loadUsers();
  logStartup(`${C.green}Ready${C.reset} to authenticate requests`);
  logDivider();
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
  log('info', '\nShutting down...');
  server.close(() => {
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  log('info', '\nShutting down...');
  server.close(() => {
    process.exit(0);
  });
});
