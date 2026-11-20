const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
require('dotenv').config();

const { testConnection } = require('./config/db');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const PUBLIC_DIR = path.resolve(__dirname, 'public');
const ASSETS_DIR = path.resolve(PUBLIC_DIR, 'assets');
const PAGES_DIR = path.resolve(PUBLIC_DIR, 'pages');
const IS_PROD = process.env.NODE_ENV === 'production';

const ALLOWED_METHODS = new Set(['GET', 'POST', 'HEAD']);
const BLOCKED_EXTENSIONS_REGEX =
  /\.(php\d?|phtml|html?|htm|env|git|svn|htaccess|htpasswd|sql|db|sqlite|bak|backup|old|log|ini|conf|config|sh|bat|cmd|ps1|exe|dll|zip|tar|gz|rar|map|yml|yaml|toml|swp)$/i;
const BLOCKED_SEGMENTS_REGEX =
  /(^|\/)(\.[^/]+|node_modules|config|middleware|routes|views|pages|__tests__|\.git|wp-admin|wp-login|phpmyadmin|adminer)(\/|$)/i;

// Known automated scanner / CLI scraper signatures (false-positive se bachne ke liye selective)
const SUSPICIOUS_UA_REGEX =
  /(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|ffuf|acunetix|nessus|wpscan|curl\/|python-requests|python-urllib|go-http-client)/i;

function getLanIp() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net && net.family === 'IPv4' && !net.internal) {
        return net.address;
      }
    }
  }
  return '127.0.0.1';
}

app.disable('x-powered-by');
app.set('trust proxy', 1);

// Request correlation ID (sirf internal error tracking ke liye, sensitive data nahi)
app.use((req, res, next) => {
  req.reqId = crypto.randomBytes(6).toString('hex');
  next();
});

// Strict HTTP headers + anti-clickjacking + anti-sniffing
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'blob:'],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"]
      }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
  })
);

// Sirf required HTTP methods allow karo
app.use((req, res, next) => {
  if (!ALLOWED_METHODS.has(req.method.toUpperCase())) {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// Automated scanner / tool User-Agent & missing Host header check
app.use((req, res, next) => {
  const host = req.headers.host;
  if (!host || typeof host !== 'string') {
    return res.status(400).send('Bad Request');
  }

  const ua = String(req.headers['user-agent'] || '');
  if (!ua.trim() || SUSPICIOUS_UA_REGEX.test(ua)) {
    return res.status(403).send('Forbidden');
  }

  next();
});

// Null bytes, traversal, dotfiles, internal folders aur blocked extensions block karo
app.use((req, res, next) => {
  const rawUrl = req.originalUrl || req.url || '';
  if (rawUrl.includes('\0') || rawUrl.toLowerCase().includes('%00')) {
    return res.status(400).send('Bad Request');
  }

  const reqPath = req.path || '/';
  if (
    reqPath.includes('..') ||
    BLOCKED_SEGMENTS_REGEX.test(reqPath) ||
    BLOCKED_EXTENSIONS_REGEX.test(reqPath)
  ) {
    return res.status(404).send('Not Found');
  }

  next();
});

// Fast static serving for public/assets (img & icon) with strong cache headers
app.use(
  '/assets',
  express.static(ASSETS_DIR, {
    maxAge: '30d',
    immutable: true,
    etag: true,
    lastModified: true,
    fallthrough: false
  })
);

// Dynamic/page responses ko browser/proxy cache mein store hone se roko (session/state leak kam karne ke liye)
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

// Global rate limiter
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too Many Requests'
  })
);

// Stricter rate limit on POST requests (auth / actions / bot bursts ke liye)
const postLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too Many Requests'
});

app.use((req, res, next) => {
  if (req.method === 'POST') {
    return postLimiter(req, res, next);
  }
  next();
});

// JSON & URL-encoded body parsers with strict content-type & size checks
app.use((req, res, next) => {
  if (req.method === 'POST' && req.is('application/json')) {
    return express.json({ limit: '50kb', strict: true })(req, res, (err) => {
      if (err) {
        return res.status(400).send('Invalid JSON Payload');
      }
      next();
    });
  }
  next();
});

app.use((req, res, next) => {
  if (req.method === 'POST' && req.is('application/x-www-form-urlencoded')) {
    return express.urlencoded({ extended: false, limit: '50kb' })(req, res, (err) => {
      if (err) {
        return res.status(400).send('Invalid Form Data');
      }
      next();
    });
  }
  next();
});

// Helper: path traversal se bachate hue sirf public/pages folder ke andar ki file serve karna
function renderCleanPage(res, fileName) {
  const safeName = path.basename(fileName);
  const filePath = path.resolve(PAGES_DIR, safeName);
  if (!filePath.startsWith(PAGES_DIR + path.sep)) {
    return res.status(403).send('Forbidden');
  }
  return res.sendFile(filePath, (err) => {
    if (err && !res.headersSent) {
      res.status(404).send('Not Found');
    }
  });
}

// Clean URLs mapped to public/pages/*
app.get('/', (req, res) => renderCleanPage(res, 'index.html'));
app.get('/auth', (req, res) => renderCleanPage(res, 'auth.html'));
app.get('/home', (req, res) => renderCleanPage(res, 'home.html'));
app.get('/profile', (req, res) => renderCleanPage(res, 'profile.html'));
app.get('/wallet', (req, res) => renderCleanPage(res, 'wallet.html'));

app.get('/health', async (req, res) => {
  try {
    const ok = await testConnection();
    res.status(ok ? 200 : 500).json({ status: ok ? 'ok' : 'db_error' });
  } catch (_) {
    res.status(500).json({ status: 'db_error' });
  }
});

// Unknown routes ke liye clean 404 (koi internal path/error leak nahi)
app.use((req, res) => {
  res.status(404).send('Not Found');
});

// Final fallback error handler (koi stack trace ya sensitive info leak nahi)
app.use((err, req, res, next) => {
  if (!res.headersSent) {
    res.status(IS_PROD ? 500 : 500).send('Server Error');
  }
});

const server = app.listen(PORT, HOST, () => {
  const lanIp = getLanIp();
  console.log(`Server running on http://localhost:${PORT} | Mobile/LAN: http://${lanIp}:${PORT}`);
});

server.requestTimeout = 15000;
server.headersTimeout = 16000;
server.keepAliveTimeout = 5000;