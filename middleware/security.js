const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const ALLOWED_METHODS = new Set(['GET', 'POST', 'HEAD', 'OPTIONS']);

const BLOCKED_EXTENSIONS_REGEX =
  /\.(php\d?|phtml|html?|htm|env|git|svn|htaccess|htpasswd|sql|db|sqlite|bak|backup|old|log|ini|conf|config|sh|bat|cmd|ps1|exe|dll|zip|tar|gz|rar)$/i;

const BLOCKED_SEGMENTS_REGEX =
  /(^|\/)(\.[^/]+|node_modules|config|middleware|routes|views|__tests__|\.git)(\/|$)/i;

function applySecurityMiddleware(app) {
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  // HTTP security headers
  app.use(
    helmet({
      contentSecurityPolicy: false, // Frontend assets/CSP hum page level par carefully set karenge
      crossOriginEmbedderPolicy: false,
      referrerPolicy: { policy: 'no-referrer' }
    })
  );

  // Block dangerous HTTP methods
  app.use((req, res, next) => {
    if (!ALLOWED_METHODS.has(req.method.toUpperCase())) {
      return res.status(405).send('Method Not Allowed');
    }
    next();
  });

  // Block null bytes, traversal attempts, dotfiles, internal folders & blocked extensions
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

  // General rate limiter
  app.use(
    rateLimit({
      windowMs: 60 * 1000,
      max: 120,
      standardHeaders: true,
      legacyHeaders: false,
      message: 'Too Many Requests'
    })
  );

  // JSON & URL-encoded body parsers with strict size cap
  app.use((req, res, next) => {
    express.json({ limit: '100kb' })(req, res, (err) => {
      if (err) {
        return res.status(400).send('Invalid Payload');
      }
      next();
    });
  });

  app.use((req, res, next) => {
    express.urlencoded({ extended: false, limit: '100kb' })(req, res, (err) => {
      if (err) {
        return res.status(400).send('Invalid Form Data');
      }
      next();
    });
  });
}

module.exports = { applySecurityMiddleware };