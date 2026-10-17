// Vercel serverless function: GET /api/board (public filtered view) and
// POST /api/board (board actions). Same CORS + rate-limit shape as
// api/remove.js, but GET is allowed too.

const { createBoardHandler } = require('../lib/token');
const { rateLimit } = require('../lib/rate-limit');

const limiter = rateLimit({ windowMs: 60_000, max: 30 });
const handler = createBoardHandler();

module.exports = async (req, res) => {
  const allowed = (process.env.ALLOWED_ORIGINS ||
    'https://muse.ai,http://localhost:3000,http://localhost,https://chess-classroom-gxq6v0xq3ldl0.cf.metaaiusercontent.com,capacitor://localhost,ionic://localhost'
  )
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const origin = req.headers.origin;
  if (origin && allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();

  // Vercel parses JSON bodies; if it arrives as a string, parse it here.
  if (typeof req.body === 'string' && req.body) {
    try {
      req.body = JSON.parse(req.body);
    } catch (ignore) {
      req.body = {};
    }
  }

  return limiter(req, res, () => handler(req, res));
};
