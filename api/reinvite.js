// Vercel serverless function: POST /api/reinvite
// Instructor generates a re-invite code for a removed person (e.g. the
// removal was a mistake, or the first code was lost). The code is HMAC-signed,
// tied to the display name, and expires in 1 hour — no server storage.
// Same CORS + rate-limit shape as api/token.js.

const { createReinviteHandler } = require('../lib/token');
const { rateLimit } = require('../lib/rate-limit');

const limiter = rateLimit({ windowMs: 60_000, max: 30 });
const handler = createReinviteHandler();

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
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();

  return limiter(req, res, () => handler(req, res));
};
