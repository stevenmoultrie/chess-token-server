// Vercel serverless function: POST /api/token
// Shares the exact same minting logic as server.js via lib/token.js.
// Set env vars in the Vercel dashboard (Project > Settings > Environment
// Variables) — never in code.

const { createTokenHandler } = require('../lib/token');
const { rateLimit } = require('../lib/rate-limit');

const limiter = rateLimit({ windowMs: 60_000, max: 30 });
const handler = createTokenHandler();

module.exports = async (req, res) => {
  // CORS: allow only the classroom page + localhost.
  // Defaults cover production; ALLOWED_ORIGINS env var can extend/override.
  const allowed = (process.env.ALLOWED_ORIGINS ||
    'https://muse.ai/s/chess-classroom-gxq6v0xq3ldl0,http://localhost:3000,https://chess-classroom-gxq6v0xq3ldl0.cf.metaaiusercontent.com'
  )
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const origin = req.headers.origin;
  if (origin === 'null') {`
`res.setHeader('Access-Control-Allow-Origin', 'null');`
`} else if (origin && allowed.includes(origin)) {`
`res.setHeader('Access-Control-Allow-Origin', origin);`
`}
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();

  return limiter(req, res, () => handler(req, res));
};
