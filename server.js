// Long-running Node server for local dev and hosts like Railway / Render /
// Fly.io. For Vercel, the api/ functions are used instead (see README).
//
// Run:  cp .env.example .env   (then fill in real values)
//       npm install
//       npm start

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createTokenHandler, createBoardHandler } = require('./lib/token');
const { rateLimit } = require('./lib/rate-limit');

const app = express();
app.use(express.json({ limit: '10kb' }));

// Only the classroom page (and localhost for testing) may call /token
// from a browser. Everything else gets a CORS rejection.
// NOTE: browsers send only the bare origin — never a path — so entries
// here must be bare origins.
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000,http://localhost,https://muse.ai,https://chess-classroom-gxq6v0xq3ldl0.cf.metaaiusercontent.com,capacitor://localhost,ionic://localhost')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
app.use(
  cors({
    origin: allowedOrigins,
    methods: ['GET', 'POST'],
  })
);

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'chess-token-server', time: new Date().toISOString() });
});

// Best-effort abuse protection: 30 token requests/min per IP.
app.post('/token', rateLimit({ windowMs: 60_000, max: 30 }), createTokenHandler());

// Shared board (admin calendar, closed days, day messages, reviews).
app.get('/board', createBoardHandler());
app.post('/board', rateLimit({ windowMs: 60_000, max: 30 }), createBoardHandler());

const port = Number(process.env.PORT) || 3001;
app.listen(port, () => {
  console.log(`chess-token-server listening on :${port}`);
  console.log(`allowed origins: ${allowedOrigins.join(', ')}`);
});
