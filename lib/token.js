// Shared token-minting logic, used by both server.js (long-running Node)
// and api/token.js (Vercel serverless). All secrets come from environment
// variables — nothing is hardcoded here.
//
// Security model:
//  - The client's ROLE IS NEVER TRUSTED. Instructor privileges are granted
//    only when the request includes the correct INSTRUCTOR_PASSPHRASE, which
//    is compared on the server with a timing-safe comparison.
//  - Tokens are short-lived (4h TTL) and scoped to ONE room only.
//  - Room names are allow-listed via ALLOWED_ROOMS so callers cannot mint
//    tokens for arbitrary rooms on your LiveKit project.

const crypto = require('crypto');
const { AccessToken } = require('livekit-server-sdk');

// 4-hour TTL: covers a 2-hour class plus reconnect buffer. Tokens die on
// their own even if someone copies one.
const TOKEN_TTL = '4h';

// Room names: letters, numbers, dash, underscore, 1–64 chars.
const ROOM_RE = /^[A-Za-z0-9_-]{1,64}$/;

function readConfig() {
  const cfg = {
    livekitUrl: process.env.LIVEKIT_URL,
    apiKey: process.env.LIVEKIT_API_KEY,
    apiSecret: process.env.LIVEKIT_API_SECRET,
    instructorPassphrase: process.env.INSTRUCTOR_PASSPHRASE,
    allowedRooms: (process.env.ALLOWED_ROOMS || 'chess-classroom')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  };
  const missing = Object.entries({
    LIVEKIT_URL: cfg.livekitUrl,
    LIVEKIT_API_KEY: cfg.apiKey,
    LIVEKIT_API_SECRET: cfg.apiSecret,
    INSTRUCTOR_PASSPHRASE: cfg.instructorPassphrase,
  })
    .filter(([, v]) => !v)
    .map(([k]) => k);
  return { cfg, missing };
}

// Timing-safe string comparison so a wrong passphrase can't be probed
// character-by-character via response timing.
function safeEqual(a, b) {
  const ba = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ba.length !== bb.length) {
    crypto.timingSafeEqual(ba, ba); // dummy op keeps timing flat
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

// Express-style (req, res) handler. Returns JSON:
//   { token, url, room, identity, role: 'instructor' | 'student' }
function createTokenHandler() {
  return async (req, res) => {
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return res.status(405).json({ error: 'POST only' });
    }

    const { cfg, missing } = readConfig();
    if (missing.length > 0) {
      // Deliberately vague: never tell the client WHICH vars are missing.
      console.error('token server misconfigured, missing env:', missing.join(','));
      return res.status(500).json({ error: 'server misconfigured' });
    }

    const body = req.body || {};
    const room = typeof body.room === 'string' ? body.room.trim() : '';
    const identity = typeof body.identity === 'string' ? body.identity.trim().slice(0, 64) : '';
    const displayName =
      typeof body.name === 'string' && body.name.trim()
        ? body.name.trim().slice(0, 64)
        : identity;
    const passphrase = typeof body.passphrase === 'string' ? body.passphrase : '';

    // Validate room name shape AND allow-list.
    if (!ROOM_RE.test(room) || !cfg.allowedRooms.includes(room)) {
      return res.status(400).json({ error: 'invalid room' });
    }
    if (!identity) {
      return res.status(400).json({ error: 'identity required' });
    }

    // Role is derived here, server-side, from the passphrase. A client
    // cannot grant itself instructor by sending role: 'instructor'.
    const isInstructor =
      passphrase.length > 0 && safeEqual(passphrase, cfg.instructorPassphrase);

    try {
      const at = new AccessToken(cfg.apiKey, cfg.apiSecret, {
        // Prefix keeps instructor/student identities distinct inside LiveKit,
        // so two people with the same display name can't collide.
        identity: `${isInstructor ? 'instructor' : 'student'}-${identity}`,
        name: displayName,
        ttl: TOKEN_TTL,
      });
      at.addGrant({
        roomJoin: true,
        room, // scoped to this room ONLY
        canPublish: true, // publish mic/camera
        canSubscribe: true, // receive everyone else
        // roomAdmin lets the instructor mute/remove participants via the API.
        // Students never get this.
        ...(isInstructor ? { roomAdmin: true } : {}),
      });
      const token = await at.toJwt();
      return res.json({
        token,
        url: cfg.livekitUrl,
        room,
        identity: `${isInstructor ? 'instructor' : 'student'}-${identity}`,
        role: isInstructor ? 'instructor' : 'student',
      });
    } catch (err) {
      console.error('token mint failed:', err && err.message);
      return res.status(500).json({ error: 'could not issue token' });
    }
  };
}

module.exports = { createTokenHandler, readConfig, safeEqual };
