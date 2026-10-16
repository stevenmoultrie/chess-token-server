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
const { AccessToken, RoomServiceClient } = require('livekit-server-sdk');

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

// ---- Remove / re-invite (build 6) ----
// Ban list lives in the LiveKit room's metadata, so it is shared across
// Vercel serverless invocations and dies with the room when the class ends.
// An entry is { identity, name }: identity is the full LiveKit identity
// (e.g. "student-<device-id>"), name is the display name the instructor saw.
// Banning by BOTH catches a same-device rejoin (identity) and a same-name
// rejoin on a new device (name). The only bypass is a new device AND a new
// name, which the instructor sees as a new person and can remove again.

const REINVITE_TTL_MS = 60 * 60 * 1000; // 1 hour
const BAN_METADATA_KEY = 'banned';

function normalizeName(name) {
  return String(name || '').trim().toLowerCase();
}

// RoomServiceClient wants an https host; LIVEKIT_URL is wss://.
function httpHostFromWs(url) {
  return String(url || '').replace(/^wss:\/\//, 'https://').replace(/^ws:\/\//, 'http://');
}

function roomServiceClient(cfg) {
  return new RoomServiceClient(httpHostFromWs(cfg.livekitUrl), cfg.apiKey, cfg.apiSecret);
}

function parseBanList(metadata) {
  try {
    const parsed = JSON.parse(metadata || '');
    const list = Array.isArray(parsed && parsed[BAN_METADATA_KEY]) ? parsed[BAN_METADATA_KEY] : [];
    return list
      .filter((e) => e && typeof e.identity === 'string' && typeof e.name === 'string')
      .map((e) => ({ identity: e.identity, name: e.name }));
  } catch (ignore) {
    return [];
  }
}

// Fail open: if the room metadata can't be read, allow the join rather
// than breaking the whole class because of a ban-check error.
async function readBanList(cfg, room) {
  try {
    const svc = roomServiceClient(cfg);
    const rooms = await svc.listRooms([room]);
    const found = (rooms || []).find((r) => r && r.name === room);
    if (!found) return { banned: [], roomExists: false };
    return { banned: parseBanList(found.metadata || ''), roomExists: true };
  } catch (err) {
    console.error('readBanList failed:', err && err.message);
    return { banned: [], roomExists: true, readError: true };
  }
}

async function writeBanList(cfg, room, banned) {
  const svc = roomServiceClient(cfg);
  await svc.updateRoomMetadata(room, JSON.stringify({ [BAN_METADATA_KEY]: banned }));
}

function findBanEntry(banned, identity, name) {
  const norm = normalizeName(name);
  return (banned || []).find(
    (e) => e.identity === identity || (norm && normalizeName(e.name) === norm)
  );
}

function removeBanEntries(banned, identity, name) {
  const norm = normalizeName(name);
  return (banned || []).filter(
    (e) => e.identity !== identity && !(norm && normalizeName(e.name) === norm)
  );
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const padded = String(str).replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(padded, 'base64').toString('utf8');
}

// Self-validating re-invite code: HMAC-signed payload, no server storage.
// { name, room, exp }. The instructor sends the code to the removed person;
// the person enters it when joining. Tied to the display name so only that
// person can use it, and expires in 1 hour.
function makeReinviteCode(name, room, secret) {
  const payload = JSON.stringify({
    name: String(name),
    room: String(room),
    exp: Date.now() + REINVITE_TTL_MS,
  });
  const sig = crypto.createHmac('sha256', String(secret)).update(payload).digest();
  return b64url(payload) + '.' + b64url(sig);
}

function verifyReinviteCode(code, secret) {
  try {
    if (typeof code !== 'string' || !code.includes('.')) return null;
    const [payloadB64, sigB64] = code.split('.');
    const payload = b64urlDecode(payloadB64);
    const expected = crypto.createHmac('sha256', String(secret)).update(payload).digest();
    const provided = Buffer.from(String(sigB64).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) return null;
    const data = JSON.parse(payload);
    if (!data || typeof data.name !== 'string' || typeof data.room !== 'string') return null;
    if (typeof data.exp !== 'number' || Date.now() > data.exp) return null;
    return { name: data.name, room: data.room };
  } catch (ignore) {
    return null;
  }
}

// Shared instructor-auth + room/identity validation for the remove/reinvite
// endpoints. Returns { cfg, room, identity, name } or sends the error.
function validateInstructorRequest(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    res.status(405).json({ error: 'POST only' });
    return null;
  }
  const { cfg, missing } = readConfig();
  if (missing.length > 0) {
    console.error('token server misconfigured, missing env:', missing.join(','));
    res.status(500).json({ error: 'server misconfigured' });
    return null;
  }
  const body = req.body || {};
  const room = typeof body.room === 'string' ? body.room.trim() : '';
  const identity = typeof body.identity === 'string' ? body.identity.trim().slice(0, 128) : '';
  const name = typeof body.name === 'string' ? body.name.trim().slice(0, 64) : '';
  const passphrase = typeof body.passphrase === 'string' ? body.passphrase : '';
  if (!ROOM_RE.test(room) || !cfg.allowedRooms.includes(room)) {
    res.status(400).json({ error: 'invalid room' });
    return null;
  }
  if (!(passphrase.length > 0 && safeEqual(passphrase, cfg.instructorPassphrase))) {
    res.status(401).json({ error: 'unauthorized' });
    return null;
  }
  return { cfg, room, identity, name };
}

// POST /api/remove — instructor removes + bans a participant for this class.
// Body: { room, identity, name, passphrase }. identity is the full LiveKit
// identity (e.g. "student-<device-id>"); name is the display name.
// Returns { ok: true, reinviteCode } — the code lets the instructor let
// them back in if the removal was a mistake.
function createRemoveHandler() {
  return async (req, res) => {
    const v = validateInstructorRequest(req, res);
    if (!v) return;
    const { cfg, room, identity, name } = v;
    if (!identity || !identity.startsWith('student-')) {
      return res.status(400).json({ error: 'invalid identity' });
    }
    if (!name) {
      return res.status(400).json({ error: 'name required' });
    }
    try {
      const { banned, roomExists } = await readBanList(cfg, room);
      if (roomExists) {
        const next = findBanEntry(banned, identity, name)
          ? banned
          : banned.concat([{ identity, name }]);
        if (next.length !== banned.length) await writeBanList(cfg, room, next);
      }
      const reinviteCode = makeReinviteCode(name, room, cfg.apiSecret);
      return res.json({ ok: true, reinviteCode });
    } catch (err) {
      console.error('remove failed:', err && err.message);
      return res.status(500).json({ error: 'could not remove' });
    }
  };
}

// POST /api/reinvite — instructor generates a re-invite code for a removed
// person (e.g. when the removal was a mistake, or the first code was lost).
// Body: { room, name, passphrase }. Returns { code }.
function createReinviteHandler() {
  return async (req, res) => {
    const v = validateInstructorRequest(req, res);
    if (!v) return;
    const { cfg, room, name } = v;
    if (!name) {
      return res.status(400).json({ error: 'name required' });
    }
    const code = makeReinviteCode(name, room, cfg.apiSecret);
    return res.json({ code });
  };
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

    // Ban check (students only): a removed participant cannot rejoin this
    // class unless they present a valid re-invite code from the instructor.
    // Fail open — a ban-check error must never break normal joins.
    if (!isInstructor) {
      const fullIdentity = `student-${identity}`;
      const reinviteCode = typeof body.reinviteCode === 'string' ? body.reinviteCode.trim() : '';
      try {
        const { banned } = await readBanList(cfg, room);
        const entry = findBanEntry(banned, fullIdentity, displayName);
        if (entry) {
          const decoded = reinviteCode ? verifyReinviteCode(reinviteCode, cfg.apiSecret) : null;
          const codeOk =
            decoded && decoded.room === room && normalizeName(decoded.name) === normalizeName(displayName);
          if (!codeOk) {
            if (reinviteCode) return res.status(403).json({ error: 'bad code' });
            return res.status(403).json({ error: 'removed' });
          }
          // Valid code: lift the ban (by name + identity) and let them in.
          try {
            await writeBanList(cfg, room, removeBanEntries(banned, fullIdentity, displayName));
          } catch (err) {
            console.error('unban failed (proceeding anyway):', err && err.message);
          }
        }
      } catch (err) {
        console.error('ban check failed (allowing join):', err && err.message);
      }
    }

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

module.exports = {
  createTokenHandler,
  createRemoveHandler,
  createReinviteHandler,
  readConfig,
  safeEqual,
  normalizeName,
  makeReinviteCode,
  verifyReinviteCode,
  findBanEntry,
  removeBanEntries,
  parseBanList,
};
