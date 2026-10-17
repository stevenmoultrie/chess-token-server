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

// ---- Shared board (build 10): admin calendar, closed days, bookings,
// day messages, shared reviews ----
// The board lives in the metadata of a dedicated room that nobody ever
// JOINS ("chess-classroom-board"). A room created via the API that no
// participant ever joins stays in storage; the classroom room, by
// contrast, auto-closes ~2 minutes after the last participant leaves,
// which would wipe the board. So the board gets its own never-joined
// room. The board is a convenience layer — booking emails to the
// instructor remain the record — so a lost board degrades gracefully.
// Metadata schema: { board: { closedDays: [YYYY-MM-DD],
//   bookings: [{ id, name, email, phone, className, date, session, createdAt }],
//   dayMessages: [{ id, date, message, createdAt }],
//   reviews: [{ id, fromName, fromEmail, className, date, stars, text, createdAt }],
//   announcements: [{ id, title, body, published, createdAt }],
//   players: [{ email, name, studentId, rating, wins, losses, draws, lastMatchAt, lastOpponent, plan }],
//   ladder: [email, ...] (ordered, top first),
//   challenges: [{ id, fromEmail, fromName, toEmail, toName, format, clock, clockMinutes, status, createdAt, expiresAt }],
//   matches: [{ id, challengeId, playerA, playerB, format, clock, clockMinutes, status, games, currentGame, scoreA, scoreB, winner, createdAt, completedAt }],
//   reactions: [{ id, fromEmail, fromName, toEmail, text, createdAt }],
//   blocks: [{ byEmail, blockedEmail, createdAt }],
//   reports: [{ id, fromEmail, aboutEmail, reason, createdAt, status }],
//   creditGrants: [{ id, email, amount, remaining, expiresAt, reason, createdAt }],
//   creditLog: [{ id, email, amount, reason, actor, createdAt }] } }
const BOARD_ROOM = 'chess-classroom-board';
const BOARD_METADATA_KEY = 'board';
const BOARD_MAX_ENTRIES = 500; // cap each list so metadata stays small
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
// Challenge formats: best of 3, best of 5, first to 10 game wins.
const CHALLENGE_FORMATS = ['bo3', 'bo5', 'first10'];
// Preset reactions only — no free-text kid-to-kid chat (ChessKid standard).
const ALLOWED_REACTIONS = ['Good game!', 'Good luck!', 'Rematch?', 'Well played!', 'Nice move!'];
const REPORT_REASONS = ['Mean', 'Weird', 'Spam', 'Other'];
const LADDER_CHALLENGE_RANGE = 3; // challenge up to 3 spots above
const CHALLENGE_TTL_MS = 24 * 60 * 60 * 1000;
const LADDER_INACTIVITY_MS = 90 * 24 * 60 * 60 * 1000;
const RATING_START = 200;
const RATING_FLOOR = 100;
const RATING_DELTA = 4;

function emptyBoard() {
  return { closedDays: [], bookings: [], dayMessages: [], reviews: [], announcements: [], players: [], ladder: [], challenges: [], matches: [], reactions: [], blocks: [], reports: [], creditGrants: [], creditLog: [] };
}
function cleanBoard(raw) {
  const b = raw && typeof raw === 'object' ? raw : {};
  const out = emptyBoard();
  if (Array.isArray(b.closedDays)) {
    out.closedDays = [...new Set(b.closedDays.filter((d) => typeof d === 'string' && DATE_RE.test(d)))];
  }
  const str = (v) => (typeof v === 'string' ? v.slice(0, 500) : '');
  if (Array.isArray(b.bookings)) {
    out.bookings = b.bookings
      .filter((e) => e && typeof e === 'object' && DATE_RE.test(e.date || '') && str(e.email) && str(e.name))
      .map((e) => ({ id: str(e.id), name: str(e.name), email: str(e.email), phone: str(e.phone), className: str(e.className), date: e.date, session: str(e.session), createdAt: str(e.createdAt) }));
  }
  if (Array.isArray(b.dayMessages)) {
    out.dayMessages = b.dayMessages
      .filter((e) => e && typeof e === 'object' && DATE_RE.test(e.date || '') && str(e.message))
      .map((e) => ({ id: str(e.id), date: e.date, message: str(e.message), createdAt: str(e.createdAt) }));
  }
  if (Array.isArray(b.reviews)) {
    out.reviews = b.reviews
      .filter((e) => e && typeof e === 'object' && Number(e.stars) >= 1 && Number(e.stars) <= 5 && str(e.text))
      .map((e) => ({ id: str(e.id), fromName: str(e.fromName), fromEmail: str(e.fromEmail), className: str(e.className), date: str(e.date), stars: Number(e.stars), text: str(e.text), createdAt: str(e.createdAt) }));
  }
  if (Array.isArray(b.announcements)) {
    out.announcements = b.announcements
      .filter((e) => e && typeof e === 'object' && str(e.body))
      .map((e) => ({ id: str(e.id), title: str(e.title), body: str(e.body), published: e.published === true, createdAt: str(e.createdAt) }));
  }
  const emailStr = (v) => (typeof v === 'string' ? v.trim().toLowerCase().slice(0, 200) : '');
  if (Array.isArray(b.players)) {
    out.players = b.players
      .filter((e) => e && typeof e === 'object' && emailStr(e.email))
      .map((e) => ({
        email: emailStr(e.email), name: str(e.name), studentId: str(e.studentId),
        rating: Number.isFinite(Number(e.rating)) ? Math.max(RATING_FLOOR, Number(e.rating)) : RATING_START,
        wins: Math.max(0, Number(e.wins) || 0), losses: Math.max(0, Number(e.losses) || 0), draws: Math.max(0, Number(e.draws) || 0),
        lastMatchAt: str(e.lastMatchAt), lastOpponent: emailStr(e.lastOpponent),
        plan: e.plan === 'monthly' ? 'monthly' : 'pay-per-class',
      }));
  }
  if (Array.isArray(b.ladder)) {
    const known = new Set(out.players.map((p) => p.email));
    out.ladder = [...new Set(b.ladder.filter((e) => typeof e === 'string' && known.has(e.toLowerCase())))].map((e) => e.toLowerCase());
  }
  if (Array.isArray(b.challenges)) {
    out.challenges = b.challenges
      .filter((e) => e && typeof e === 'object' && emailStr(e.fromEmail) && emailStr(e.toEmail) && CHALLENGE_FORMATS.includes(e.format))
      .map((e) => ({ id: str(e.id), fromEmail: emailStr(e.fromEmail), fromName: str(e.fromName), toEmail: emailStr(e.toEmail), toName: str(e.toName), format: e.format, clock: e.clock === true, clockMinutes: Math.max(0, Number(e.clockMinutes) || 0), status: ['pending', 'accepted', 'declined', 'expired', 'completed'].includes(e.status) ? e.status : 'pending', createdAt: str(e.createdAt), expiresAt: str(e.expiresAt) }));
  }
  if (Array.isArray(b.matches)) {
    out.matches = b.matches
      .filter((e) => e && typeof e === 'object' && emailStr(e.playerA) && emailStr(e.playerB))
      .map((e) => ({
        id: str(e.id), challengeId: str(e.challengeId), playerA: emailStr(e.playerA), playerB: emailStr(e.playerB),
        format: CHALLENGE_FORMATS.includes(e.format) ? e.format : 'bo3', clock: e.clock === true, clockMinutes: Math.max(0, Number(e.clockMinutes) || 0),
        status: e.status === 'complete' ? 'complete' : 'active',
        games: (Array.isArray(e.games) ? e.games : []).slice(0, 40).map((g) => ({ n: Number(g.n) || 0, white: emailStr(g.white), black: emailStr(g.black), moves: (Array.isArray(g.moves) ? g.moves : []).filter((m) => m && typeof m === 'object').slice(0, 300).map((m) => ({ from: str(m.from), to: str(m.to), promotion: str(m.promotion), by: emailStr(m.by) })), result: ['white', 'black', 'draw'].includes(g.result) ? g.result : null, resultReason: str(g.resultReason) })),
        currentGame: Math.max(1, Number(e.currentGame) || 1), scoreA: Math.max(0, Number(e.scoreA) || 0), scoreB: Math.max(0, Number(e.scoreB) || 0),
        winner: emailStr(e.winner), createdAt: str(e.createdAt), completedAt: str(e.completedAt), drawOfferBy: emailStr(e.drawOfferBy),
      }));
  }
  if (Array.isArray(b.reactions)) {
    out.reactions = b.reactions
      .filter((e) => e && typeof e === 'object' && emailStr(e.fromEmail) && emailStr(e.toEmail) && ALLOWED_REACTIONS.includes(e.text))
      .map((e) => ({ id: str(e.id), fromEmail: emailStr(e.fromEmail), fromName: str(e.fromName), toEmail: emailStr(e.toEmail), text: e.text, createdAt: str(e.createdAt) }));
  }
  if (Array.isArray(b.blocks)) {
    out.blocks = b.blocks
      .filter((e) => e && typeof e === 'object' && emailStr(e.byEmail) && emailStr(e.blockedEmail))
      .map((e) => ({ byEmail: emailStr(e.byEmail), blockedEmail: emailStr(e.blockedEmail), createdAt: str(e.createdAt) }));
  }
  if (Array.isArray(b.reports)) {
    out.reports = b.reports
      .filter((e) => e && typeof e === 'object' && emailStr(e.fromEmail) && emailStr(e.aboutEmail))
      .map((e) => ({ id: str(e.id), fromEmail: emailStr(e.fromEmail), aboutEmail: emailStr(e.aboutEmail), reason: REPORT_REASONS.includes(e.reason) ? e.reason : 'Other', createdAt: str(e.createdAt), status: e.status === 'resolved' ? 'resolved' : 'open' }));
  }
  if (Array.isArray(b.creditGrants)) {
    out.creditGrants = b.creditGrants
      .filter((e) => e && typeof e === 'object' && emailStr(e.email) && Number(e.amount) > 0)
      .map((e) => ({ id: str(e.id), email: emailStr(e.email), amount: Number(e.amount), remaining: Math.max(0, Math.min(Number(e.amount), Number(e.remaining) || 0)), expiresAt: str(e.expiresAt), reason: str(e.reason), createdAt: str(e.createdAt) }));
  }
  if (Array.isArray(b.creditLog)) {
    out.creditLog = b.creditLog
      .filter((e) => e && typeof e === 'object' && emailStr(e.email) && Number(e.amount) !== 0)
      .map((e) => ({ id: str(e.id), email: emailStr(e.email), amount: Number(e.amount), reason: str(e.reason), actor: str(e.actor), createdAt: str(e.createdAt) }));
  }
  return out;
}
function parseBoard(metadata) {
  try {
    const parsed = JSON.parse(metadata || '');
    return cleanBoard(parsed && parsed[BOARD_METADATA_KEY]);
  } catch (ignore) {
    return emptyBoard();
  }
}
async function readBoard(cfg) {
  try {
    const svc = roomServiceClient(cfg);
    const rooms = await svc.listRooms([BOARD_ROOM]);
    const found = (rooms || []).find((r) => r && r.name === BOARD_ROOM);
    if (!found) return { board: emptyBoard(), roomExists: false };
    return { board: parseBoard(found.metadata || ''), roomExists: true };
  } catch (err) {
    console.error('readBoard failed:', err && err.message);
    return { board: emptyBoard(), roomExists: true, readError: true };
  }
}
async function writeBoard(cfg, board) {
  const svc = roomServiceClient(cfg);
  // CreateRoom is idempotent: ensures the never-joined board room exists.
  await svc.createRoom({ name: BOARD_ROOM });
  await svc.updateRoomMetadata(BOARD_ROOM, JSON.stringify({ [BOARD_METADATA_KEY]: board }));
}
function isSunday(dateStr) {
  const [y, m, d] = dateStr.split('-').map(Number);
  return new Date(y, m - 1, d).getDay() === 0;
}
function isPastDate(dateStr) {
  // Lenient by one day: the server runs on UTC, the school on Eastern,
  // so a same-day booking made late at night must not be rejected.
  const [y, m, d] = dateStr.split('-').map(Number);
  const day = new Date(Date.UTC(y, m - 1, d));
  const now = new Date();
  const cutoff = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - 1));
  return day < cutoff;
}

// ---- Challenges / ladder / credits helpers ----
function newBoardId() { return Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8); }
function findPlayer(board, email) { return board.players.find((p) => p.email === email); }
function ensurePlayer(board, email, name, studentId) {
  let p = findPlayer(board, email);
  if (!p) {
    p = { email, name: name || '', studentId: studentId || '', rating: RATING_START, wins: 0, losses: 0, draws: 0, lastMatchAt: '', lastOpponent: '', plan: 'pay-per-class' };
    board.players.push(p);
    if (!board.ladder.includes(email)) board.ladder.push(email);
  } else {
    if (name) p.name = name;
    if (studentId) p.studentId = studentId;
    if (!board.ladder.includes(email)) board.ladder.push(email);
  }
  return p;
}
function isBlockedPair(board, a, b) {
  return board.blocks.some((x) => (x.byEmail === a && x.blockedEmail === b) || (x.byEmail === b && x.blockedEmail === a));
}
// Ladder without players inactive 90+ days (new players with no matches stay).
function activeLadder(board) {
  const now = Date.now();
  return board.ladder.filter((email) => {
    const p = findPlayer(board, email);
    if (!p) return false;
    return !p.lastMatchAt || now - new Date(p.lastMatchAt).getTime() < LADDER_INACTIVITY_MS;
  });
}
// Credits: balance = remaining on unexpired grants. FIFO deduct, earliest expiry first.
function creditsFor(board, email) {
  const now = Date.now();
  const grants = board.creditGrants.filter((g) => g.email === email && g.remaining > 0 && (!g.expiresAt || new Date(g.expiresAt).getTime() > now));
  return {
    balance: grants.reduce((s, g) => s + g.remaining, 0),
    expiring: grants.filter((g) => g.expiresAt).sort((a, b) => new Date(a.expiresAt) - new Date(b.expiresAt)).map((g) => ({ amount: g.remaining, expiresAt: g.expiresAt })),
  };
}
function grantCredits(board, email, amount, reason, actor, expiresAt) {
  board.creditGrants.push({ id: newBoardId(), email, amount, remaining: amount, expiresAt: expiresAt || '', reason, createdAt: new Date().toISOString() });
  if (board.creditGrants.length > 1000) board.creditGrants = board.creditGrants.slice(-1000);
  board.creditLog.push({ id: newBoardId(), email, amount, reason, actor, createdAt: new Date().toISOString() });
  if (board.creditLog.length > 1000) board.creditLog = board.creditLog.slice(-1000);
}
function deductCredits(board, email, amount, reason, actor) {
  const now = Date.now();
  const grants = board.creditGrants
    .filter((g) => g.email === email && g.remaining > 0 && (!g.expiresAt || new Date(g.expiresAt).getTime() > now))
    .sort((a, b) => (a.expiresAt ? new Date(a.expiresAt).getTime() : Infinity) - (b.expiresAt ? new Date(b.expiresAt).getTime() : Infinity));
  const available = grants.reduce((s, g) => s + g.remaining, 0);
  if (available < amount) return { ok: false, available };
  let left = amount;
  for (const g of grants) {
    const take = Math.min(g.remaining, left);
    g.remaining -= take;
    left -= take;
    if (!left) break;
  }
  board.creditLog.push({ id: newBoardId(), email, amount: -amount, reason, actor, createdAt: new Date().toISOString() });
  if (board.creditLog.length > 1000) board.creditLog = board.creditLog.slice(-1000);
  return { ok: true, available: available - amount };
}
function winsNeeded(format) { return format === 'bo3' ? 2 : format === 'bo5' ? 3 : 10; }
function maxGames(format) { return format === 'bo3' ? 5 : format === 'bo5' ? 9 : 29; }
// Apply one finished game's result to ratings, records, scores, ladder,
// and series progression. Shared by reportGameResult and respondDraw.
function applyGameResult(board, match, game, result, resultReason) {
  game.result = result;
  game.resultReason = resultReason || '';
  match.drawOfferBy = '';
  const nowIso = new Date().toISOString();
  const pA = ensurePlayer(board, match.playerA, '', '');
  const pB = ensurePlayer(board, match.playerB, '', '');
  if (result === 'draw') {
    pA.draws++; pB.draws++;
  } else {
    const winnerEmail = result === 'white' ? game.white : game.black;
    const winner = winnerEmail === match.playerA ? pA : pB;
    const loser = winnerEmail === match.playerA ? pB : pA;
    winner.wins++;
    winner.rating += RATING_DELTA;
    loser.losses++;
    loser.rating = Math.max(RATING_FLOOR, loser.rating - RATING_DELTA);
    if (winnerEmail === match.playerA) match.scoreA++; else match.scoreB++;
  }
  pA.lastMatchAt = nowIso; pA.lastOpponent = match.playerB;
  pB.lastMatchAt = nowIso; pB.lastOpponent = match.playerA;
  const needed = winsNeeded(match.format);
  if (match.scoreA >= needed || match.scoreB >= needed) {
    match.status = 'complete';
    match.winner = match.scoreA > match.scoreB ? match.playerA : match.playerB;
    match.completedAt = nowIso;
    const ch = board.challenges.find((c) => c.id === match.challengeId);
    if (ch) ch.status = 'completed';
    applyLadderResult(board, match.playerA, match.playerB, match.winner === match.playerA ? 'challenger' : 'defender');
  } else if (match.games.length >= maxGames(match.format)) {
    match.status = 'complete';
    match.winner = '';
    match.completedAt = nowIso;
    const ch = board.challenges.find((c) => c.id === match.challengeId);
    if (ch) ch.status = 'completed';
    applyLadderResult(board, match.playerA, match.playerB, 'draw');
  } else {
    const n = match.games.length + 1;
    match.games.push({ n, white: n % 2 === 1 ? match.playerA : match.playerB, black: n % 2 === 1 ? match.playerB : match.playerA, moves: [], result: null, resultReason: '' });
    match.currentGame = n;
  }
}
// Ladder reorder when a match series ends. Challenger = playerA, defender = playerB.
// Challenger win: challenger takes defender's spot. Defender win: no change.
// Draw: challenger moves to just below defender.
function applyLadderResult(board, challengerEmail, defenderEmail, outcome) {
  const ci = board.ladder.indexOf(challengerEmail);
  const di = board.ladder.indexOf(defenderEmail);
  if (ci === -1 || di === -1 || ci < di) return;
  const [moved] = board.ladder.splice(ci, 1);
  if (outcome === 'challenger') board.ladder.splice(di, 0, moved);
  else if (outcome === 'draw') board.ladder.splice(di + 1, 0, moved);
  else board.ladder.splice(ci, 0, moved); // defender win: put it back
}

// GET /api/board?email=... — public filtered view: closed days, the day
// messages for that email's booked days, and shared reviews. Bookings,
// phones, and other students' emails are never returned here.
// POST /api/board (JSON) — actions:
//   { action: "read", passphrase } → full board (instructor only).
//   { action: "closeDay"|"openDay", date, passphrase } → instructor.
//   { action: "addDayMessage", date, message, passphrase } → instructor.
//   { action: "addBooking", booking } → public; rejects Sundays,
//     past dates, and closed days.
//   { action: "addReview", review } → public.
//   { action: "addAnnouncement", title, body, published, passphrase } → instructor.
//   { action: "setAnnouncementPublished", id, published, passphrase } → instructor.
//   { action: "deleteAnnouncement", id, passphrase } → instructor.
//   { action: "upsertPlayer", player } → public; creates/updates ladder player.
//   { action: "sendChallenge", challenge } → public; ladder-gated (up to 3 spots up).
//   { action: "respondChallenge", id, email, accept } → public; accept starts a match.
//   { action: "postMove", matchId, email, move } → public; turn order + shape checked.
//   { action: "reportGameResult", matchId, email, result } → public; applies
//     ratings (+4/-4), records, ladder reorder, series progression.
//   { action: "offerDraw"|"respondDraw", matchId, email, accept } → public.
//   { action: "sendReaction", reaction } → public; preset reactions only.
//   { action: "blockPlayer"|"unblockPlayer", byEmail, blockedEmail } → public.
//   { action: "sendReport", report } → public.
//   { action: "resolveReport", id, passphrase } → instructor.
//   { action: "addCredits"|"deductCredits", email, amount, reason, passphrase } → instructor.
//   { action: "setPlan", email, plan, passphrase } → instructor.
function createBoardHandler() {
  return async (req, res) => {
    const { cfg, missing } = readConfig();
    if (missing.length > 0) {
      console.error('token server misconfigured, missing env:', missing.join(','));
      return res.status(500).json({ error: 'server misconfigured' });
    }
    if (req.method === 'GET') {
      const email = typeof (req.query || {}).email === 'string' ? req.query.email.trim().toLowerCase() : '';
      const { board } = await readBoard(cfg);
      const bookedDates = new Set(
        board.bookings.filter((b) => String(b.email || '').toLowerCase() === email).map((b) => b.date)
      );
      const now = Date.now();
      const me = email ? findPlayer(board, email) || null : null;
      const ladderEmails = activeLadder(board);
      const ladder = ladderEmails.map((e) => findPlayer(board, e)).filter(Boolean).map((p) => ({ email: p.email, name: p.name, studentId: p.studentId, rating: p.rating, wins: p.wins, losses: p.losses, draws: p.draws, lastMatchAt: p.lastMatchAt, plan: p.plan }));
      const myBlocks = email ? board.blocks.filter((b) => b.byEmail === email).map((b) => b.blockedEmail) : [];
      const blockedSet = new Set(myBlocks);
      const challenges = email ? board.challenges.filter((c) => (c.fromEmail === email || c.toEmail === email) && !isBlockedPair(board, c.fromEmail, c.toEmail)).map((c) => (c.status === 'pending' && c.expiresAt && new Date(c.expiresAt).getTime() < now ? { ...c, status: 'expired' } : c)) : [];
      const matches = email ? board.matches.filter((m) => m.playerA === email || m.playerB === email).slice(-50) : [];
      const reactions = email ? board.reactions.filter((r) => r.toEmail === email && !blockedSet.has(r.fromEmail)).slice(-50) : [];
      return res.json({
        closedDays: board.closedDays,
        dayMessages: email ? board.dayMessages.filter((m) => bookedDates.has(m.date)) : [],
        reviews: board.reviews,
        announcements: board.announcements.filter((a) => a.published),
        me,
        ladder,
        ladderPosition: email ? ladderEmails.indexOf(email) : -1,
        challenges,
        matches,
        reactions,
        blockedEmails: myBlocks,
        credits: email ? creditsFor(board, email) : { balance: 0, expiring: [] },
      });
    }
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'GET, POST');
      return res.status(405).json({ error: 'GET or POST only' });
    }
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const action = typeof body.action === 'string' ? body.action : '';
    const passphrase = typeof body.passphrase === 'string' ? body.passphrase : '';
    const isInstructor = passphrase.length > 0 && safeEqual(passphrase, cfg.instructorPassphrase);
    const needInstructor = ['read', 'closeDay', 'openDay', 'addDayMessage', 'addAnnouncement', 'setAnnouncementPublished', 'deleteAnnouncement', 'resolveReport', 'addCredits', 'deductCredits', 'setPlan'].includes(action);
    if (needInstructor && !isInstructor) return res.status(401).json({ error: 'unauthorized' });
    try {
      const { board } = await readBoard(cfg);
      if (action === 'read') return res.json({ board });
      if (action === 'closeDay' || action === 'openDay') {
        const date = typeof body.date === 'string' ? body.date : '';
        if (!DATE_RE.test(date)) return res.status(400).json({ error: 'invalid date' });
        board.closedDays = action === 'closeDay'
          ? [...new Set([...board.closedDays, date])]
          : board.closedDays.filter((d) => d !== date);
        await writeBoard(cfg, board);
        return res.json({ board });
      }
      if (action === 'addDayMessage') {
        const date = typeof body.date === 'string' ? body.date : '';
        const message = typeof body.message === 'string' ? body.message.trim().slice(0, 2000) : '';
        if (!DATE_RE.test(date) || !message) return res.status(400).json({ error: 'date and message required' });
        board.dayMessages.push({ id: Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8), date, message, createdAt: new Date().toISOString() });
        if (board.dayMessages.length > BOARD_MAX_ENTRIES) board.dayMessages = board.dayMessages.slice(-BOARD_MAX_ENTRIES);
        await writeBoard(cfg, board);
        return res.json({ board });
      }
      if (action === 'addBooking') {
        const bk = body.booking && typeof body.booking === 'object' ? body.booking : {};
        const booking = {
          id: (typeof bk.id === 'string' ? bk.id : '').slice(0, 64),
          name: (typeof bk.name === 'string' ? bk.name : '').trim().slice(0, 100),
          email: (typeof bk.email === 'string' ? bk.email : '').trim().toLowerCase().slice(0, 200),
          phone: (typeof bk.phone === 'string' ? bk.phone : '').trim().slice(0, 40),
          className: (typeof bk.className === 'string' ? bk.className : '').trim().slice(0, 100),
          date: typeof bk.date === 'string' ? bk.date : '',
          session: (typeof bk.session === 'string' ? bk.session : '').trim().slice(0, 100),
          createdAt: new Date().toISOString(),
        };
        if (!booking.name || !booking.email || !booking.className || !DATE_RE.test(booking.date)) {
          return res.status(400).json({ error: 'name, email, class, and date required' });
        }
        if (isPastDate(booking.date)) return res.status(409).json({ error: 'past date' });
        if (isSunday(booking.date)) return res.status(409).json({ error: 'no Sunday classes' });
        if (board.closedDays.includes(booking.date)) return res.status(409).json({ error: 'day closed' });
        // Dedup: same student + class + date + session within 5 minutes
        // is a double-tap, not a second booking.
        const dup = board.bookings.find((e) => e.email === booking.email && e.className === booking.className && e.date === booking.date && e.session === booking.session && Date.now() - new Date(e.createdAt).getTime() < 5 * 60 * 1000);
        if (!dup) {
          if (!booking.id) booking.id = Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
          board.bookings.push(booking);
          if (board.bookings.length > BOARD_MAX_ENTRIES) board.bookings = board.bookings.slice(-BOARD_MAX_ENTRIES);
          await writeBoard(cfg, board);
        }
        return res.json({ ok: true });
      }
      if (action === 'addReview') {
        const rv = body.review && typeof body.review === 'object' ? body.review : {};
        const review = {
          id: (typeof rv.id === 'string' ? rv.id : '').slice(0, 64),
          fromName: (typeof rv.fromName === 'string' ? rv.fromName : '').trim().slice(0, 100),
          fromEmail: (typeof rv.fromEmail === 'string' ? rv.fromEmail : '').trim().toLowerCase().slice(0, 200),
          className: (typeof rv.className === 'string' ? rv.className : '').trim().slice(0, 100),
          date: (typeof rv.date === 'string' ? rv.date : '').slice(0, 20),
          stars: Number(rv.stars),
          text: (typeof rv.text === 'string' ? rv.text : '').trim().slice(0, 2000),
          createdAt: new Date().toISOString(),
        };
        if (!review.id || !review.fromName || !(review.stars >= 1 && review.stars <= 5) || !review.text) {
          return res.status(400).json({ error: 'id, name, stars, and text required' });
        }
        if (!board.reviews.some((r) => r.id === review.id)) {
          board.reviews.push(review);
          if (board.reviews.length > BOARD_MAX_ENTRIES) board.reviews = board.reviews.slice(-BOARD_MAX_ENTRIES);
          await writeBoard(cfg, board);
        }
        return res.json({ ok: true });
      }
      if (action === 'addAnnouncement') {
        const title = typeof body.title === 'string' ? body.title.trim().slice(0, 200) : '';
        const annBody = typeof body.body === 'string' ? body.body.trim().slice(0, 2000) : '';
        if (!annBody) return res.status(400).json({ error: 'body required' });
        board.announcements.push({ id: Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8), title, body: annBody, published: body.published === true, createdAt: new Date().toISOString() });
        if (board.announcements.length > 100) board.announcements = board.announcements.slice(-100);
        await writeBoard(cfg, board);
        return res.json({ board });
      }
      if (action === 'setAnnouncementPublished') {
        const id = typeof body.id === 'string' ? body.id : '';
        const ann = board.announcements.find((a) => a.id === id);
        if (!ann) return res.status(404).json({ error: 'announcement not found' });
        ann.published = body.published === true;
        await writeBoard(cfg, board);
        return res.json({ board });
      }
      if (action === 'deleteAnnouncement') {
        const id = typeof body.id === 'string' ? body.id : '';
        board.announcements = board.announcements.filter((a) => a.id !== id);
        await writeBoard(cfg, board);
        return res.json({ board });
      }
      if (action === 'upsertPlayer') {
        const pl = body.player && typeof body.player === 'object' ? body.player : {};
        const pEmail = typeof pl.email === 'string' ? pl.email.trim().toLowerCase() : '';
        if (!pEmail) return res.status(400).json({ error: 'email required' });
        const p = ensurePlayer(board, pEmail, typeof pl.name === 'string' ? pl.name.trim().slice(0, 100) : '', typeof pl.studentId === 'string' ? pl.studentId.slice(0, 32) : '');
        if (pl.plan === 'monthly' || pl.plan === 'pay-per-class') p.plan = pl.plan;
        await writeBoard(cfg, board);
        return res.json({ ok: true, player: p });
      }
      if (action === 'sendChallenge') {
        const ch = body.challenge && typeof body.challenge === 'object' ? body.challenge : {};
        const fromEmail = typeof ch.fromEmail === 'string' ? ch.fromEmail.trim().toLowerCase() : '';
        const toEmail = typeof ch.toEmail === 'string' ? ch.toEmail.trim().toLowerCase() : '';
        const format = CHALLENGE_FORMATS.includes(ch.format) ? ch.format : '';
        if (!fromEmail || !toEmail || !format || fromEmail === toEmail) return res.status(400).json({ error: 'from, to, and format required' });
        if (isBlockedPair(board, fromEmail, toEmail)) return res.status(403).json({ error: 'blocked' });
        const fromP = findPlayer(board, fromEmail);
        const toP = findPlayer(board, toEmail);
        if (!fromP || !toP) return res.status(400).json({ error: 'both players must have a profile' });
        if (fromP.lastOpponent === toEmail) return res.status(409).json({ error: 'play someone else before an immediate rematch' });
        const ladder = activeLadder(board);
        const fromIdx = ladder.indexOf(fromEmail);
        const toIdx = ladder.indexOf(toEmail);
        if (fromIdx === -1 || toIdx === -1 || toIdx >= fromIdx || fromIdx - toIdx > LADDER_CHALLENGE_RANGE) {
          return res.status(409).json({ error: 'challenge someone up to 3 spots above you' });
        }
        if (board.challenges.some((c) => c.status === 'pending' && c.fromEmail === fromEmail && c.toEmail === toEmail)) {
          return res.status(409).json({ error: 'challenge already pending' });
        }
        if (board.challenges.filter((c) => c.status === 'pending' && c.fromEmail === fromEmail).length >= 5) {
          return res.status(409).json({ error: 'too many pending challenges' });
        }
        const now = new Date();
        board.challenges.push({ id: newBoardId(), fromEmail, fromName: fromP.name, toEmail, toName: toP.name, format, clock: ch.clock === true, clockMinutes: ch.clock === true ? 15 : 0, status: 'pending', createdAt: now.toISOString(), expiresAt: new Date(now.getTime() + CHALLENGE_TTL_MS).toISOString() });
        if (board.challenges.length > BOARD_MAX_ENTRIES) board.challenges = board.challenges.slice(-BOARD_MAX_ENTRIES);
        await writeBoard(cfg, board);
        return res.json({ ok: true });
      }
      if (action === 'respondChallenge') {
        const id = typeof body.id === 'string' ? body.id : '';
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        const ch = board.challenges.find((c) => c.id === id);
        if (!ch) return res.status(404).json({ error: 'challenge not found' });
        if (ch.toEmail !== email) return res.status(403).json({ error: 'not your challenge' });
        if (ch.status !== 'pending') return res.status(409).json({ error: 'challenge already answered' });
        if (ch.expiresAt && new Date(ch.expiresAt).getTime() < Date.now()) { ch.status = 'expired'; await writeBoard(cfg, board); return res.status(409).json({ error: 'challenge expired' }); }
        if (body.accept === true) {
          ch.status = 'accepted';
          board.matches.push({ id: newBoardId(), challengeId: ch.id, playerA: ch.fromEmail, playerB: ch.toEmail, format: ch.format, clock: ch.clock, clockMinutes: ch.clockMinutes, status: 'active', games: [{ n: 1, white: ch.fromEmail, black: ch.toEmail, moves: [], result: null, resultReason: '' }], currentGame: 1, scoreA: 0, scoreB: 0, winner: '', createdAt: new Date().toISOString(), completedAt: '' });
          if (board.matches.length > BOARD_MAX_ENTRIES) board.matches = board.matches.slice(-BOARD_MAX_ENTRIES);
        } else {
          ch.status = 'declined';
        }
        await writeBoard(cfg, board);
        return res.json({ ok: true });
      }
      if (action === 'postMove') {
        const matchId = typeof body.matchId === 'string' ? body.matchId : '';
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        const mv = body.move && typeof body.move === 'object' ? body.move : {};
        const match = board.matches.find((m) => m.id === matchId);
        if (!match) return res.status(404).json({ error: 'match not found' });
        if (match.status !== 'active') return res.status(409).json({ error: 'match not active' });
        if (email !== match.playerA && email !== match.playerB) return res.status(403).json({ error: 'not your match' });
        const game = match.games[match.games.length - 1];
        if (!game || game.result) return res.status(409).json({ error: 'game already decided' });
        const turnEmail = game.moves.length % 2 === 0 ? game.white : game.black;
        if (email !== turnEmail) return res.status(409).json({ error: 'not your turn' });
        const sq = /^[a-h][1-8]$/;
        if (!sq.test(mv.from || '') || !sq.test(mv.to || '') || (mv.promotion && !['q', 'r', 'b', 'n'].includes(mv.promotion))) {
          return res.status(400).json({ error: 'invalid move' });
        }
        // Full legality (check, pins, castling rights) is enforced by the
        // app's chess engine before posting; the server enforces turn
        // order and move shape so a stale client cannot corrupt a game.
        game.moves.push({ from: mv.from, to: mv.to, promotion: mv.promotion || '', by: email });
        await writeBoard(cfg, board);
        return res.json({ ok: true });
      }
      if (action === 'reportGameResult') {
        const matchId = typeof body.matchId === 'string' ? body.matchId : '';
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        const result = ['white', 'black', 'draw'].includes(body.result) ? body.result : '';
        if (!result) return res.status(400).json({ error: 'result required' });
        const match = board.matches.find((m) => m.id === matchId);
        if (!match) return res.status(404).json({ error: 'match not found' });
        if (match.status !== 'active') return res.status(409).json({ error: 'match not active' });
        if (email !== match.playerA && email !== match.playerB) return res.status(403).json({ error: 'not your match' });
        const game = match.games[match.games.length - 1];
        if (!game) return res.status(409).json({ error: 'no game' });
        if (game.result) return res.json({ ok: true, already: true });
        applyGameResult(board, match, game, result, typeof body.resultReason === 'string' ? body.resultReason.slice(0, 100) : '');
        await writeBoard(cfg, board);
        return res.json({ ok: true });
      }
      if (action === 'offerDraw') {
        const matchId = typeof body.matchId === 'string' ? body.matchId : '';
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        const match = board.matches.find((m) => m.id === matchId);
        if (!match) return res.status(404).json({ error: 'match not found' });
        if (match.status !== 'active') return res.status(409).json({ error: 'match not active' });
        if (email !== match.playerA && email !== match.playerB) return res.status(403).json({ error: 'not your match' });
        match.drawOfferBy = email;
        await writeBoard(cfg, board);
        return res.json({ ok: true });
      }
      if (action === 'respondDraw') {
        const matchId = typeof body.matchId === 'string' ? body.matchId : '';
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        const match = board.matches.find((m) => m.id === matchId);
        if (!match) return res.status(404).json({ error: 'match not found' });
        if (match.status !== 'active' || !match.drawOfferBy || match.drawOfferBy === email) return res.status(409).json({ error: 'no draw offer to answer' });
        if (body.accept === true) {
          const game = match.games[match.games.length - 1];
          if (game && !game.result) applyGameResult(board, match, game, 'draw', 'agreed');
          await writeBoard(cfg, board);
          return res.json({ ok: true });
        }
        match.drawOfferBy = '';
        await writeBoard(cfg, board);
        return res.json({ ok: true });
      }
      if (action === 'sendReaction') {
        const r = body.reaction && typeof body.reaction === 'object' ? body.reaction : {};
        const fromEmail = typeof r.fromEmail === 'string' ? r.fromEmail.trim().toLowerCase() : '';
        const toEmail = typeof r.toEmail === 'string' ? r.toEmail.trim().toLowerCase() : '';
        if (!fromEmail || !toEmail || !ALLOWED_REACTIONS.includes(r.text)) return res.status(400).json({ error: 'valid preset reaction required' });
        if (isBlockedPair(board, fromEmail, toEmail)) return res.status(403).json({ error: 'blocked' });
        board.reactions.push({ id: newBoardId(), fromEmail, fromName: typeof r.fromName === 'string' ? r.fromName.trim().slice(0, 100) : '', toEmail, text: r.text, createdAt: new Date().toISOString() });
        if (board.reactions.length > BOARD_MAX_ENTRIES) board.reactions = board.reactions.slice(-BOARD_MAX_ENTRIES);
        await writeBoard(cfg, board);
        return res.json({ ok: true });
      }
      if (action === 'blockPlayer') {
        const byEmail = typeof body.byEmail === 'string' ? body.byEmail.trim().toLowerCase() : '';
        const blockedEmail = typeof body.blockedEmail === 'string' ? body.blockedEmail.trim().toLowerCase() : '';
        if (!byEmail || !blockedEmail || byEmail === blockedEmail) return res.status(400).json({ error: 'both emails required' });
        if (!board.blocks.some((b) => b.byEmail === byEmail && b.blockedEmail === blockedEmail)) {
          board.blocks.push({ byEmail, blockedEmail, createdAt: new Date().toISOString() });
        }
        board.challenges.forEach((c) => {
          if (c.status === 'pending' && ((c.fromEmail === byEmail && c.toEmail === blockedEmail) || (c.fromEmail === blockedEmail && c.toEmail === byEmail))) c.status = 'declined';
        });
        await writeBoard(cfg, board);
        return res.json({ ok: true });
      }
      if (action === 'unblockPlayer') {
        const byEmail = typeof body.byEmail === 'string' ? body.byEmail.trim().toLowerCase() : '';
        const blockedEmail = typeof body.blockedEmail === 'string' ? body.blockedEmail.trim().toLowerCase() : '';
        board.blocks = board.blocks.filter((b) => !(b.byEmail === byEmail && b.blockedEmail === blockedEmail));
        await writeBoard(cfg, board);
        return res.json({ ok: true });
      }
      if (action === 'sendReport') {
        const r = body.report && typeof body.report === 'object' ? body.report : {};
        const fromEmail = typeof r.fromEmail === 'string' ? r.fromEmail.trim().toLowerCase() : '';
        const aboutEmail = typeof r.aboutEmail === 'string' ? r.aboutEmail.trim().toLowerCase() : '';
        if (!fromEmail || !aboutEmail || !REPORT_REASONS.includes(r.reason)) return res.status(400).json({ error: 'valid report required' });
        board.reports.push({ id: newBoardId(), fromEmail, aboutEmail, reason: r.reason, createdAt: new Date().toISOString(), status: 'open' });
        if (board.reports.length > BOARD_MAX_ENTRIES) board.reports = board.reports.slice(-BOARD_MAX_ENTRIES);
        await writeBoard(cfg, board);
        return res.json({ ok: true });
      }
      if (action === 'resolveReport') {
        const rep = board.reports.find((r) => r.id === body.id);
        if (!rep) return res.status(404).json({ error: 'report not found' });
        rep.status = 'resolved';
        await writeBoard(cfg, board);
        return res.json({ board });
      }
      if (action === 'addCredits') {
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        const amount = Math.floor(Number(body.amount) || 0);
        if (!email || amount <= 0) return res.status(400).json({ error: 'email and positive amount required' });
        ensurePlayer(board, email, '', '');
        grantCredits(board, email, amount, typeof body.reason === 'string' ? body.reason.slice(0, 200) : 'Admin grant', 'instructor', typeof body.expiresAt === 'string' ? body.expiresAt : '');
        await writeBoard(cfg, board);
        return res.json({ board });
      }
      if (action === 'deductCredits') {
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        const amount = Math.floor(Number(body.amount) || 0);
        if (!email || amount <= 0) return res.status(400).json({ error: 'email and positive amount required' });
        const out = deductCredits(board, email, amount, typeof body.reason === 'string' ? body.reason.slice(0, 200) : 'Admin deduction', 'instructor');
        if (!out.ok) return res.status(409).json({ error: 'insufficient credits', available: out.available });
        await writeBoard(cfg, board);
        return res.json({ board });
      }
      if (action === 'setPlan') {
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        if (!email || (body.plan !== 'monthly' && body.plan !== 'pay-per-class')) return res.status(400).json({ error: 'email and plan required' });
        const p = ensurePlayer(board, email, '', '');
        p.plan = body.plan;
        await writeBoard(cfg, board);
        return res.json({ board });
      }
      return res.status(400).json({ error: 'unknown action' });
    } catch (err) {
      console.error('board failed:', err && err.message);
      return res.status(500).json({ error: 'could not update board' });
    }
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
  createBoardHandler,
  readConfig,
  safeEqual,
  normalizeName,
  makeReinviteCode,
  verifyReinviteCode,
  findBanEntry,
  removeBanEntries,
  parseBanList,
};
