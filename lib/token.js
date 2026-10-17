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
//   announcements: [{ id, title, body, published, createdAt }] } }
const BOARD_ROOM = 'chess-classroom-board';
const BOARD_METADATA_KEY = 'board';
const BOARD_MAX_ENTRIES = 500; // cap each list so metadata stays small
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function emptyBoard() {
  return { closedDays: [], bookings: [], dayMessages: [], reviews: [], announcements: [] };
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
      .filter((e) => e && typeof e === 'object' && str(e.title) && str(e.body))
      .map((e) => ({ id: str(e.id), title: str(e.title), body: str(e.body), published: e.published === true, createdAt: str(e.createdAt) }));
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
      return res.json({
        closedDays: board.closedDays,
        dayMessages: email ? board.dayMessages.filter((m) => bookedDates.has(m.date)) : [],
        reviews: board.reviews,
        announcements: board.announcements.filter((a) => a.published),
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
    const needInstructor = ['read', 'closeDay', 'openDay', 'addDayMessage', 'addAnnouncement', 'setAnnouncementPublished', 'deleteAnnouncement'].includes(action);
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
        if (!title || !annBody) return res.status(400).json({ error: 'title and body required' });
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
