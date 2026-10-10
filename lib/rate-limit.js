// Tiny best-effort rate limiter: max `max` requests per `windowMs` per IP.
// On serverless hosts (Vercel) each function instance keeps its own counter,
// so this is a speed bump, not a guarantee — real abuse protection belongs at
// the hosting/CDN layer if you ever need it.
function rateLimit({ windowMs = 60_000, max = 30 } = {}) {
  const hits = new Map(); // ip -> { count, resetAt }
  return (req, res, next) => {
    const ip =
      (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
      (req.socket && req.socket.remoteAddress) ||
      'unknown';
    const now = Date.now();
    let slot = hits.get(ip);
    if (!slot || now > slot.resetAt) {
      slot = { count: 0, resetAt: now + windowMs };
      hits.set(ip, slot);
    }
    slot.count += 1;
    if (slot.count > max) {
      res.setHeader('Retry-After', Math.ceil((slot.resetAt - now) / 1000));
      return res.status(429).json({ error: 'too many requests' });
    }
    // Opportunistic cleanup so the map can't grow forever.
    if (hits.size > 5000 && Math.random() < 0.01) {
      for (const [k, v] of hits) if (now > v.resetAt) hits.delete(k);
    }
    return next();
  };
}

module.exports = { rateLimit };
