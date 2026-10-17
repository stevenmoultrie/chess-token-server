// Serves the support page for the App Store listing (privacy/support URL).
// Source of truth: the draft in the chess-app goal files — regenerate this
// file from that draft if the page text changes; do not hand-edit the HTML here.
// Static files at the repo root are NOT served by this Vercel project
// (verified Oct 2026: README.md/package.json/server.js all 404), so the page
// is served through this function + a rewrite in vercel.json.
const HTML = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>Support — Tokyo's Chess Academy</title>\n<style>\n  body { font-family: -apple-system, Helvetica, Arial, sans-serif; max-width: 720px; margin: 0 auto; padding: 24px 16px 64px; line-height: 1.6; color: #1a1a1a; }\n  h1 { font-size: 1.6rem; }\n  a { color: #1a5fb4; }\n</style>\n</head>\n<body>\n<h1>Support — Tokyo's Chess Academy</h1>\n<p>Questions about classes, bookings, payments, or your account? Email us:</p>\n<p><a href=\"mailto:stevenmoultrie.jobs@gmail.com\">stevenmoultrie.jobs@gmail.com</a></p>\n<p>We can help with:</p>\n<ul>\n  <li>Booking or changing a class</li>\n  <li>Payments and credits</li>\n  <li>Seeing, correcting, or deleting your (or your child's) information</li>\n  <li>Reporting a problem with another student (block and report tools are also in the app)</li>\n  <li>Anything else about the app</li>\n</ul>\n<p><a href=\"/privacy.html\">Privacy Policy</a></p>\n</body>\n</html>\n";

module.exports = (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.status(200).send(HTML);
};
