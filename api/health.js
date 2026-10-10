// Vercel serverless function: GET /api/health
module.exports = async (req, res) => {
  res.status(200).json({
    ok: true,
    service: 'chess-token-server',
    time: new Date().toISOString(),
  });
};
