
module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Use GET." });
  }

  const expected = process.env.LAB_DASHBOARD_KEY;
  const supplied = req.headers["x-lab-dashboard-key"];

  if (!expected || typeof supplied !== "string" ||
      supplied.length !== expected.length ||
      !require("crypto").timingSafeEqual(
        Buffer.from(supplied), Buffer.from(expected)
      )) {
    return res.status(401).json({ error: "Dashboard authorization required." });
  }

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !key) {
    return res.status(503).json({ error: "Database configuration missing." });
  }

  try {
    const base = new URL(url);
    if (base.protocol !== "https:" ||
        !base.hostname.endsWith(".supabase.co")) {
      throw new Error("Invalid database URL");
    }

    const response = await fetch(
      `${base.origin}/rest/v1/ai_firewall_transfers?select=request_id,source_app,prompt_text,decision,risk_score,reasons,received_at,inspected_at,response_sent_at,nova_confirmed_at,transfer_status,model_called,action_executed&order=received_at.desc&limit=200`,
      {
        headers: {
          apikey: key,
          Authorization: `Bearer ${key}`
        },
        signal: AbortSignal.timeout(8000)
      }
    );

    if (!response.ok) {
      return res.status(502).json({ error: "Could not load saved transfer records." });
    }

    const records = await response.json();
    return res.status(200).json({ records, count: records.length });
  } catch {
    return res.status(503).json({ error: "Audit database is unavailable." });
  }
};
