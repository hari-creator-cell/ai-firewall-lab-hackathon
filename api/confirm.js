
const crypto = require("crypto");

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Use POST." });
  }

  const expected = process.env.LAB_DASHBOARD_KEY;
  const supplied = req.headers["x-lab-dashboard-key"];

  if (!expected || typeof supplied !== "string" ||
      supplied.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))) {
    return res.status(401).json({ error: "Invalid server authentication." });
  }

  const requestId = req.body?.requestId;
  if (typeof requestId !== "string" ||
      !/^[0-9a-f-]{36}$/i.test(requestId)) {
    return res.status(400).json({ error: "Invalid request ID." });
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
      `${base.origin}/rest/v1/ai_firewall_transfers?request_id=eq.${encodeURIComponent(requestId)}&select=request_id`,
      {
        method: "PATCH",
        headers: {
          apikey: key,
          Authorization: `Bearer ${key}`,
          "Content-Type": "application/json",
          Prefer: "return=representation"
        },
        body: JSON.stringify({
          nova_confirmed_at: new Date().toISOString(),
          transfer_status: "RETURN_CONFIRMED"
        }),
        signal: AbortSignal.timeout(8000)
      }
    );

    if (!response.ok) {
      return res.status(502).json({ error: "Could not update transfer record." });
    }

    const updated = await response.json();
    if (!updated.length) {
      return res.status(404).json({ error: "Transfer record not found." });
    }

    return res.status(200).json({
      confirmed: true,
      requestId: updated[0].request_id
    });
  } catch {
    return res.status(503).json({ error: "Could not confirm transfer." });
  }
};
