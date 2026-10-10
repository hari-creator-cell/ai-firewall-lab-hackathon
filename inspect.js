
const crypto = require("crypto");

const MAX_CHARS = 12000;

function inspectPrompt(text) {
  const rules = [
    {
      name: "Sensitive data disclosure",
      score: 90,
      pattern: /\b(reveal|disclose|dump|export|expose)\b.{0,80}\b(private|personal|confidential|sensitive)\b/i
    },
    {
      name: "Instruction override / prompt injection",
      score: 85,
      pattern: /ignore\s+(all\s+)?(previous|prior|above|system|developer)\s+instructions|reveal\s+(your\s+)?hidden\s+system prompt|override\s+(the\s+)?(system|safety|security)\s+(prompt|rules|instructions)/i
    },
    {
      name: "Jailbreak or safety bypass",
      score: 80,
      pattern: /act as (an? )?(unrestricted|uncensored|jailbroken)|bypass (all )?(safety|security|approval) (rules|checks|filters)/i
    },
    {
      name: "Credential or secret request",
      score: 90,
      pattern: /(reveal|show|print|dump|send|export).{0,50}(api[_ -]?keys?|passwords?|credentials?|tokens?|secrets?)/i
    },
    {
      name: "Unauthorized action request",
      score: 75,
      pattern: /execute (an? )?unauthorized action|bypass.{0,30}(approval|permission|authorization)|disable (the )?(security|audit) logs/i
    },
    {
      name: "Possible secret pattern",
      score: 75,
      pattern: /(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/
    }
  ];

  let score = 5;
  const reasons = [];

  for (const rule of rules) {
    if (rule.pattern.test(text)) {
      reasons.push(rule.name);
      score = Math.max(score, rule.score);
    }
  }

  const configured = Number(process.env.RISK_THRESHOLD || 50);
  const threshold = Number.isFinite(configured)
    ? Math.min(90, Math.max(10, configured))
    : 50;

  const decision = score >= threshold
    ? "BLOCK"
    : reasons.length
      ? "REVIEW"
      : "ALLOW";

  if (!reasons.length) {
    reasons.push(
      "No configured threat pattern matched. This is not a guarantee of safety."
    );
  }

  return { score, decision, reasons, blocked: decision === "BLOCK" };
}

function bodyOf(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string") {
    try { return JSON.parse(req.body); } catch {}
  }
  return null;
}

function send(res, status, body) {
  return res.status(status).json(body);
}

async function saveTransfer(record) {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !key) throw new Error("Storage is not configured");

  const base = new URL(url);
  if (base.protocol !== "https:" || !base.hostname.endsWith(".supabase.co")) {
    throw new Error("Invalid storage URL");
  }

  const response = await fetch(
    `${base.origin}/rest/v1/ai_firewall_transfers`,
    {
      method: "POST",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "return=minimal"
      },
      body: JSON.stringify(record),
      signal: AbortSignal.timeout(5000)
    }
  );

  if (!response.ok) {
    // Do not print prompt contents or secrets to deployment logs.
    throw new Error("Database insert failed with HTTP " + response.status);
  }
}

module.exports = async function inspectHandler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return send(res, 405, { error: "Use POST." });
  }

  const body = bodyOf(req);
  if (!body || typeof body.text !== "string") {
    return send(res, 400, { error: "Provide a text string." });
  }

  const text = body.text.trim();
  if (!text) return send(res, 400, { error: "Text is empty." });
  if (text.length > MAX_CHARS) {
    return send(res, 413, { error: "Maximum prompt length is 12,000 characters." });
  }

  const suppliedId = body.requestId;
  const requestId = typeof suppliedId === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(suppliedId)
      ? suppliedId
      : crypto.randomUUID();

  const startedAt = Date.now();
  const result = inspectPrompt(text);

  try {
    await saveTransfer({
      request_id: requestId,
      source_app: body.sourceApp === "Nova AI" ? "Nova AI" : "Lab Dashboard",
      prompt_text: text,
      decision: result.decision,
      risk_score: result.score,
      reasons: result.reasons,
      transfer_status: "INSPECTED",
      model_called: false,
      action_executed: false
    });
  } catch {
    // Do not claim persistent recording if storage failed.
    return send(res, 503, {
      error: "Inspection completed, but the result could not be saved to the audit database. No successful transfer record was created.",
      decision: result.decision,
      score: result.score,
      reasons: result.reasons,
      requestId,
      storageSaved: false,
      modelCalled: false,
      actionExecuted: false
    });
  }

  return send(res, 200, {
    ...result,
    requestId,
    source: "Server-side rules",
    modelCalled: false,
    actionExecuted: false,
    storageSaved: true,
    durationMs: Date.now() - startedAt
  });
};

module.exports.inspectPrompt = inspectPrompt;
