const crypto = require("crypto");

function redactSecrets(value) {
  return String(value)
    .replace(
      /(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})/g,
      "[REDACTED SECRET]"
    )
    .replace(
      /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
      "[REDACTED PRIVATE KEY]"
    )
    .replace(
      /\b(password|passwd|api[_ -]?key|access[_ -]?token|secret)\s*[:=]\s*[^\s,;]+/gi,
      "$1=[REDACTED]"
    );
}

module.exports = async function sendRiskAlert({
  score,
  decision,
  reasons,
  prompt
}) {
  try {
    const apiKey = process.env.RESEND_API_KEY;
    const to = process.env.ALERT_EMAIL_TO;
    const from = process.env.ALERT_EMAIL_FROM;
    const configured = Number(process.env.ALERT_RISK_THRESHOLD || 70);
    const threshold = Number.isFinite(configured)
      ? Math.min(100, Math.max(1, configured))
      : 70;

    if (score < threshold) {
      return { sent: false, reason: "below_threshold" };
    }

    if (!apiKey || !to || !from) {
      console.error("Risk alert configuration is incomplete.");
      return { sent: false, reason: "not_configured" };
    }

    const safePrompt = redactSecrets(prompt).slice(0, 12000);
    const safeReasons = Array.isArray(reasons) && reasons.length
      ? reasons.map(r => String(r).slice(0, 200)).join(", ")
      : "Risk threshold reached";

    const text = [
      "AI Firewall Lab — Risk Alert",
      "",
      `Risk score: ${score}/100`,
      `Decision: ${decision}`,
      `Reason: ${safeReasons}`,
      `Timestamp: ${new Date().toISOString()}`,
      `Alert ID: ${crypto.randomUUID()}`,
      "",
      "Submitted prompt (detected secrets redacted):",
      safePrompt
    ].join("\n");

    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from,
        to: [to],
        subject: `AI Firewall risk alert — ${score}/100`,
        text
      }),
      signal: AbortSignal.timeout(5000)
    });

    if (!response.ok) {
      console.error("Risk alert provider returned HTTP", response.status);
      return { sent: false, reason: "provider_error" };
    }

    return { sent: true };
  } catch {
    // Email failures must not change the firewall's verdict.
    console.error("Risk alert email unavailable.");
    return { sent: false, reason: "delivery_error" };
  }
};
