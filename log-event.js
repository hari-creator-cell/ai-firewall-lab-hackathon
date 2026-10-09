module.exports = async function logSecurityEvent(event) {
  try {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

    // Fail safely when server configuration is missing.
    if (!url || !key) {
      console.error("Security event logging is not configured.");
      return false;
    }

    // Validate the Supabase URL before making a request.
    let baseUrl;

    try {
      baseUrl = new URL(url);

      if (
        baseUrl.protocol !== "https:" ||
        baseUrl.username ||
        baseUrl.password ||
        baseUrl.search ||
        baseUrl.hash
      ) {
        console.error("Security event logging configuration is invalid.");
        return false;
      }
    } catch {
      console.error("Security event logging configuration is invalid.");
      return false;
    }

    // Accept only known event decisions and endpoints.
    const allowedDecisions = ["ALLOW", "REVIEW", "BLOCK"];

    const allowedEndpoints = [
      "/api/inspect",
      "/api/chat",
      "system"
    ];

    if (
      !event ||
      !allowedDecisions.includes(event.decision) ||
      !allowedEndpoints.includes(event.endpoint)
    ) {
      return false;
    }

    // Keep categories short and bounded.
    const categories = Array.isArray(event.categories)
      ? event.categories
          .filter(
            item =>
              typeof item === "string" &&
              item.length > 0 &&
              item.length <= 100
          )
          .slice(0, 20)
      : [];

    const numericScore = Number(event.risk_score);

    const riskScore = Number.isFinite(numericScore)
      ? Math.max(0, Math.min(100, Math.round(numericScore)))
      : 0;

    const numericDuration = Number(event.duration_ms);

    const durationMs =
      event.duration_ms !== null &&
      event.duration_ms !== undefined &&
      Number.isFinite(numericDuration)
        ? Math.max(0, Math.min(2147483647, Math.round(numericDuration)))
        : null;

    const errorCategory =
      typeof event.error_category === "string"
        ? event.error_category.slice(0, 80)
        : null;

    // Store metadata only. Never store prompts, responses, or credentials.
    const payload = {
      decision: event.decision,
      risk_score: riskScore,
      categories,
      endpoint: event.endpoint,
      duration_ms: durationMs,
      error_category: errorCategory,
      request_fingerprint: null
    };

    const endpoint =
      `${baseUrl.origin}${baseUrl.pathname.replace(/\/+$/, "")}` +
      "/rest/v1/ai_firewall_security_events";

    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "return=minimal"
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(2000)
    });

    if (!response.ok) {
      // Do not log the request body, key, or database response body.
      console.error(
        "Security event logging failed with HTTP status:",
        response.status
      );
      return false;
    }

    return true;
  } catch {
    // Logging failures must not expose secrets or crash the application.
    console.error("Security event logging unavailable.");
    return false;
  }
};
