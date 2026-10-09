module.exports = async function logSecurityEvent(event) {
const url = process.env.SUPABASE_URL;
const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!url || !key) {
console.error("Security event logging is not configured.");
return;
}

const decisions = ["ALLOW", "REVIEW", "BLOCK"];
const endpoints = ["/api/inspect", "/api/chat", "system"];

if (!decisions.includes(event.decision) ||
!endpoints.includes(event.endpoint)) return;

const payload = {
decision: event.decision,
risk_score: Math.max(0, Math.min(100,
Math.round(Number(event.risk_score) || 0))),
categories: Array.isArray(event.categories)
? event.categories
.filter(x => typeof x === "string")
.slice(0, 20)
: [],
endpoint: event.endpoint,
duration_ms: Number.isFinite(event.duration_ms)
? Math.max(0, Math.round(event.duration_ms))
: null,
error_category: typeof event.error_category === "string"
? event.error_category.slice(0, 80)
: null,
request_fingerprint: null
};

try {
const response = await fetch(
"${url.replace(/\/+$/, "")}/rest/v1/ai_firewall_security_events",
{
method: "POST",
headers: {
apikey: key,
Authorization: "Bearer ${key}",
"Content-Type": "application/json",
Prefer: "return=minimal"
},
body: JSON.stringify(payload),
signal: AbortSignal.timeout(2000)
}
);

if (!response.ok) {
  console.error("Security event logging failed:", response.status);
}

} catch {
console.error("Security event logging unavailable.");
}
};
