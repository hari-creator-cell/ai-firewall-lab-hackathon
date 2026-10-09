const logSecurityEvent = require("./log-event");

const MAX_CHARS = 12000;

function inspectPrompt(text) {
const rules = [
{
name: "Instruction override / prompt injection",
score: 85,
pattern: /ignore\s+(all\s+)?(previous|prior|above|system|developer)\s+instructions|disregard\s+(all\s+)?(previous|prior|above)\s+instructions|reveal\s+(your\s+)?(hidden\s+)?(system prompt|developer message)|override\s+(the\s+)?(system|safety|security)\s+(prompt|rules|instructions)/i
},
{
name: "Jailbreak or safety bypass",
score: 80,
pattern: /act as (an? )?(unrestricted|uncensored|jailbroken)|ignore (your )?(safety|content) policies|bypass (all )?(safety|security|approval) (rules|checks|filters)/i
},
{
name: "Credential or secret exfiltration",
score: 90,
pattern: /(reveal|show|print|exfiltrate|dump|send|export).{0,50}(api[_ -]?keys?|passwords?|credentials?|tokens?|secrets?)|(api[_ -]?keys?|passwords?|credentials?|access tokens?).{0,50}(reveal|show|print|dump|send|exfiltrate)/i
},
{
name: "Unauthorized tool or action request",
score: 75,
pattern: /execute (an? )?unauthorized action|bypass.{0,30}(approval|permission|authorization)|run (shell|terminal) commands? without approval|disable (the )?(security|audit) logs/i
},
{
name: "Potential secret in submitted text",
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

if (
/internal configuration|confidential data|private records/i.test(text) &&
!reasons.length
) {
reasons.push("Potentially sensitive internal information request");
score = Math.max(score, 40);
}

const threshold = Math.min(
90,
Math.max(10, Number(process.env.RISK_THRESHOLD || 50))
);

const decision =
score >= threshold
? "BLOCK"
: reasons.length
? "REVIEW"
: "ALLOW";

return {
score,
decision,
reasons,
blocked: decision === "BLOCK"
};
}

function bodyOf(req) {
if (req.body && typeof req.body === "object") {
return req.body;
}

if (typeof req.body === "string") {
try {
return JSON.parse(req.body);
} catch {
return null;
}
}

return null;
}

function valid(req, res) {
if (req.method !== "POST") {
res.setHeader("Allow", "POST");
res.status(405).json({
error: "Method not allowed. Use POST."
});
return false;
}

const origin = req.headers.origin;
const host = req.headers.host;

if (origin && host) {
try {
if (new URL(origin).host !== host) {
res.status(403).json({
error: "Cross-origin requests are not allowed."
});
return false;
}
} catch {
res.status(403).json({
error: "Invalid request origin."
});
return false;
}
}

return true;
}

module.exports = async function(req, res) {
const startedAt = Date.now();

if (!valid(req, res)) {
return;
}

const body = bodyOf(req);

if (!body || typeof body.text !== "string") {
return res.status(400).json({
error: "Provide a JSON body with a text string."
});
}

const text = body.text.trim();

if (!text) {
return res.status(400).json({
error: "Text must not be empty."
});
}

if (text.length > MAX_CHARS) {
return res.status(413).json({
error: "Text exceeds the 12,000 character limit."
});
}

const result = inspectPrompt(text);

await logSecurityEvent({
decision: result.decision,
risk_score: result.score,
categories: result.reasons,
endpoint: "/api/inspect",
duration_ms: Date.now() - startedAt,
error_category: null
});

return res.status(200).json({
...result,
modelCalled: false,
source: "Server-side rules",
reasons: result.reasons.length
? result.reasons
: ["No configured threat pattern matched. This is not a guarantee of safety."]
});
};

module.exports.inspectPrompt = inspectPrompt;
