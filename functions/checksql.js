// functions/checksql.js
const axios = require("axios");
const { ADMIN_KEY, WHITELIST, getHost, short, saveReport } = require("./_utils.js");

const PAYLOADS = [
  { p: "' OR '1'='1", type: "boolean" },
  { p: "\" OR \"1\"=\"1", type: "boolean" },
  { p: "' OR 1=1--", type: "classic" },
  { p: "';", type: "error" },
  { p: "\";", type: "error" },
  { p: "' OR sleep(4)--", type: "time" },
  { p: "\" OR pg_sleep(4)--", type: "time" }
];

const INDICATORS = [
  "you have an error in your sql syntax",
  "warning: mysql",
  "unclosed quotation",
  "sql syntax",
  "mysql_fetch",
  "pg_fetch",
  "sqlstate",
  "odbc",
  "ora-"
];

const TIMEOUT = 7000;
const TIME_THRESHOLD = 2000; // ms

function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }

exports.handler = async (event) => {
  try {
    const q = event.queryStringParameters || {};
    const target = (q.u || q.url || "").trim();
    const providedKey = (event.headers && (event.headers["x-api-key"] || event.headers["X-API-KEY"])) || q.k || "";

    if (!ADMIN_KEY) return { statusCode: 500, body: JSON.stringify({ error: "ADMIN_KEY chưa được cấu hình" }) };
    if (!providedKey || providedKey !== ADMIN_KEY) return { statusCode: 401, body: JSON.stringify({ error: "Unauthorized - missing/invalid API key" }) };
    if (!target) return { statusCode: 400, body: JSON.stringify({ error: "Thiếu tham số ?u=<URL>" }) };

    // validate host and block local addresses
    const host = getHost(target);
    if (!host) return { statusCode: 400, body: JSON.stringify({ error: "URL không hợp lệ" }) };
    if (WHITELIST.length > 0 && !WHITELIST.includes(host)) return { statusCode: 403, body: JSON.stringify({ error: `Host ${host} không nằm trong whitelist` }) };
    if (/^(http:\/\/localhost|https?:\/\/127\.0\.0\.1|http:\/\/10\.|http:\/\/192\.168\.)/i.test(target)) return { statusCode: 400, body: JSON.stringify({ error: "Không cho phép quét localhost/private network" }) };

    // baseline
    const baseStart = Date.now();
    await axios.get(target, { timeout: TIMEOUT }).catch(()=>{});
    const baseline = Date.now() - baseStart;

    const results = [];
    for (const pl of PAYLOADS) {
      const testUrl = target.includes("?") ? `${target}&t=${encodeURIComponent(pl.p)}` : `${target}?t=${encodeURIComponent(pl.p)}`;
      const start = Date.now();
      try {
        const res = await axios.get(testUrl, { timeout: TIMEOUT, validateStatus: () => true });
        const took = Date.now() - start;
        const body = (typeof res.data === "string" ? res.data : JSON.stringify(res.data)).toLowerCase();
        const found = INDICATORS.find(i => body.includes(i));
        const timeDelay = pl.type === "time" && (took - baseline) >= TIME_THRESHOLD;
        const vulnerable = Boolean(found) || timeDelay || (res.status >= 500 && res.status < 600);

        results.push({
          payload: pl.p,
          type: pl.type,
          status: res.status,
          timeMs: took,
          baselineMs: baseline,
          vulnerable,
          indicator: found || null,
          timeEvidence: timeDelay ? { baselineMs: baseline, observedMs: took } : null
        });
      } catch (err) {
        results.push({ payload: pl.p, error: short(err.message) });
      }
      await sleep(150);
    }

    const positives = results.filter(r => r.vulnerable).length;
    const score = Math.min(100, Math.round((positives / PAYLOADS.length) * 100));
    const level = score >= 50 ? "HIGH" : score >= 20 ? "MEDIUM" : "LOW";

    const report = {
      id: `rpt_${Date.now()}`,
      createdAt: new Date().toISOString(),
      target,
      baselineMs: baseline,
      risk: { score, level },
      results
    };

    // best-effort save (ephemeral)
    try { await saveReport(report); } catch (e) { /* ignore */ }

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, baselineMs: baseline, risk: { score, level }, results, reportId: report.id })
    };
  } catch (err) {
    return { statusCode: 500, headers: { "Content-Type": "application/json" }, body: JSON.stringify({ error: "Internal error", detail: short(err && err.message) }) };
  }
};
