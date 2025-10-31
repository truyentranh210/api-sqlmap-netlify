// functions/report.js
const { ADMIN_KEY, short, saveReport, loadReports } = require("./_utils.js");

exports.handler = async (event) => {
  try {
    const q = event.queryStringParameters || {};
    const providedKey = (event.headers && (event.headers["x-api-key"] || event.headers["X-API-KEY"])) || q.k || "";

    if (!ADMIN_KEY) return { statusCode: 500, body: JSON.stringify({ error: "ADMIN_KEY chưa được cấu hình" }) };
    if (!providedKey || providedKey !== ADMIN_KEY) return { statusCode: 401, body: JSON.stringify({ error: "Unauthorized - missing/invalid API key" }) };

    if (event.httpMethod === "POST") {
      // save posted report
      try {
        const body = event.body ? JSON.parse(event.body) : null;
        if (!body) return { statusCode: 400, body: JSON.stringify({ error: "Missing JSON body" }) };
        const report = { id: `rpt_${Date.now()}`, createdAt: new Date().toISOString(), ...body };
        const ok = await saveReport(report);
        return { statusCode: ok ? 200 : 500, body: JSON.stringify({ saved: ok, reportId: report.id }) };
      } catch (e) {
        return { statusCode: 400, body: JSON.stringify({ error: "Invalid JSON body", detail: short(e && e.message) }) };
      }
    } else {
      // GET: list recent reports
      const limit = Math.min(200, parseInt(q.limit || "50", 10) || 50);
      const arr = await loadReports(limit);
      return { statusCode: 200, body: JSON.stringify({ count: arr.length, reports: arr }) };
    }
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: "Internal error", detail: short(err && err.message) }) };
  }
};
