// functions/status.js
const axios = require("axios");
const { ADMIN_KEY, SQLMAP_API, short } = require("./_utils.js");

exports.handler = async (event) => {
  try {
    const q = event.queryStringParameters || {};
    const providedKey = (event.headers && (event.headers["x-api-key"] || event.headers["X-API-KEY"])) || q.k || "";
    const taskid = (q.taskid || q.tid || "").trim();

    if (!ADMIN_KEY) return { statusCode: 500, body: JSON.stringify({ error: "ADMIN_KEY chưa được cấu hình" }) };
    if (!providedKey || providedKey !== ADMIN_KEY) return { statusCode: 401, body: JSON.stringify({ error: "Unauthorized - missing/invalid API key" }) };
    if (!SQLMAP_API) return { statusCode: 500, body: JSON.stringify({ error: "SQLMAP_API chưa được cấu hình" }) };
    if (!taskid) return { statusCode: 400, body: JSON.stringify({ error: "Thiếu ?taskid=" }) };

    const res = await axios.get(`${SQLMAP_API}/scan/${taskid}/status`, { timeout: 7000 }).catch(e => ({ data: null, err: e && e.message }));
    return { statusCode: 200, headers: { "Content-Type": "application/json" }, body: JSON.stringify({ taskid, status: res && res.data ? res.data : null }) };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: "Internal error", detail: short(err && err.message) }) };
  }
};
