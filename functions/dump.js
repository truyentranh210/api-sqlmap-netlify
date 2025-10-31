import axios from "axios";
import { ADMIN_KEY, SQLMAP_API } from "./_utils.js";

export const handler = async (event) => {
  const q = event.queryStringParameters || {};
  const key = q.k || event.headers["x-api-key"];
  if (!key || key !== ADMIN_KEY) return { statusCode: 401, body: JSON.stringify({ error: "Sai key" }) };

  const target = q.u, db = q.db, table = q.table, mode = q.mode || "create";
  if (!target) return { statusCode: 400, body: JSON.stringify({ error: "Thiếu URL" }) };

  try {
    const task = await axios.get(`${SQLMAP_API}/task/new`);
    const taskid = task.data.taskid;

    await axios.post(`${SQLMAP_API}/scan/${taskid}/start`, {
      url: target,
      options: { dump: true, D: db || undefined, T: table || undefined }
    });

    if (mode === "create")
      return { statusCode: 200, body: JSON.stringify({ taskid, note: "Đã tạo task, kiểm tra bằng /status hoặc /fetch" }) };

    let done = false, status;
    for (let i = 0; i < 120; i++) {
      const res = await axios.get(`${SQLMAP_API}/scan/${taskid}/status`);
      status = res.data;
      if (status.status === "terminated") { done = true; break; }
      await new Promise(r => setTimeout(r, 2000));
    }

    const data = await axios.get(`${SQLMAP_API}/scan/${taskid}/data`);
    return { statusCode: 200, body: JSON.stringify({ taskid, status, data: data.data }) };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};
