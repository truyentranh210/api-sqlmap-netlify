import axios from "axios";
import { ADMIN_KEY, SQLMAP_API } from "./_utils.js";

export const handler = async (event) => {
  const q = event.queryStringParameters || {};
  const key = q.k || event.headers["x-api-key"];
  const taskid = q.taskid;
  if (!key || key !== ADMIN_KEY) return { statusCode: 401, body: JSON.stringify({ error: "Sai key" }) };

  const data = await axios.get(`${SQLMAP_API}/scan/${taskid}/data`);
  return { statusCode: 200, body: JSON.stringify(data.data) };
};
