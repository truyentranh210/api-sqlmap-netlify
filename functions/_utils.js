// functions/_utils.js
const fs = require("fs").promises;
const path = require("path");

const ADMIN_KEY = process.env.ADMIN_KEY || "";
const SQLMAP_API = process.env.SQLMAP_API || "";
const WHITELIST = (process.env.WHITELIST || "").split(",").map(s => s.trim()).filter(Boolean);

const REPORTS_FILE = "/tmp/reports.json"; // ephemeral storage on Netlify; may be reset between cold starts

function getHost(u) {
  try { return new URL(u).hostname.replace(/^www\./, ""); } catch (e) { return null; }
}
function short(s, n = 600) {
  if (s == null) return s;
  s = String(s);
  return s.length > n ? s.slice(0, n) + "…" : s;
}

async function saveReport(report) {
  try {
    let arr = [];
    try {
      const prev = await fs.readFile(REPORTS_FILE, "utf8");
      arr = JSON.parse(prev || "[]");
    } catch (e) {
      arr = [];
    }
    arr.unshift(report);
    if (arr.length > 200) arr = arr.slice(0, 200);
    await fs.writeFile(REPORTS_FILE, JSON.stringify(arr, null, 2), "utf8");
    return true;
  } catch (e) {
    console.error("saveReport error:", e);
    return false;
  }
}

async function loadReports(limit = 50) {
  try {
    const raw = await fs.readFile(REPORTS_FILE, "utf8");
    const arr = JSON.parse(raw || "[]");
    return Array.isArray(arr) ? arr.slice(0, limit) : [];
  } catch (e) {
    return [];
  }
}

module.exports = {
  ADMIN_KEY,
  SQLMAP_API,
  WHITELIST,
  REPORTS_FILE,
  getHost,
  short,
  saveReport,
  loadReports
};
