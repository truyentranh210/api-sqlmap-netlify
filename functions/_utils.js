import fs from "fs/promises";

export const ADMIN_KEY = process.env.ADMIN_KEY || "";
export const SQLMAP_API = process.env.SQLMAP_API || "";
export const WHITELIST = (process.env.WHITELIST || "").split(",").map(s=>s.trim()).filter(Boolean);

export function getHost(u){
  try { return new URL(u).hostname.replace(/^www\./,''); } catch { return null; }
}
export function short(s,n=600){ if(!s) return s; s=String(s); return s.length>n?s.slice(0,n)+"…":s; }
