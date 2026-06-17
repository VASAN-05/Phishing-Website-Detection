import type { RequestHandler } from "express";
import type { Request, Response } from "express";
import fs from "node:fs";
import http from "node:http";
import type { ScanResponse } from "../../shared/api.ts";

const ML_ENGINE_URL   = process.env.ML_ENGINE_URL ?? "http://localhost:5001";
const FILE_TIMEOUT_MS = 30 * 60 * 1000; // 30 min for large files

// ── Health check ─────────────────────────────────────────────
export const handleHealth: RequestHandler = async (_req, res) => {
  try {
    const r = await fetch(`${ML_ENGINE_URL}/health`, { signal: AbortSignal.timeout(5000) });
    const data = await r.json();
    res.json(data);
  } catch {
    res.status(503).json({ status: "unavailable", error: "ML engine unreachable" });
  }
};

// ── URL scan (SSE streaming) ──────────────────────────────────
// Proxies the Python SSE stream straight through to the browser
export const handleUrlScanStream = (req: Request, res: Response): void => {
  const { url } = req.body as { url?: string };
  if (!url?.trim()) {
    res.status(400).json({ error: "URL is required" });
    return;
  }

  const body = JSON.stringify({ url: url.trim() });

  // Set SSE headers immediately so the browser opens the stream
  res.setHeader("Content-Type",     "text/event-stream");
  res.setHeader("Cache-Control",    "no-cache");
  res.setHeader("Connection",       "keep-alive");
  res.setHeader("X-Accel-Buffering","no");
  res.flushHeaders();

  // Try using fetch for better handling of streaming responses
  (async () => {
    try {
      console.log(`[SSE] Starting stream to ${ML_ENGINE_URL}/analyze/url/stream`);
      
      const fetchRes = await fetch(`${ML_ENGINE_URL}/analyze/url/stream`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: body,
        signal: AbortSignal.timeout(300000), // 5 min timeout for long-running scan
      });

      if (!fetchRes.ok || !fetchRes.body) {
        throw new Error(`ML engine returned ${fetchRes.status}`);
      }

      console.log(`[SSE] Connected to ML engine, streaming response`);
      
      // Read the response body as a stream
      const reader = fetchRes.body.getReader();
      const decoder = new TextDecoder();

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value, { stream: true });
        console.log(`[SSE] Received ${chunk.length} bytes`);
        res.write(chunk);
        if (typeof (res as any).flush === "function") (res as any).flush();
      }

      console.log(`[SSE] Stream completed successfully`);
      res.end();
    } catch (err) {
      console.error(`[SSE] Stream error: ${err instanceof Error ? err.message : String(err)}`);
      if (!res.headersSent) {
        res.setHeader("Content-Type", "text/event-stream");
        res.flushHeaders();
      }
      if (!res.writableEnded) {
        const errEvent = JSON.stringify({ type: "error", message: "ML engine unreachable" });
        res.write(`data: ${errEvent}\n\n`);
        res.end();
      }
    }
  })();
};

// ── URL scan (standard JSON, kept as fallback) ────────────────
export const handleUrlScan: RequestHandler = async (req, res) => {
  const { url } = req.body as { url?: string };
  if (!url?.trim()) { res.status(400).json({ error: "URL is required" }); return; }
  try {
    const r = await fetch(`${ML_ENGINE_URL}/analyze/url`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url: url.trim() }),
      signal:  AbortSignal.timeout(60_000),
    });
    const data: ScanResponse = await r.json();
    res.status(r.ok ? 200 : 400).json(data);
  } catch (err) {
    console.error("URL scan error:", err);
    res.status(503).json({
      error: "ML engine unavailable", mode: "url",
      threat_label: "WARNING", risk_level: "medium", category: "Analysis Failed",
      virustotal: { success: false, malicious: 0, suspicious: 0, harmless: 0, undetected: 0, total: 0 },
    } satisfies Partial<ScanResponse>);
  }
};

// ── File scan ────────────────────────────────────────────────
export const handleFileScan: RequestHandler = async (req, res) => {
  const file    = (req as any).file as (Express.Multer.File & { path?: string }) | undefined;
  if (!file) { res.status(400).json({ error: "File is required" }); return; }

  const tmpPath    = (file as any).path as string | undefined;
  const originName = file.originalname ?? "upload";

  try {
    const formData = new FormData();
    if (tmpPath && fs.existsSync(tmpPath)) {
      const fileBytes = fs.readFileSync(tmpPath);
      const blob = new Blob([fileBytes], { type: file.mimetype || "application/octet-stream" });
      formData.append("file", blob, originName);
    } else if (file.buffer) {
      const blob = new Blob([file.buffer], { type: file.mimetype || "application/octet-stream" });
      formData.append("file", blob, originName);
    } else {
      res.status(400).json({ error: "File data missing" }); return;
    }

    const r = await fetch(`${ML_ENGINE_URL}/analyze/file`, {
      method: "POST", body: formData,
      signal: AbortSignal.timeout(FILE_TIMEOUT_MS),
    });
    const data: ScanResponse = await r.json();
    res.status(r.ok ? 200 : 400).json(data);
  } catch (err) {
    console.error("File scan error:", err);
    res.status(503).json({
      error: "ML engine unavailable or scan timed out", mode: "file",
      threat_label: "WARNING", risk_level: "medium", category: "Analysis Failed",
      virustotal: { success: false, malicious: 0, suspicious: 0, harmless: 0, undetected: 0, total: 0 },
    } satisfies Partial<ScanResponse>);
  } finally {
    if (tmpPath) { try { fs.unlinkSync(tmpPath); } catch { /* ignore */ } }
  }
};
