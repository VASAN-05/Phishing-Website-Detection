import path from "node:path";
import "dotenv/config";
import * as express$1 from "express";
import express from "express";
import cors from "cors";
import multer from "multer";
import os from "node:os";
import fs from "node:fs";
//#region server/routes/demo.ts
var handleDemo = (req, res) => {
	res.status(200).json({ message: "Hello from Express server" });
};
//#endregion
//#region server/routes/scan.ts
var ML_ENGINE_URL = process.env.ML_ENGINE_URL ?? "http://localhost:5001";
var FILE_TIMEOUT_MS = 1800 * 1e3;
var handleHealth = async (_req, res) => {
	try {
		const data = await (await fetch(`${ML_ENGINE_URL}/health`, { signal: AbortSignal.timeout(5e3) })).json();
		res.json(data);
	} catch {
		res.status(503).json({
			status: "unavailable",
			error: "ML engine unreachable"
		});
	}
};
var handleUrlScanStream = (req, res) => {
	const { url } = req.body;
	if (!url?.trim()) {
		res.status(400).json({ error: "URL is required" });
		return;
	}
	const body = JSON.stringify({ url: url.trim() });
	res.setHeader("Content-Type", "text/event-stream");
	res.setHeader("Cache-Control", "no-cache");
	res.setHeader("Connection", "keep-alive");
	res.setHeader("X-Accel-Buffering", "no");
	res.flushHeaders();
	(async () => {
		try {
			console.log(`[SSE] Starting stream to ${ML_ENGINE_URL}/analyze/url/stream`);
			const fetchRes = await fetch(`${ML_ENGINE_URL}/analyze/url/stream`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body,
				signal: AbortSignal.timeout(3e5)
			});
			if (!fetchRes.ok || !fetchRes.body) throw new Error(`ML engine returned ${fetchRes.status}`);
			console.log(`[SSE] Connected to ML engine, streaming response`);
			const reader = fetchRes.body.getReader();
			const decoder = new TextDecoder();
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				const chunk = decoder.decode(value, { stream: true });
				console.log(`[SSE] Received ${chunk.length} bytes`);
				res.write(chunk);
				if (typeof res.flush === "function") res.flush();
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
				const errEvent = JSON.stringify({
					type: "error",
					message: "ML engine unreachable"
				});
				res.write(`data: ${errEvent}\n\n`);
				res.end();
			}
		}
	})();
};
var handleUrlScan = async (req, res) => {
	const { url } = req.body;
	if (!url?.trim()) {
		res.status(400).json({ error: "URL is required" });
		return;
	}
	try {
		const r = await fetch(`${ML_ENGINE_URL}/analyze/url`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ url: url.trim() }),
			signal: AbortSignal.timeout(6e4)
		});
		const data = await r.json();
		res.status(r.ok ? 200 : 400).json(data);
	} catch (err) {
		console.error("URL scan error:", err);
		res.status(503).json({
			error: "ML engine unavailable",
			mode: "url",
			threat_label: "WARNING",
			risk_level: "medium",
			category: "Analysis Failed",
			virustotal: {
				success: false,
				malicious: 0,
				suspicious: 0,
				harmless: 0,
				undetected: 0,
				total: 0
			}
		});
	}
};
var handleFileScan = async (req, res) => {
	const file = req.file;
	if (!file) {
		res.status(400).json({ error: "File is required" });
		return;
	}
	const tmpPath = file.path;
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
			res.status(400).json({ error: "File data missing" });
			return;
		}
		const r = await fetch(`${ML_ENGINE_URL}/analyze/file`, {
			method: "POST",
			body: formData,
			signal: AbortSignal.timeout(FILE_TIMEOUT_MS)
		});
		const data = await r.json();
		res.status(r.ok ? 200 : 400).json(data);
	} catch (err) {
		console.error("File scan error:", err);
		res.status(503).json({
			error: "ML engine unavailable or scan timed out",
			mode: "file",
			threat_label: "WARNING",
			risk_level: "medium",
			category: "Analysis Failed",
			virustotal: {
				success: false,
				malicious: 0,
				suspicious: 0,
				harmless: 0,
				undetected: 0,
				total: 0
			}
		});
	} finally {
		if (tmpPath) try {
			fs.unlinkSync(tmpPath);
		} catch {}
	}
};
//#endregion
//#region server/index.ts
var upload = multer({
	storage: multer.diskStorage({
		destination: (_req, _file, cb) => cb(null, os.tmpdir()),
		filename: (_req, file, cb) => cb(null, `atl-upload-${Date.now()}-${file.originalname}`)
	}),
	limits: { fileSize: 15 * 1024 * 1024 * 1024 }
});
function createServer() {
	const app = express();
	app.use(cors({ origin: ["http://localhost:8080", "http://localhost:3001"] }));
	app.use(express.json({ limit: "10mb" }));
	app.use(express.urlencoded({
		extended: true,
		limit: "10mb"
	}));
	app.get("/api/ping", (_req, res) => {
		res.json({ message: process.env.PING_MESSAGE ?? "ping" });
	});
	app.get("/api/ml/health", handleHealth);
	app.post("/api/scan/url/stream", handleUrlScanStream);
	app.post("/api/scan/url", handleUrlScan);
	app.post("/api/scan/file", upload.single("file"), handleFileScan);
	app.get("/api/demo", handleDemo);
	return app;
}
//#endregion
//#region server/node-build.ts
var app = createServer();
var port = process.env.PORT || 3e3;
var __dirname = import.meta.dirname;
var distPath = path.join(__dirname, "../spa");
app.use(express$1.static(distPath));
app.get("*", (req, res) => {
	if (req.path.startsWith("/api/") || req.path.startsWith("/health")) return res.status(404).json({ error: "API endpoint not found" });
	res.sendFile(path.join(distPath, "index.html"));
});
app.listen(port, () => {
	console.log(`🚀 Fusion Starter server running on port ${port}`);
	console.log(`📱 Frontend: http://localhost:${port}`);
	console.log(`🔧 API: http://localhost:${port}/api`);
});
process.on("SIGTERM", () => {
	console.log("🛑 Received SIGTERM, shutting down gracefully");
	process.exit(0);
});
process.on("SIGINT", () => {
	console.log("🛑 Received SIGINT, shutting down gracefully");
	process.exit(0);
});
//#endregion
export {};

//# sourceMappingURL=node-build.mjs.map