import "dotenv/config";
import express from "express";
import cors from "cors";
import multer from "multer";
import os from "node:os";
import { handleDemo } from "./routes/demo.ts";
import { handleUrlScan, handleUrlScanStream, handleFileScan, handleHealth } from "./routes/scan.ts";

const FILE_SIZE_LIMIT = 15 * 1024 * 1024 * 1024; // 15 GB

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, os.tmpdir()),
    filename:    (_req, file, cb) =>
      cb(null, `atl-upload-${Date.now()}-${file.originalname}`),
  }),
  limits: { fileSize: FILE_SIZE_LIMIT },
});

export function createServer() {
  const app = express();

  app.use(cors({ origin: ["http://localhost:8080", "http://localhost:3001"] }));
  app.use(express.json({ limit: "10mb" }));
  app.use(express.urlencoded({ extended: true, limit: "10mb" }));

  app.get("/api/ping", (_req, res) => {
    res.json({ message: process.env.PING_MESSAGE ?? "ping" });
  });
  app.get("/api/ml/health", handleHealth);

  // SSE streaming scan — used by the live terminal
  app.post("/api/scan/url/stream", handleUrlScanStream);

  // Standard JSON scan — fallback / file
  app.post("/api/scan/url",  handleUrlScan);
  app.post("/api/scan/file", upload.single("file"), handleFileScan);

  app.get("/api/demo", handleDemo);

  return app;
}
