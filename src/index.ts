/**
 * BIShare Relay — Cloudflare Worker + R2 + KV
 *
 * Features:
 *   - Remote File Transfer (16-char share code, E2E encrypted)
 *   - Chunked Upload with R2 Multipart (resume support)
 *   - Remote Rooms (disabled — local-only mode)
 *   - Rate Limiting (per IP + per device)
 *   - Abuse Prevention (volume + rapid + blacklist)
 *   - File Type Scanning (block executables)
 *   - Concurrent Upload Limit (max 3 per device)
 *   - Report Abuse + Admin endpoints
 *   - Cron Cleanup (orphan chunks, expired files)
 *
 * File Transfer endpoints:
 *   POST   /api/upload              Upload encrypted file (single request, <100MB)
 *   POST   /api/upload/init         Init chunked upload (R2 multipart)
 *   PUT    /api/upload/:id/chunk/:i Upload single chunk
 *   POST   /api/upload/:id/complete Complete chunked upload
 *   GET    /api/upload/:id/status   Get upload status (for resume)
 *   DELETE /api/upload/:id          Cancel chunked upload
 *   GET    /api/download/:id        Download encrypted file (streaming)
 *   GET    /api/status/:id          Check file validity
 *   DELETE /api/delete/:id          Revoke file
 *
 * Admin endpoints:
 *   POST   /api/report               Report abuse
 *   GET    /api/admin/reports         View reports (token-protected)
 *   GET    /api/admin/stats           View stats (token-protected)
 */

interface Env {
  BUCKET: R2Bucket;
  ROOMS: KVNamespace;
  MAX_FILE_SIZE: string;
  EXPIRY_HOURS: string;
  ADMIN_TOKEN?: string;
}

// ==================== SHARED ====================

const CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function generateId(length: number): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => CODE_CHARS[b % CODE_CHARS.length])
    .join("");
}

function generateToken(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

const corsHeaders: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Delete-Token, X-Lookup-Id, X-File-Name, X-File-Type, X-File-Id, X-Sender-Alias, X-One-Time, X-Fingerprint, X-Thumbnail, X-File-Size, X-Chunk-Hash, X-Sender-Fingerprint, X-Total-Chunks",
  "Access-Control-Max-Age": "86400",
};

function jsonResponse(data: object, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders },
  });
}

function errorResponse(message: string, status: number, extra?: Record<string, string>): Response {
  const headers: Record<string, string> = { "Content-Type": "application/json", ...corsHeaders };
  if (extra) Object.assign(headers, extra);
  return new Response(JSON.stringify({ success: false, error: message }), { status, headers });
}

// ==================== RATE LIMITING ====================

const RATE_LIMITS = {
  uploadPerIP:     { max: 100, window: 3600 },    // 100 uploads/jam per IP
  uploadPerDevice: { max: 200, window: 86400 },   // 200 uploads/hari per device
  downloadPerIP:   { max: 500, window: 3600 },    // 500 downloads/jam per IP
};

const MAX_CONCURRENT_UPLOADS_PER_DEVICE = 3;

interface RateEntry {
  count: number;
  totalBytes: number;
  firstRequest: number;
}

async function checkRateLimit(
  env: Env, key: string, action: keyof typeof RATE_LIMITS, bytes = 0
): Promise<{ allowed: boolean; retryAfter?: number }> {
  const kvKey = `rate:${key}:${action}`;
  const limit = RATE_LIMITS[action];
  const entry = await env.ROOMS.get<RateEntry>(kvKey, "json");

  if (!entry) {
    await env.ROOMS.put(kvKey, JSON.stringify({
      count: 1, totalBytes: bytes, firstRequest: Date.now()
    }), { expirationTtl: limit.window });
    return { allowed: true };
  }

  const elapsed = (Date.now() - entry.firstRequest) / 1000;
  if (elapsed > limit.window) {
    await env.ROOMS.put(kvKey, JSON.stringify({
      count: 1, totalBytes: bytes, firstRequest: Date.now()
    }), { expirationTtl: limit.window });
    return { allowed: true };
  }

  if (entry.count >= limit.max) {
    return { allowed: false, retryAfter: Math.ceil(limit.window - elapsed) };
  }

  entry.count++;
  entry.totalBytes += bytes;
  await env.ROOMS.put(kvKey, JSON.stringify(entry), {
    expirationTtl: Math.ceil(limit.window - elapsed)
  });
  return { allowed: true };
}

async function checkConcurrent(env: Env, fingerprint: string): Promise<boolean> {
  const count = await env.ROOMS.get<number>(`concurrent:${fingerprint}`, "json") || 0;
  return count < MAX_CONCURRENT_UPLOADS_PER_DEVICE;
}

async function adjustConcurrent(env: Env, fingerprint: string, delta: number) {
  const key = `concurrent:${fingerprint}`;
  const count = (await env.ROOMS.get<number>(key, "json") || 0) + delta;
  if (count <= 0) await env.ROOMS.delete(key);
  else await env.ROOMS.put(key, JSON.stringify(count), { expirationTtl: 3600 });
}

// ==================== ABUSE PREVENTION ====================

const ABUSE_VOLUME_LIMIT = 20 * 1024 * 1024 * 1024; // 20GB/day/IP

async function checkAbuse(env: Env, ip: string, bytes: number): Promise<boolean> {
  // Check blacklist
  if (await env.ROOMS.get(`blacklist:${ip}`)) return false;

  // Check volume
  const volumeKey = `volume:${ip}`;
  const volume = await env.ROOMS.get<{ total: number; since: number }>(volumeKey, "json");
  if (volume && volume.total + bytes > ABUSE_VOLUME_LIMIT) return false;

  // Update
  const newTotal = (volume?.total || 0) + bytes;
  await env.ROOMS.put(volumeKey, JSON.stringify({
    total: newTotal, since: volume?.since || Date.now()
  }), { expirationTtl: 86400 });

  return true;
}

// ==================== FILE TYPE SCANNING ====================

const BLOCKED_EXTENSIONS = [
  ".exe", ".bat", ".cmd", ".scr", ".pif",
  ".msi", ".dll", ".com", ".vbs",
  ".ps1", ".sh", ".bash",
];

const BLOCKED_MIME_TYPES = [
  "application/x-executable",
  "application/x-msdos-program",
  "application/x-msdownload",
];

function isBlockedFile(fileName: string, mimeType: string): boolean {
  const ext = "." + (fileName.split(".").pop()?.toLowerCase() || "");
  return BLOCKED_EXTENSIONS.includes(ext) || BLOCKED_MIME_TYPES.includes(mimeType);
}

// ==================== FILE TRANSFER ====================

interface FileMetadata {
  fileName: string;
  fileType: string;
  fileSize: number;
  senderAlias: string;
  createdAt: string;
  expiresAt: string;
  oneTimeDownload: boolean;
  downloaded: boolean;
  deleteToken: string;
}

function getIp(request: Request): string {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

function getFingerprint(request: Request): string {
  return request.headers.get("X-Sender-Fingerprint") || getIp(request);
}

async function handleUpload(request: Request, env: Env): Promise<Response> {
  const maxSize = parseInt(env.MAX_FILE_SIZE);
  const expiryHours = parseInt(env.EXPIRY_HOURS);
  const contentLength = parseInt(request.headers.get("Content-Length") || "0");
  if (contentLength <= 0) return errorResponse("Empty file", 400);
  if (contentLength > maxSize) return errorResponse(`File too large. Max ${Math.floor(maxSize / 1024 / 1024)}MB`, 413);

  const rawFileName = request.headers.get("X-File-Name") || "unknown";
  const fileName = decodeURIComponent(rawFileName);
  const fileType = request.headers.get("X-File-Type") || "application/octet-stream";
  const senderAlias = request.headers.get("X-Sender-Alias") || "Unknown";
  const oneTime = request.headers.get("X-One-Time") === "true";
  if (!request.body) return errorResponse("No body", 400);

  // File type scanning
  if (isBlockedFile(fileName, fileType)) {
    return errorResponse("File type not allowed", 403);
  }

  // Rate limiting
  const ip = getIp(request);
  const fp = getFingerprint(request);

  const ipCheck = await checkRateLimit(env, ip, "uploadPerIP", contentLength);
  if (!ipCheck.allowed) return errorResponse("Too many uploads. Try again later.", 429, { "Retry-After": String(ipCheck.retryAfter) });

  const devCheck = await checkRateLimit(env, fp, "uploadPerDevice", contentLength);
  if (!devCheck.allowed) return errorResponse("Daily upload limit reached.", 429, { "Retry-After": String(devCheck.retryAfter) });

  // Abuse check
  if (!await checkAbuse(env, ip, contentLength)) return errorResponse("Upload limit exceeded", 429);

  let lookupId = (request.headers.get("X-Lookup-Id") || "").replace(/-/g, "").toUpperCase().substring(0, 6);
  if (lookupId.length < 6) lookupId = generateId(6);
  if (await env.BUCKET.head(`transfers/${lookupId}`)) lookupId = generateId(6);

  const deleteToken = generateToken();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + expiryHours * 3600000);

  const metadata: FileMetadata = {
    fileName, fileType, fileSize: contentLength, senderAlias,
    createdAt: now.toISOString(), expiresAt: expiresAt.toISOString(),
    oneTimeDownload: oneTime, downloaded: false, deleteToken,
  };

  await env.BUCKET.put(`transfers/${lookupId}`, request.body, {
    customMetadata: { meta: JSON.stringify(metadata) },
    httpMetadata: { contentType: "application/octet-stream" },
  });

  return jsonResponse({ success: true, lookupId, expiresAt: expiresAt.toISOString(), deleteToken });
}

// ==================== CHUNKED UPLOAD (R2 MULTIPART) ====================

interface ChunkedUploadState {
  key: string;
  lookupId: string;
  uploadId: string;
  totalChunks: number;
  receivedParts: { partNumber: number; etag: string }[];
  receivedChunks: number[];
  fingerprint: string;
  metadata: FileMetadata;
  createdAt: number;
  lastChunkAt: number;
}

async function handleUploadInit(request: Request, env: Env): Promise<Response> {
  const maxSize = parseInt(env.MAX_FILE_SIZE);
  const expiryHours = parseInt(env.EXPIRY_HOURS);

  const rawFileName = request.headers.get("X-File-Name") || "unknown";
  const fileName = decodeURIComponent(rawFileName);
  const fileType = request.headers.get("X-File-Type") || "application/octet-stream";
  const fileSize = parseInt(request.headers.get("X-File-Size") || "0");
  const senderAlias = request.headers.get("X-Sender-Alias") || "Unknown";
  const oneTime = request.headers.get("X-One-Time") === "true";

  if (fileSize <= 0) return errorResponse("X-File-Size required", 400);
  if (fileSize > maxSize) return errorResponse(`File too large. Max ${Math.floor(maxSize / 1024 / 1024)}MB`, 413);

  // File type scanning
  if (isBlockedFile(fileName, fileType)) {
    return errorResponse("File type not allowed", 403);
  }

  // Rate limiting
  const ip = getIp(request);
  const fp = getFingerprint(request);

  const ipCheck = await checkRateLimit(env, ip, "uploadPerIP", fileSize);
  if (!ipCheck.allowed) return errorResponse("Too many uploads. Try again later.", 429, { "Retry-After": String(ipCheck.retryAfter) });

  const devCheck = await checkRateLimit(env, fp, "uploadPerDevice", fileSize);
  if (!devCheck.allowed) return errorResponse("Daily upload limit reached.", 429, { "Retry-After": String(devCheck.retryAfter) });

  // Concurrent limit
  if (!await checkConcurrent(env, fp)) {
    return errorResponse("Too many concurrent uploads (max 3)", 429);
  }

  // Abuse check
  if (!await checkAbuse(env, ip, fileSize)) return errorResponse("Upload limit exceeded", 429);

  // Chunk size — client decides, relay just validates minimum
  const clientChunks = parseInt(request.headers.get("X-Total-Chunks") || "0");
  let chunkSize: number;
  let totalChunks: number;
  if (clientChunks > 0) {
    // Client specifies chunk count — trust it
    totalChunks = clientChunks;
    chunkSize = Math.ceil(fileSize / totalChunks);
  } else {
    // Fallback: relay calculates
    chunkSize = fileSize < 500_000_000 ? 50_000_000 : 100_000_000;
    if (chunkSize < 5_000_000) chunkSize = 5_000_000;
    totalChunks = Math.ceil(fileSize / chunkSize);
  }

  // Generate lookup ID
  let lookupId = (request.headers.get("X-Lookup-Id") || "").replace(/-/g, "").toUpperCase().substring(0, 6);
  if (lookupId.length < 6) lookupId = generateId(6);
  if (await env.BUCKET.head(`transfers/${lookupId}`)) lookupId = generateId(6);

  const key = `transfers/${lookupId}`;
  const deleteToken = generateToken();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + expiryHours * 3600000);

  // Create R2 multipart upload
  const multipart = await env.BUCKET.createMultipartUpload(key, {
    httpMetadata: { contentType: "application/octet-stream" },
    customMetadata: {
      meta: JSON.stringify({
        fileName, fileType, fileSize, senderAlias,
        createdAt: now.toISOString(), expiresAt: expiresAt.toISOString(),
        oneTimeDownload: oneTime, downloaded: false, deleteToken,
      } as FileMetadata)
    },
  });

  const metadata: FileMetadata = {
    fileName, fileType, fileSize, senderAlias,
    createdAt: now.toISOString(), expiresAt: expiresAt.toISOString(),
    oneTimeDownload: oneTime, downloaded: false, deleteToken,
  };

  // Store upload state in KV
  const state: ChunkedUploadState = {
    key, lookupId, uploadId: multipart.uploadId,
    totalChunks, receivedParts: [], receivedChunks: [],
    fingerprint: fp, metadata, createdAt: Date.now(), lastChunkAt: Date.now(),
  };
  await env.ROOMS.put(`upload:${multipart.uploadId}`, JSON.stringify(state), { expirationTtl: 86400 });

  // Track concurrent
  await adjustConcurrent(env, fp, 1);

  return jsonResponse({
    success: true, uploadId: multipart.uploadId, lookupId, chunkSize, totalChunks,
    expiresAt: expiresAt.toISOString(), deleteToken,
  });
}

async function handleUploadChunk(request: Request, env: Env, uploadId: string, index: number): Promise<Response> {
  const state = await env.ROOMS.get<ChunkedUploadState>(`upload:${uploadId}`, "json");
  if (!state) return errorResponse("Upload not found or expired", 404);

  // Already uploaded this chunk?
  if (state.receivedChunks.includes(index)) {
    return jsonResponse({
      received: state.receivedChunks.length,
      total: state.totalChunks,
      complete: state.receivedChunks.length === state.totalChunks,
      duplicate: true,
    });
  }

  const body = await request.arrayBuffer();

  // Verify chunk integrity via SHA-256
  const chunkHash = request.headers.get("X-Chunk-Hash");
  if (chunkHash) {
    const hash = await crypto.subtle.digest("SHA-256", body);
    const hex = [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
    if (hex !== chunkHash.toLowerCase()) return errorResponse("Chunk hash mismatch", 400);
  }

  // Upload part via R2 multipart API (parts are 1-indexed)
  const multipart = env.BUCKET.resumeMultipartUpload(state.key, uploadId);
  const part = await multipart.uploadPart(index + 1, body);

  // Track
  state.receivedParts.push({ partNumber: index + 1, etag: part.etag });
  state.receivedChunks.push(index);
  state.lastChunkAt = Date.now();
  await env.ROOMS.put(`upload:${uploadId}`, JSON.stringify(state), { expirationTtl: 86400 });

  return jsonResponse({
    received: state.receivedChunks.length,
    total: state.totalChunks,
    complete: state.receivedChunks.length === state.totalChunks,
    verified: !!chunkHash,
  });
}

async function handleUploadComplete(request: Request, env: Env, uploadId: string): Promise<Response> {
  const state = await env.ROOMS.get<ChunkedUploadState>(`upload:${uploadId}`, "json");
  if (!state) return errorResponse("Upload not found", 404);

  if (state.receivedChunks.length !== state.totalChunks) {
    return errorResponse(`Missing chunks: ${state.totalChunks - state.receivedChunks.length} remaining`, 400);
  }

  // R2 merges all parts internally — zero CPU cost
  const multipart = env.BUCKET.resumeMultipartUpload(state.key, uploadId);
  await multipart.complete(
    state.receivedParts.sort((a, b) => a.partNumber - b.partNumber)
  );

  // Cleanup
  await env.ROOMS.delete(`upload:${uploadId}`);
  await adjustConcurrent(env, state.fingerprint, -1);

  return jsonResponse({
    success: true,
    lookupId: state.lookupId,
    expiresAt: state.metadata.expiresAt,
    deleteToken: state.metadata.deleteToken,
  });
}

async function handleUploadStatus(env: Env, uploadId: string): Promise<Response> {
  const state = await env.ROOMS.get<ChunkedUploadState>(`upload:${uploadId}`, "json");
  if (!state) return errorResponse("Upload not found", 404);

  return jsonResponse({
    uploadId: state.uploadId,
    lookupId: state.lookupId,
    totalChunks: state.totalChunks,
    receivedChunks: state.receivedChunks,
    complete: state.receivedChunks.length === state.totalChunks,
  });
}

async function handleUploadCancel(request: Request, env: Env, uploadId: string): Promise<Response> {
  const state = await env.ROOMS.get<ChunkedUploadState>(`upload:${uploadId}`, "json");
  if (!state) return errorResponse("Upload not found", 404);

  // Abort R2 multipart — cleans up all uploaded parts
  try {
    const multipart = env.BUCKET.resumeMultipartUpload(state.key, uploadId);
    await multipart.abort();
  } catch { /* already cleaned up */ }

  await env.ROOMS.delete(`upload:${uploadId}`);
  await adjustConcurrent(env, state.fingerprint, -1);

  return jsonResponse({ success: true, message: "Upload cancelled" });
}

// ==================== DOWNLOAD (STREAMING) ====================

async function handleDownload(id: string, env: Env): Promise<Response> {
  const cleanId = id.replace(/-/g, "").toUpperCase().substring(0, 6);
  const object = await env.BUCKET.get(`transfers/${cleanId}`);
  if (!object) return errorResponse("Code not found or expired", 404);

  let metadata: FileMetadata;
  try {
    metadata = JSON.parse(object.customMetadata?.meta || "{}");
  } catch {
    // Metadata corrupt — still serve the file with defaults
    metadata = {
      fileName: "unknown", fileType: "application/octet-stream",
      fileSize: object.size, senderAlias: "Unknown",
      createdAt: "", expiresAt: new Date(Date.now() + 86400000).toISOString(),
      oneTimeDownload: false, downloaded: false, deleteToken: "",
    };
  }

  if (metadata.expiresAt && new Date() > new Date(metadata.expiresAt)) {
    await env.BUCKET.delete(`transfers/${cleanId}`);
    return errorResponse("Code expired", 410);
  }
  if (metadata.oneTimeDownload) {
    // Check KV flag (set during first download)
    const alreadyDownloaded = await env.ROOMS.get(`downloaded:${cleanId}`);
    if (alreadyDownloaded || metadata.downloaded) {
      await env.BUCKET.delete(`transfers/${cleanId}`);
      return errorResponse("Already downloaded (one-time use)", 410);
    }
  }

  const headers = new Headers(corsHeaders);
  headers.set("Content-Type", "application/octet-stream");
  headers.set("Content-Length", String(metadata.fileSize || object.size));
  headers.set("X-File-Name", metadata.fileName || "unknown");
  headers.set("X-File-Type", metadata.fileType || "application/octet-stream");
  headers.set("X-Sender-Alias", metadata.senderAlias || "Unknown");
  if (metadata.expiresAt) headers.set("X-Expires-At", metadata.expiresAt);

  if (metadata.oneTimeDownload) {
    // Don't delete now — body stream needs to complete first.
    // Mark as downloaded in KV (lightweight). Cron will delete the R2 object later.
    await env.ROOMS.put(`downloaded:${cleanId}`, "true", { expirationTtl: 86400 });
  }

  return new Response(object.body, { status: 200, headers });
}

async function handleStatus(id: string, env: Env): Promise<Response> {
  const cleanId = id.replace(/-/g, "").toUpperCase().substring(0, 6);
  const object = await env.BUCKET.head(`transfers/${cleanId}`);
  if (!object) return errorResponse("Code not found or expired", 404);

  const metadata: FileMetadata = JSON.parse(object.customMetadata?.meta || "{}");
  if (new Date() > new Date(metadata.expiresAt)) {
    await env.BUCKET.delete(`transfers/${cleanId}`);
    return errorResponse("Code expired", 410);
  }

  return jsonResponse({
    success: true, fileName: metadata.fileName, fileType: metadata.fileType,
    fileSize: metadata.fileSize, senderAlias: metadata.senderAlias,
    expiresAt: metadata.expiresAt, oneTimeDownload: metadata.oneTimeDownload,
  });
}

async function handleFileDelete(id: string, request: Request, env: Env): Promise<Response> {
  const cleanId = id.replace(/-/g, "").toUpperCase().substring(0, 6);
  const object = await env.BUCKET.head(`transfers/${cleanId}`);
  if (!object) return errorResponse("Code not found", 404);
  const metadata: FileMetadata = JSON.parse(object.customMetadata?.meta || "{}");
  if (metadata.deleteToken !== (request.headers.get("X-Delete-Token") || "")) return errorResponse("Invalid delete token", 403);
  await env.BUCKET.delete(`transfers/${cleanId}`);
  return jsonResponse({ success: true, message: "File deleted" });
}

// ==================== REPORT ABUSE ====================

async function handleReport(request: Request, env: Env): Promise<Response> {
  const body = await request.json<{ code?: string; reason?: string; reporterEmail?: string }>();
  if (!body.code || !body.reason) return errorResponse("code and reason required", 400);

  const reportId = generateId(8);
  await env.ROOMS.put(`report:${reportId}`, JSON.stringify({
    ...body, reportId, reportedAt: new Date().toISOString(), ip: getIp(request),
  }), { expirationTtl: 30 * 86400 }); // Keep 30 days

  return jsonResponse({ success: true, reportId, status: "received" });
}

async function handleAdminStats(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const token = url.searchParams.get("token");
  if (!env.ADMIN_TOKEN || token !== env.ADMIN_TOKEN) return errorResponse("Unauthorized", 401);

  // Basic stats from R2
  const transfers = await env.BUCKET.list({ prefix: "transfers/", limit: 1000 });
  let totalSize = 0;
  for (const obj of transfers.objects) totalSize += obj.size;

  return jsonResponse({
    activeFiles: transfers.objects.length,
    totalStorageBytes: totalSize,
    service: "bishare-relay",
    version: "4.0.0",
  });
}

async function handleAdminReports(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const token = url.searchParams.get("token");
  if (!env.ADMIN_TOKEN || token !== env.ADMIN_TOKEN) return errorResponse("Unauthorized", 401);

  const list = await env.ROOMS.list({ prefix: "report:" });
  const reports = [];
  for (const key of list.keys) {
    const report = await env.ROOMS.get(key.name, "json");
    if (report) reports.push(report);
  }

  return jsonResponse({ success: true, reports });
}

// ==================== (Rooms removed — local-only mode) ====================



// ==================== CRON CLEANUP ====================

async function handleScheduled(env: Env) {
  // 1. Cleanup expired transfers (paginated — R2 list returns max 1000 per call)
  let transferCursor: string | undefined;
  let deletedTransfers = 0;
  do {
    const transfers = await env.BUCKET.list({
      prefix: "transfers/",
      limit: 500,
      cursor: transferCursor,
    });
    for (const obj of transfers.objects) {
      const meta = await env.BUCKET.head(obj.key);
      if (!meta?.customMetadata?.meta) continue;
      try {
        const metadata: FileMetadata = JSON.parse(meta.customMetadata.meta);
        const expired = new Date(metadata.expiresAt) < new Date();
        const lookupId = obj.key.replace("transfers/", "");
        const kvDownloaded = await env.ROOMS.get(`downloaded:${lookupId}`);
        const downloaded = metadata.oneTimeDownload && (metadata.downloaded || !!kvDownloaded);
        if (expired || downloaded) {
          if (kvDownloaded) await env.ROOMS.delete(`downloaded:${lookupId}`);
          await env.BUCKET.delete(obj.key);
          deletedTransfers++;
        }
      } catch { /* skip malformed */ }
    }
    transferCursor = transfers.truncated ? transfers.cursor : undefined;
  } while (transferCursor);

  // 2. Cleanup orphan chunked uploads (>1h idle or >24h old, paginated)
  let uploadCursor: string | undefined;
  let abortedUploads = 0;
  do {
    const uploads = await env.ROOMS.list({ prefix: "upload:", cursor: uploadCursor, limit: 500 });
    for (const key of uploads.keys) {
      const state = await env.ROOMS.get<ChunkedUploadState>(key.name, "json");
      if (!state) continue;
      const age = Date.now() - state.createdAt;
      const idle = Date.now() - (state.lastChunkAt || state.createdAt);
      if (age > 24 * 3600 * 1000 || idle > 1 * 3600 * 1000) {
        try {
          const multipart = env.BUCKET.resumeMultipartUpload(state.key, state.uploadId);
          await multipart.abort();
        } catch { /* already cleaned */ }
        await env.ROOMS.delete(key.name);
        await adjustConcurrent(env, state.fingerprint, -1);
        abortedUploads++;
      }
    }
    uploadCursor = uploads.list_complete ? undefined : uploads.cursor;
  } while (uploadCursor);

}

// ==================== ROUTER ====================

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // --- File Transfer (single upload) ---
      if (path === "/api/upload" && request.method === "POST") return await handleUpload(request, env);

      // --- Chunked Upload ---
      if (path === "/api/upload/init" && request.method === "POST") return await handleUploadInit(request, env);

      const chunkMatch = path.match(/^\/api\/upload\/(.+)\/chunk\/(\d+)$/);
      if (chunkMatch && request.method === "PUT") return await handleUploadChunk(request, env, chunkMatch[1], parseInt(chunkMatch[2]));

      const completeMatch = path.match(/^\/api\/upload\/(.+)\/complete$/);
      if (completeMatch && request.method === "POST") return await handleUploadComplete(request, env, completeMatch[1]);

      const uploadStatusMatch = path.match(/^\/api\/upload\/(.+)\/status$/);
      if (uploadStatusMatch && request.method === "GET") return await handleUploadStatus(env, uploadStatusMatch[1]);

      // Cancel: DELETE /api/upload/:uploadId (uploadId can contain dots, slashes etc)
      if (request.method === "DELETE" && path.startsWith("/api/upload/") && path !== "/api/upload/init") {
        const uploadId = path.substring("/api/upload/".length);
        if (uploadId.length > 0) return await handleUploadCancel(request, env, uploadId);
      }

      // --- Download ---
      const dlMatch = path.match(/^\/api\/download\/([A-Za-z0-9-]+)$/);
      if (dlMatch && request.method === "GET") return await handleDownload(dlMatch[1], env);

      const statusMatch = path.match(/^\/api\/status\/([A-Za-z0-9-]+)$/);
      if (statusMatch && request.method === "GET") return await handleStatus(statusMatch[1], env);

      const delMatch = path.match(/^\/api\/delete\/([A-Za-z0-9-]+)$/);
      if (delMatch && request.method === "DELETE") return await handleFileDelete(delMatch[1], request, env);

      // --- Report ---
      if (path === "/api/report" && request.method === "POST") return await handleReport(request, env);

      // --- Admin ---
      if (path === "/api/admin/stats" && request.method === "GET") return await handleAdminStats(request, env);
      if (path === "/api/admin/reports" && request.method === "GET") return await handleAdminReports(request, env);
      if (path === "/api/admin/cleanup" && request.method === "POST") {
        ctx.waitUntil(handleScheduled(env));
        return jsonResponse({ success: true, message: "Cleanup triggered" });
      }
      // Force abort a specific multipart upload by key + uploadId
      if (path === "/api/admin/abort-multipart" && request.method === "POST") {
        const body = await request.json<{ key: string; uploadId: string }[]>();
        let aborted = 0;
        for (const item of body) {
          try {
            const mp = env.BUCKET.resumeMultipartUpload(item.key, item.uploadId);
            await mp.abort();
            aborted++;
          } catch { /* skip */ }
        }
        // Also abort all tracked in KV
        const kvList = await env.ROOMS.list({ prefix: "upload:" });
        for (const k of kvList.keys) {
          const state = await env.ROOMS.get<ChunkedUploadState>(k.name, "json");
          if (!state) continue;
          try {
            const mp = env.BUCKET.resumeMultipartUpload(state.key, state.uploadId);
            await mp.abort();
            aborted++;
          } catch { /* skip */ }
          await env.ROOMS.delete(k.name);
          await adjustConcurrent(env, state.fingerprint, -1);
        }
        return jsonResponse({ success: true, aborted });
      }

      // Health
      if (path === "/api/health") return jsonResponse({ status: "ok", service: "bishare-relay", version: "4.0.0" });

      return errorResponse("Not found", 404);
    } catch (e: any) {
      return errorResponse(e?.message || "Internal error", 500);
    }
  },

  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(handleScheduled(env));
  },
};
