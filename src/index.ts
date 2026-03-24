/**
 * BIShare Relay — Cloudflare Worker + R2
 *
 * Remote file transfer via 16-character code.
 * Files are E2E encrypted on-device before upload.
 * Server never sees plaintext — only ciphertext.
 *
 * Code format: ABCX-9K2M-P4HN-7RVW (16 chars)
 *   - First 6 chars = server lookup ID
 *   - Full 16 chars = used to derive AES-256 encryption key on device
 *   - Server only knows the 6-char lookup ID, NOT the full code
 *
 * Endpoints:
 *   POST   /api/upload          Upload encrypted file, returns 6-char lookup ID
 *   GET    /api/download/:id    Download encrypted file
 *   GET    /api/status/:id      Check validity, file info
 *   DELETE /api/delete/:id      Revoke file (needs delete token)
 */

interface Env {
  BUCKET: R2Bucket;
  MAX_FILE_SIZE: string;
  EXPIRY_HOURS: string;
}

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

// --- Code Generation ---

const CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no I, O, 0, 1

function generateLookupId(length: number): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => CODE_CHARS[b % CODE_CHARS.length])
    .join("");
}

function generateDeleteToken(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// --- CORS ---

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Delete-Token",
  "Access-Control-Max-Age": "86400",
};

function jsonResponse(data: object, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders },
  });
}

function errorResponse(message: string, status: number): Response {
  return jsonResponse({ success: false, error: message }, status);
}

// --- Handlers ---

async function handleUpload(request: Request, env: Env): Promise<Response> {
  const maxSize = parseInt(env.MAX_FILE_SIZE);
  const expiryHours = parseInt(env.EXPIRY_HOURS);

  // Validate content length
  const contentLength = parseInt(request.headers.get("Content-Length") || "0");
  if (contentLength <= 0) {
    return errorResponse("Empty file", 400);
  }
  if (contentLength > maxSize) {
    return errorResponse(`File too large. Max ${maxSize / 1024 / 1024}MB`, 413);
  }

  // Read metadata from headers
  const fileName = request.headers.get("X-File-Name") || "unknown";
  const fileType = request.headers.get("X-File-Type") || "application/octet-stream";
  const senderAlias = request.headers.get("X-Sender-Alias") || "Unknown";
  const oneTime = request.headers.get("X-One-Time") === "true";

  if (!request.body) {
    return errorResponse("No body", 400);
  }

  // Use client-provided lookup ID (first 6 chars of share code) or generate one
  let lookupId = (request.headers.get("X-Lookup-Id") || "").replace(/-/g, "").toUpperCase().substring(0, 6);
  if (lookupId.length < 6) {
    lookupId = generateLookupId(6);
  }
  // Check collision — if exists, append random char
  const existing = await env.BUCKET.head(`transfers/${lookupId}`);
  if (existing) {
    lookupId = generateLookupId(6);
  }

  const deleteToken = generateDeleteToken();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + expiryHours * 60 * 60 * 1000);

  const metadata: FileMetadata = {
    fileName,
    fileType,
    fileSize: contentLength,
    senderAlias,
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    oneTimeDownload: oneTime,
    downloaded: false,
    deleteToken,
  };

  // Stream body directly to R2 (no buffering in Worker memory)
  await env.BUCKET.put(`transfers/${lookupId}`, request.body, {
    customMetadata: {
      meta: JSON.stringify(metadata),
    },
    httpMetadata: {
      contentType: "application/octet-stream",
    },
  });

  return jsonResponse({
    success: true,
    lookupId,
    expiresAt: expiresAt.toISOString(),
    deleteToken,
  });
}

async function handleDownload(id: string, env: Env, _ctx: ExecutionContext): Promise<Response> {
  const cleanId = id.replace(/-/g, "").toUpperCase().substring(0, 6);

  const object = await env.BUCKET.get(`transfers/${cleanId}`);
  if (!object) {
    return errorResponse("Code not found or expired", 404);
  }

  const metaStr = object.customMetadata?.meta;
  if (!metaStr) {
    return errorResponse("Invalid file metadata", 500);
  }

  const metadata: FileMetadata = JSON.parse(metaStr);

  // Check expiry
  if (new Date() > new Date(metadata.expiresAt)) {
    await env.BUCKET.delete(`transfers/${cleanId}`);
    return errorResponse("Code expired", 410);
  }

  // Check one-time download
  if (metadata.oneTimeDownload && metadata.downloaded) {
    await env.BUCKET.delete(`transfers/${cleanId}`);
    return errorResponse("Already downloaded (one-time use)", 410);
  }

  // For one-time downloads: read body into memory first, then delete from R2 immediately
  // This prevents race conditions where a second download sneaks in before deletion
  let body: ReadableStream | ArrayBuffer;
  if (metadata.oneTimeDownload) {
    body = await object.arrayBuffer();
    await env.BUCKET.delete(`transfers/${cleanId}`);
  } else {
    body = object.body;
  }

  const headers = new Headers(corsHeaders);
  headers.set("Content-Type", "application/octet-stream");
  headers.set("Content-Length", metadata.fileSize.toString());
  headers.set("X-File-Name", metadata.fileName);
  headers.set("X-File-Type", metadata.fileType);
  headers.set("X-Sender-Alias", metadata.senderAlias);
  headers.set("X-Expires-At", metadata.expiresAt);

  return new Response(body, { status: 200, headers });
}

async function handleStatus(id: string, env: Env): Promise<Response> {
  const cleanId = id.replace(/-/g, "").toUpperCase().substring(0, 6);

  const object = await env.BUCKET.head(`transfers/${cleanId}`);
  if (!object) {
    return errorResponse("Code not found or expired", 404);
  }

  const metaStr = object.customMetadata?.meta;
  if (!metaStr) {
    return errorResponse("Invalid metadata", 500);
  }

  const metadata: FileMetadata = JSON.parse(metaStr);

  // Check expiry
  if (new Date() > new Date(metadata.expiresAt)) {
    await env.BUCKET.delete(`transfers/${cleanId}`);
    return errorResponse("Code expired", 410);
  }

  return jsonResponse({
    success: true,
    fileName: metadata.fileName,
    fileType: metadata.fileType,
    fileSize: metadata.fileSize,
    senderAlias: metadata.senderAlias,
    expiresAt: metadata.expiresAt,
    oneTimeDownload: metadata.oneTimeDownload,
  });
}

async function handleDelete(
  id: string,
  request: Request,
  env: Env
): Promise<Response> {
  const cleanId = id.replace(/-/g, "").toUpperCase().substring(0, 6);
  const deleteToken = request.headers.get("X-Delete-Token") || "";

  const object = await env.BUCKET.head(`transfers/${cleanId}`);
  if (!object) {
    return errorResponse("Code not found", 404);
  }

  const metaStr = object.customMetadata?.meta;
  if (!metaStr) {
    return errorResponse("Invalid metadata", 500);
  }

  const metadata: FileMetadata = JSON.parse(metaStr);

  if (metadata.deleteToken !== deleteToken) {
    return errorResponse("Invalid delete token", 403);
  }

  await env.BUCKET.delete(`transfers/${cleanId}`);

  return jsonResponse({ success: true, message: "File deleted" });
}

// --- Router ---

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // POST /api/upload
    if (path === "/api/upload" && request.method === "POST") {
      return handleUpload(request, env);
    }

    // GET /api/download/:id
    const downloadMatch = path.match(/^\/api\/download\/([A-Za-z0-9-]+)$/);
    if (downloadMatch && request.method === "GET") {
      return handleDownload(downloadMatch[1], env, ctx);
    }

    // GET /api/status/:id
    const statusMatch = path.match(/^\/api\/status\/([A-Za-z0-9-]+)$/);
    if (statusMatch && request.method === "GET") {
      return handleStatus(statusMatch[1], env);
    }

    // DELETE /api/delete/:id
    const deleteMatch = path.match(/^\/api\/delete\/([A-Za-z0-9-]+)$/);
    if (deleteMatch && request.method === "DELETE") {
      return handleDelete(deleteMatch[1], request, env);
    }

    // Health check
    if (path === "/api/health") {
      return jsonResponse({
        status: "ok",
        service: "bishare-relay",
        version: "2.0.0",
      });
    }

    return errorResponse("Not found", 404);
  },
};
