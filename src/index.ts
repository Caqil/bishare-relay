/**
 * BIShare Relay — Cloudflare Worker + R2 + KV
 *
 * 1. Remote File Transfer (via 16-char share code)
 * 2. Remote Rooms (via 4-char room code, polling-based)
 *
 * File Transfer endpoints:
 *   POST   /api/upload          Upload encrypted file
 *   GET    /api/download/:id    Download encrypted file
 *   GET    /api/status/:id      Check validity
 *   DELETE /api/delete/:id      Revoke file
 *
 * Room endpoints:
 *   POST   /api/room/create           Create a new room
 *   POST   /api/room/join/:code       Join a room
 *   GET    /api/room/info/:code       Get room info
 *   GET    /api/room/poll/:code       Poll for updates (members, files, events)
 *   POST   /api/room/file/:code       Upload file to room
 *   GET    /api/room/file/:code/:id   Download room file
 *   POST   /api/room/leave/:code      Leave room
 *   DELETE /api/room/:code            Close room (host)
 */

interface Env {
  BUCKET: R2Bucket;
  ROOMS: KVNamespace;
  MAX_FILE_SIZE: string;
  EXPIRY_HOURS: string;
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

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Delete-Token, X-Lookup-Id, X-File-Name, X-File-Type, X-File-Id, X-Sender-Alias, X-One-Time, X-Fingerprint, X-Thumbnail",
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

async function handleUpload(request: Request, env: Env): Promise<Response> {
  const maxSize = parseInt(env.MAX_FILE_SIZE);
  const expiryHours = parseInt(env.EXPIRY_HOURS);
  const contentLength = parseInt(request.headers.get("Content-Length") || "0");
  if (contentLength <= 0) return errorResponse("Empty file", 400);
  if (contentLength > maxSize) return errorResponse(`File too large. Max ${maxSize / 1024 / 1024}MB`, 413);

  const fileName = request.headers.get("X-File-Name") || "unknown";
  const fileType = request.headers.get("X-File-Type") || "application/octet-stream";
  const senderAlias = request.headers.get("X-Sender-Alias") || "Unknown";
  const oneTime = request.headers.get("X-One-Time") === "true";
  if (!request.body) return errorResponse("No body", 400);

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

async function handleDownload(id: string, env: Env): Promise<Response> {
  const cleanId = id.replace(/-/g, "").toUpperCase().substring(0, 6);
  const object = await env.BUCKET.get(`transfers/${cleanId}`);
  if (!object) return errorResponse("Code not found or expired", 404);

  const metadata: FileMetadata = JSON.parse(object.customMetadata?.meta || "{}");
  if (new Date() > new Date(metadata.expiresAt)) {
    await env.BUCKET.delete(`transfers/${cleanId}`);
    return errorResponse("Code expired", 410);
  }
  if (metadata.oneTimeDownload && metadata.downloaded) {
    await env.BUCKET.delete(`transfers/${cleanId}`);
    return errorResponse("Already downloaded (one-time use)", 410);
  }

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

// ==================== ROOMS ====================

interface RoomState {
  code: string;
  hostAlias: string;
  hostFingerprint: string;
  hostToken: string; // secret token for host operations
  createdAt: string;
  members: RoomMemberState[];
  files: RoomFileState[];
  events: RoomEvent[];
  lastActivity: string;
}

interface RoomMemberState {
  fingerprint: string;
  alias: string;
  deviceType: string;
  joinedAt: string;
}

interface RoomFileState {
  id: string;
  fileName: string;
  fileType: string;
  size: number;
  ownerAlias: string;
  ownerFingerprint: string;
  addedAt: string;
  thumbnail?: string; // base64 JPEG thumbnail for images/videos
}

interface RoomEvent {
  type: "member_joined" | "member_left" | "file_added" | "room_closed";
  timestamp: string;
  data: Record<string, string>;
}

const ROOM_EXPIRY_HOURS = 24;

async function getRoom(code: string, env: Env): Promise<RoomState | null> {
  const data = await env.ROOMS.get(`room:${code.toUpperCase()}`);
  if (!data) return null;
  const room: RoomState = JSON.parse(data);
  // Check expiry
  if (new Date() > new Date(new Date(room.createdAt).getTime() + ROOM_EXPIRY_HOURS * 3600000)) {
    await cleanupRoom(code, env);
    return null;
  }
  return room;
}

async function saveRoom(room: RoomState, env: Env): Promise<void> {
  room.lastActivity = new Date().toISOString();
  // Keep only last 50 events
  if (room.events.length > 50) room.events = room.events.slice(-50);
  await env.ROOMS.put(`room:${room.code}`, JSON.stringify(room), {
    expirationTtl: ROOM_EXPIRY_HOURS * 3600,
  });
}

async function cleanupRoom(code: string, env: Env): Promise<void> {
  // Delete room state
  await env.ROOMS.delete(`room:${code.toUpperCase()}`);
  // Delete room files from R2
  const listed = await env.BUCKET.list({ prefix: `rooms/${code.toUpperCase()}/` });
  for (const obj of listed.objects) {
    await env.BUCKET.delete(obj.key);
  }
}

async function handleRoomCreate(request: Request, env: Env): Promise<Response> {
  const body = await request.json<{ alias: string; fingerprint: string; deviceType?: string; code?: string }>();
  if (!body.alias || !body.fingerprint) return errorResponse("alias and fingerprint required", 400);

  // Use client-provided code or generate one
  let code = (body.code || "").toUpperCase();
  if (code.length !== 4) {
    for (let i = 0; i < 10; i++) {
      code = generateId(4);
      const existing = await env.ROOMS.get(`room:${code}`);
      if (!existing) break;
    }
  } else {
    // Check collision for client-provided code
    const existing = await env.ROOMS.get(`room:${code}`);
    if (existing) {
      // Code already in use, use it anyway (same host re-registering)
      const room: RoomState = JSON.parse(existing);
      if (room.hostFingerprint === body.fingerprint) {
        // Same host, return existing token
        return jsonResponse({ success: true, code, hostToken: room.hostToken, expiresAt: new Date(new Date(room.createdAt).getTime() + ROOM_EXPIRY_HOURS * 3600000).toISOString() });
      }
    }
  }

  const hostToken = generateToken();
  const now = new Date().toISOString();

  const room: RoomState = {
    code,
    hostAlias: body.alias,
    hostFingerprint: body.fingerprint,
    hostToken,
    createdAt: now,
    members: [{
      fingerprint: body.fingerprint,
      alias: body.alias,
      deviceType: body.deviceType || "mobile",
      joinedAt: now,
    }],
    files: [],
    events: [],
    lastActivity: now,
  };

  await saveRoom(room, env);

  return jsonResponse({
    success: true,
    code,
    hostToken,
    expiresAt: new Date(Date.now() + ROOM_EXPIRY_HOURS * 3600000).toISOString(),
  });
}

async function handleRoomJoin(code: string, request: Request, env: Env): Promise<Response> {
  const cleanCode = code.toUpperCase();
  const room = await getRoom(cleanCode, env);
  if (!room) return errorResponse("Room not found or expired", 404);

  const body = await request.json<{ alias: string; fingerprint: string; deviceType?: string }>();
  if (!body.alias || !body.fingerprint) return errorResponse("alias and fingerprint required", 400);

  // Check if already a member
  const existing = room.members.find(m => m.fingerprint === body.fingerprint);
  if (existing) {
    // Update alias if changed, return current state
    existing.alias = body.alias;
  } else {
    // Add new member
    const member: RoomMemberState = {
      fingerprint: body.fingerprint,
      alias: body.alias,
      deviceType: body.deviceType || "mobile",
      joinedAt: new Date().toISOString(),
    };
    room.members.push(member);
    room.events.push({
      type: "member_joined",
      timestamp: new Date().toISOString(),
      data: { fingerprint: body.fingerprint, alias: body.alias },
    });
  }

  await saveRoom(room, env);

  return jsonResponse({
    success: true,
    members: room.members,
    files: room.files,
    hostAlias: room.hostAlias,
    hostFingerprint: room.hostFingerprint,
  });
}

async function handleRoomInfo(code: string, env: Env): Promise<Response> {
  const room = await getRoom(code, env);
  if (!room) return errorResponse("Room not found or expired", 404);

  return jsonResponse({
    success: true,
    code: room.code,
    hostAlias: room.hostAlias,
    hostFingerprint: room.hostFingerprint,
    memberCount: room.members.length,
    fileCount: room.files.length,
    createdAt: room.createdAt,
  });
}

async function handleRoomPoll(code: string, request: Request, env: Env): Promise<Response> {
  const room = await getRoom(code, env);
  if (!room) return errorResponse("Room not found or expired", 404);

  // Get events since timestamp
  const url = new URL(request.url);
  const since = url.searchParams.get("since") || "1970-01-01T00:00:00Z";
  const fingerprint = url.searchParams.get("fingerprint") || "";

  // Check if member is still in room
  if (fingerprint && !room.members.find(m => m.fingerprint === fingerprint)) {
    return errorResponse("You are not in this room", 403);
  }

  const newEvents = room.events.filter(e => e.timestamp > since);

  return jsonResponse({
    success: true,
    members: room.members,
    files: room.files,
    events: newEvents,
    lastActivity: room.lastActivity,
  });
}

async function handleRoomFileUpload(code: string, request: Request, env: Env): Promise<Response> {
  const cleanCode = code.toUpperCase();
  const room = await getRoom(cleanCode, env);
  if (!room) return errorResponse("Room not found or expired", 404);

  const fileName = request.headers.get("X-File-Name") || "unknown";
  const fileType = request.headers.get("X-File-Type") || "application/octet-stream";
  const ownerAlias = request.headers.get("X-Sender-Alias") || "Unknown";
  const ownerFingerprint = request.headers.get("X-Fingerprint") || "";
  const contentLength = parseInt(request.headers.get("Content-Length") || "0");

  if (!request.body) return errorResponse("No body", 400);

  // Use client-provided fileId or generate one
  const fileId = request.headers.get("X-File-Id") || generateId(8);

  // Skip if file already exists in room
  if (room.files.find(f => f.id === fileId)) {
    return jsonResponse({ success: true, fileId, fileName, duplicate: true });
  }

  const r2Key = `rooms/${cleanCode}/${fileId}`;

  // Store file in R2
  await env.BUCKET.put(r2Key, request.body, {
    httpMetadata: { contentType: "application/octet-stream" },
  });

  // Read thumbnail from header (base64 JPEG, ~3-5KB for 120px)
  const thumbnail = request.headers.get("X-Thumbnail") || undefined;

  // Add to room state
  const fileItem: RoomFileState = {
    id: fileId,
    fileName,
    fileType,
    size: contentLength,
    ownerAlias,
    ownerFingerprint,
    addedAt: new Date().toISOString(),
    thumbnail,
  };
  room.files.push(fileItem);
  room.events.push({
    type: "file_added",
    timestamp: new Date().toISOString(),
    data: { fileId, fileName, ownerAlias },
  });

  await saveRoom(room, env);

  return jsonResponse({ success: true, fileId, fileName });
}

async function handleRoomFileDownload(code: string, fileId: string, env: Env): Promise<Response> {
  const cleanCode = code.toUpperCase();
  const room = await getRoom(cleanCode, env);
  if (!room) return errorResponse("Room not found", 404);

  const fileMeta = room.files.find(f => f.id === fileId);
  if (!fileMeta) return errorResponse("File not found", 404);

  const object = await env.BUCKET.get(`rooms/${cleanCode}/${fileId}`);
  if (!object) return errorResponse("File data not found", 404);

  const headers = new Headers(corsHeaders);
  headers.set("Content-Type", "application/octet-stream");
  headers.set("Content-Length", fileMeta.size.toString());
  headers.set("X-File-Name", fileMeta.fileName);
  headers.set("X-File-Type", fileMeta.fileType);
  return new Response(object.body, { status: 200, headers });
}

async function handleRoomFileThumb(code: string, request: Request, env: Env): Promise<Response> {
  const cleanCode = code.toUpperCase();
  const room = await getRoom(cleanCode, env);
  if (!room) return errorResponse("Room not found", 404);

  const body = await request.json<{ fileId: string; thumbnail: string }>();
  if (!body.fileId || !body.thumbnail) return errorResponse("fileId and thumbnail required", 400);

  const file = room.files.find(f => f.id === body.fileId);
  if (file) {
    file.thumbnail = body.thumbnail;
    await saveRoom(room, env);
  }

  return jsonResponse({ success: true });
}

async function handleRoomLeave(code: string, request: Request, env: Env): Promise<Response> {
  const cleanCode = code.toUpperCase();
  const room = await getRoom(cleanCode, env);
  if (!room) return errorResponse("Room not found", 404);

  const body = await request.json<{ fingerprint: string }>();
  if (!body.fingerprint) return errorResponse("fingerprint required", 400);

  room.members = room.members.filter(m => m.fingerprint !== body.fingerprint);
  room.events.push({
    type: "member_left",
    timestamp: new Date().toISOString(),
    data: { fingerprint: body.fingerprint },
  });

  await saveRoom(room, env);
  return jsonResponse({ success: true });
}

async function handleRoomClose(code: string, request: Request, env: Env): Promise<Response> {
  const cleanCode = code.toUpperCase();
  const room = await getRoom(cleanCode, env);
  if (!room) return errorResponse("Room not found", 404);

  // Verify host token
  const hostToken = request.headers.get("X-Delete-Token") || "";
  if (room.hostToken !== hostToken) return errorResponse("Not authorized", 403);

  // Add close event and clear members — pollers will see the event
  room.events.push({
    type: "room_closed",
    timestamp: new Date().toISOString(),
    data: { hostAlias: room.hostAlias },
  });
  room.members = []; // Clear members so pollers know room is closed

  // Save with short TTL (60s) so pollers can see the close event before auto-delete
  await env.ROOMS.put(`room:${room.code}`, JSON.stringify(room), { expirationTtl: 60 });

  // Clean up R2 files
  const listed = await env.BUCKET.list({ prefix: `rooms/${cleanCode}/` });
  for (const obj of listed.objects) {
    await env.BUCKET.delete(obj.key);
  }

  return jsonResponse({ success: true, message: "Room closed" });
}

// ==================== ROUTER ====================

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // --- File Transfer ---
    if (path === "/api/upload" && request.method === "POST") return handleUpload(request, env);

    const dlMatch = path.match(/^\/api\/download\/([A-Za-z0-9-]+)$/);
    if (dlMatch && request.method === "GET") return handleDownload(dlMatch[1], env);

    const statusMatch = path.match(/^\/api\/status\/([A-Za-z0-9-]+)$/);
    if (statusMatch && request.method === "GET") return handleStatus(statusMatch[1], env);

    const delMatch = path.match(/^\/api\/delete\/([A-Za-z0-9-]+)$/);
    if (delMatch && request.method === "DELETE") return handleFileDelete(delMatch[1], request, env);

    // --- Rooms ---
    if (path === "/api/room/create" && request.method === "POST") return handleRoomCreate(request, env);

    const joinMatch = path.match(/^\/api\/room\/join\/([A-Za-z0-9]+)$/);
    if (joinMatch && request.method === "POST") return handleRoomJoin(joinMatch[1], request, env);

    const infoMatch = path.match(/^\/api\/room\/info\/([A-Za-z0-9]+)$/);
    if (infoMatch && request.method === "GET") return handleRoomInfo(infoMatch[1], env);

    const pollMatch = path.match(/^\/api\/room\/poll\/([A-Za-z0-9]+)$/);
    if (pollMatch && request.method === "GET") return handleRoomPoll(pollMatch[1], request, env);

    const fileUpMatch = path.match(/^\/api\/room\/file\/([A-Za-z0-9]+)$/);
    if (fileUpMatch && request.method === "POST") return handleRoomFileUpload(fileUpMatch[1], request, env);

    const fileDlMatch = path.match(/^\/api\/room\/file\/([A-Za-z0-9]+)\/([A-Za-z0-9_-]+)$/);
    if (fileDlMatch && request.method === "GET") return handleRoomFileDownload(fileDlMatch[1], fileDlMatch[2], env);

    const fileThumbMatch = path.match(/^\/api\/room\/file-thumb\/([A-Za-z0-9]+)$/);
    if (fileThumbMatch && request.method === "POST") return handleRoomFileThumb(fileThumbMatch[1], request, env);

    const leaveMatch = path.match(/^\/api\/room\/leave\/([A-Za-z0-9]+)$/);
    if (leaveMatch && request.method === "POST") return handleRoomLeave(leaveMatch[1], request, env);

    const closeMatch = path.match(/^\/api\/room\/([A-Za-z0-9]+)$/);
    if (closeMatch && request.method === "DELETE") return handleRoomClose(closeMatch[1], request, env);

    // Health
    if (path === "/api/health") return jsonResponse({ status: "ok", service: "bishare-relay", version: "3.0.0" });

    return errorResponse("Not found", 404);
  },
};
