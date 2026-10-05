const MAX_FILE_BYTES = 100_000_000;
const MAX_ATTACHMENT_BYTES = 20 * 1024 * 1024;
const TOKEN_SECONDS = 8 * 60 * 60;
const LINK_SECONDS = 24 * 60 * 60;

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function base64url(bytes) {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function fromBase64url(value) {
  const text = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(text, character => character.charCodeAt(0));
}
async function signingKey(env) {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(env.SESSION_SIGNING_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function signClaims(env, claims) {
  const payload = base64url(new TextEncoder().encode(JSON.stringify(claims)));
  const signature = await crypto.subtle.sign('HMAC', await signingKey(env), new TextEncoder().encode(payload));
  return `${payload}.${base64url(new Uint8Array(signature))}`;
}
async function verifyClaims(env, token, kind) {
  const [payload, signature, extra] = token.split('.');
  if (!payload || !signature || extra) return null;
  try {
    const valid = await crypto.subtle.verify('HMAC', await signingKey(env), fromBase64url(signature), new TextEncoder().encode(payload));
    if (!valid) return null;
    const claims = JSON.parse(new TextDecoder().decode(fromBase64url(payload)));
    if (claims.kind !== kind || !Number.isInteger(claims.exp) || claims.exp <= Math.floor(Date.now() / 1000)) return null;
    if (kind === 'session') {
      if (typeof claims.jti !== 'string') return null;
      const revoked = await env.DB.prepare('SELECT jti FROM revoked_tokens WHERE jti = ?1').bind(claims.jti).first();
      if (revoked) return null;
    }
    return claims;
  } catch { return null; }
}
async function secureEqual(left, right) {
  const encode = value => new TextEncoder().encode(value);
  const [a, b] = await Promise.all([crypto.subtle.digest('SHA-256', encode(left)), crypto.subtle.digest('SHA-256', encode(right))]);
  const one = new Uint8Array(a), two = new Uint8Array(b);
  let diff = 0;
  for (let index = 0; index < one.length; index += 1) diff |= one[index] ^ two[index];
  return diff === 0;
}
function cors(origin) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-File-Name, X-File-Size',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store'
  };
}
function json(data, status, headers) {
  return new Response(JSON.stringify(data), { status, headers: { ...headers, 'Content-Type': 'application/json; charset=utf-8' } });
}
async function sha256Text(value) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
}
async function rateLimit(env, label, ip, maximum, windowSeconds) {
  const key = `${label}:${base64url(await sha256Text(ip || 'unknown'))}`;
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(`
    INSERT INTO rate_limits (rate_key, count, window_started) VALUES (?1, 1, ?2)
    ON CONFLICT(rate_key) DO UPDATE SET
      count = CASE WHEN window_started <= ?2 - ?3 THEN 1 ELSE count + 1 END,
      window_started = CASE WHEN window_started <= ?2 - ?3 THEN ?2 ELSE window_started END
  `).bind(key, now, windowSeconds).run();
  const row = await env.DB.prepare('SELECT count FROM rate_limits WHERE rate_key = ?1').bind(key).first();
  if (row.count > maximum) throw new ApiError(429, 'Zu viele Versuche. Bitte später erneut versuchen.');
}
function sanitizeName(value) {
  let name;
  try { name = decodeURIComponent(value || ''); } catch { throw new ApiError(400, 'Der Dateiname ist ungültig.'); }
  const leaf = name.split(/[\\/]/).pop() || '';
  const safe = leaf.normalize('NFKC').replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, '').trim().slice(0, 180);
  return safe && safe !== '.' && safe !== '..' ? safe : null;
}
function inspectSignature(bytes, extension) {
  const starts = (...signature) => signature.every((byte, index) => bytes[index] === byte);
  let mime;
  if (starts(0x25, 0x50, 0x44, 0x46, 0x2d)) mime = 'application/pdf';
  else if (starts(0xff, 0xd8, 0xff)) mime = 'image/jpeg';
  else if (starts(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)) mime = 'image/png';
  else if (starts(0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1)) mime = 'application/x-cfb';
  else if (starts(0x50, 0x4b, 0x03, 0x04) || starts(0x50, 0x4b, 0x05, 0x06) || starts(0x50, 0x4b, 0x07, 0x08)) mime = 'application/zip';
  const allowed = {
    '.pdf': 'application/pdf', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
    '.doc': 'application/x-cfb', '.xls': 'application/x-cfb', '.docx': 'application/zip',
    '.xlsx': 'application/zip', '.zip': 'application/zip'
  };
  if (!allowed[extension] || allowed[extension] !== mime) throw new ApiError(415, 'Dateiendung und Dateiinhalte passen nicht zu einem unterstützten Typ.');
  return mime;
}
function bytesToBase64(bytes) {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  return btoa(binary);
}
function htmlEscape(value) {
  return String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}
async function emailUpload(env, upload, attachment, downloadUrl) {
  const when = new Intl.DateTimeFormat('de-DE', { dateStyle: 'full', timeStyle: 'short', timeZone: 'UTC' }).format(new Date(upload.uploadedAt));
  const largeFileText = attachment ? '' : `\nDownload (24 Stunden gültig): ${downloadUrl}`;
  const largeFileHtml = attachment ? '' : `<p><a href="${htmlEscape(downloadUrl)}">Datei herunterladen (24 Stunden gültig)</a></p>`;
  const message = {
    from: env.MAIL_FROM,
    to: [env.MAIL_TO],
    subject: 'Neuer Datei-Upload',
    text: `Neuer Datei-Upload\n\nDatei: ${upload.originalName}\nUpload-Zeitpunkt: ${when} UTC${largeFileText}`,
    html: `<h2>Neuer Datei-Upload</h2><p><strong>Datei:</strong> ${htmlEscape(upload.originalName)}</p><p><strong>Upload-Zeitpunkt:</strong> ${htmlEscape(when)} UTC</p>${largeFileHtml}`
  };
  if (attachment) message.attachments = [{ filename: upload.originalName, content: bytesToBase64(attachment), content_type: upload.mimeType }];
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(message),
    signal: AbortSignal.timeout(25000)
  });
  if (!response.ok) {
    const result = await response.json().catch(() => ({}));
    console.error('Email provider rejected upload notification:', response.status, result.name || 'provider error');
    throw new Error('Der E-Mail-Versand ist fehlgeschlagen. Bitte Mail-Anbieter-Konfiguration prüfen.');
  }
}
async function allUploads(env) {
  const result = await env.DB.prepare(`SELECT id, original_name AS originalName, size, mime_type AS mimeType,
    uploaded_at AS uploadedAt, status FROM uploads ORDER BY uploaded_at DESC LIMIT 200`).all();
  return result.results;
}
async function download(request, env, url) {
  const claims = await verifyClaims(env, url.searchParams.get('token') || '', 'download');
  if (!claims || typeof claims.id !== 'string') return new Response('Dieser Download-Link ist ungültig oder abgelaufen.', { status: 401 });
  await rateLimit(env, 'download', request.headers.get('CF-Connecting-IP'), 30, 3600);
  const row = await env.DB.prepare('SELECT original_name, object_key, mime_type FROM uploads WHERE id = ?1').bind(claims.id).first();
  if (!row) return new Response('Datei wurde nicht gefunden.', { status: 404 });
  const object = await env.UPLOADS.get(row.object_key);
  if (!object) return new Response('Datei wurde nicht gefunden.', { status: 404 });
  const filename = encodeURIComponent(row.original_name).replace(/['()]/g, escape => `%${escape.charCodeAt(0).toString(16)}`);
  return new Response(object.body, { headers: {
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': `attachment; filename*=UTF-8''${filename}`,
    'Content-Length': String(object.size),
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'private, no-store'
  } });
}
async function upload(request, env, headers) {
  await rateLimit(env, 'upload', request.headers.get('CF-Connecting-IP'), 10, 3600);
  const contentLength = Number(request.headers.get('Content-Length') || 0);
  const length = Number(request.headers.get('X-File-Size') || contentLength);
  if (!Number.isSafeInteger(length) || length < 1) throw new ApiError(411, 'Die Dateigröße konnte nicht ermittelt werden.');
  if (contentLength && contentLength !== length) throw new ApiError(400, 'Die Upload-Größenangaben stimmen nicht überein.');
  if (length > MAX_FILE_BYTES) throw new ApiError(413, 'Maximal erlaubt sind 100 MB pro Datei.');
  if (!request.body) throw new ApiError(400, 'Der Upload enthält keine Datei.');
  const originalName = sanitizeName(request.headers.get('X-File-Name'));
  if (!originalName) throw new ApiError(400, 'Der Dateiname ist ungültig.');
  const extension = originalName.includes('.') ? originalName.slice(originalName.lastIndexOf('.')).toLowerCase() : '';
  if (!['.pdf', '.jpg', '.jpeg', '.png', '.doc', '.docx', '.xls', '.xlsx', '.zip'].includes(extension)) throw new ApiError(415, 'Dieser Dateityp ist nicht erlaubt.');

  const reader = request.body.getReader();
  const prefixChunks = [];
  let prefixSize = 0;
  while (prefixSize < 16) {
    const part = await reader.read();
    if (part.done) break;
    prefixChunks.push(part.value);
    prefixSize += part.value.byteLength;
  }
  if (!prefixSize) throw new ApiError(400, 'Die Datei ist leer.');
  const prefix = new Uint8Array(prefixSize);
  let prefixOffset = 0;
  for (const chunk of prefixChunks) { prefix.set(chunk, prefixOffset); prefixOffset += chunk.byteLength; }
  const mimeType = inspectSignature(prefix.subarray(0, 16), extension);
  const objectKey = `${crypto.randomUUID()}/${originalName.replace(/[^a-zA-Z0-9._-]/g, '_')}`;
  const capture = length <= MAX_ATTACHMENT_BYTES ? [] : null;
  let received = 0;
  let pendingChunks = prefixChunks;
  const stream = new ReadableStream({
    async pull(controller) {
      try {
        const part = pendingChunks.length ? { done: false, value: pendingChunks.shift() } : await reader.read();
        if (part.done) {
          if (received !== length) throw new ApiError(400, 'Der Upload wurde unvollständig übertragen.');
          controller.close();
          return;
        }
        const chunk = part.value;
        received += chunk.byteLength;
        if (received > MAX_FILE_BYTES || received > length) throw new ApiError(413, 'Der Upload überschreitet die erlaubte Größe.');
        if (capture) capture.push(chunk.slice());
        controller.enqueue(chunk);
      } catch (error) {
        controller.error(error);
        await reader.cancel(error).catch(() => {});
      }
    }
  });
  const uploadedAt = new Date().toISOString();
  const id = crypto.randomUUID();
  try {
    await env.UPLOADS.put(objectKey, stream, { httpMetadata: { contentType: mimeType } });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    console.error('Private object upload failed:', error.message);
    throw new ApiError(502, 'Die Datei konnte nicht sicher gespeichert werden.');
  }
  const row = { id, originalName, objectKey, size: length, mimeType, uploadedAt };
  try {
    await env.DB.prepare(`INSERT INTO uploads (id, original_name, object_key, size, mime_type, uploaded_at, status)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'sending')`)
      .bind(id, originalName, objectKey, length, mimeType, uploadedAt).run();
  } catch (error) {
    await env.UPLOADS.delete(objectKey);
    throw error;
  }

  let emailSent = false;
  let errorMessage = '';
  try {
    const attachment = capture ? concatenate(capture, length) : null;
    const downloadToken = await signClaims(env, { kind: 'download', id, exp: Math.floor(Date.now() / 1000) + LINK_SECONDS });
    const downloadUrl = `${new URL(request.url).origin}/download/${id}?token=${encodeURIComponent(downloadToken)}`;
    await emailUpload(env, row, attachment, downloadUrl);
    emailSent = true;
  } catch (error) {
    errorMessage = error.message || 'E-Mail-Versand fehlgeschlagen.';
    console.error('Upload notification failed:', errorMessage);
  }
  const status = emailSent ? 'email_sent' : 'email_failed';
  await env.DB.prepare('UPDATE uploads SET status = ?1 WHERE id = ?2').bind(status, id).run();
  return json({ emailSent, error: errorMessage, upload: { id, originalName, size: length, mimeType, uploadedAt, status } }, 201, headers);
}
function concatenate(chunks, length) {
  const result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length; }
  return result;
}
async function apiRoute(request, env, headers) {
  const url = new URL(request.url);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers });
  if (url.pathname === '/api/health' && request.method === 'GET') return json({ ok: true }, 200, headers);
  if (url.pathname === '/api/unlock' && request.method === 'POST') {
    await rateLimit(env, 'unlock', request.headers.get('CF-Connecting-IP'), 8, 900);
    const body = await request.json().catch(() => null);
    if (!body || typeof body.password !== 'string' || body.password.length > 256) throw new ApiError(400, 'Bitte gib das Zugangspasswort ein.');
    if (!await secureEqual(body.password, env.ACCESS_PASSWORD)) throw new ApiError(401, 'Das Zugangspasswort ist nicht korrekt.');
    const token = await signClaims(env, { kind: 'session', jti: crypto.randomUUID(), exp: Math.floor(Date.now() / 1000) + TOKEN_SECONDS });
    return json({ token, expiresIn: TOKEN_SECONDS }, 200, headers);
  }
  const token = (request.headers.get('Authorization') || '').match(/^Bearer (.+)$/)?.[1];
  const claims = token ? await verifyClaims(env, token, 'session') : null;
  if (!claims) throw new ApiError(401, 'Der Zugang ist abgelaufen. Bitte gib das Passwort erneut ein.');
  if (url.pathname === '/api/logout' && request.method === 'POST') {
    await env.DB.prepare('INSERT OR IGNORE INTO revoked_tokens (jti, expires_at) VALUES (?1, ?2)')
      .bind(claims.jti, claims.exp).run();
    await env.DB.prepare('DELETE FROM revoked_tokens WHERE expires_at <= ?1').bind(Math.floor(Date.now() / 1000)).run();
    return new Response(null, { status: 204, headers });
  }
  if (!url.pathname.startsWith('/api/')) throw new ApiError(404, 'Endpunkt nicht gefunden.');
  if (url.pathname === '/api/uploads' && request.method === 'GET') return json({ uploads: await allUploads(env) }, 200, headers);
  if (url.pathname === '/api/uploads' && request.method === 'POST') return upload(request, env, headers);
  const match = /^\/api\/uploads\/([0-9a-f-]{36})$/i.exec(url.pathname);
  if (match && request.method === 'DELETE') {
    const row = await env.DB.prepare('SELECT object_key FROM uploads WHERE id = ?1').bind(match[1]).first();
    if (!row) throw new ApiError(404, 'Upload wurde nicht gefunden.');
    await env.UPLOADS.delete(row.object_key);
    await env.DB.prepare('DELETE FROM uploads WHERE id = ?1').bind(match[1]).run();
    return new Response(null, { status: 204, headers });
  }
  throw new ApiError(404, 'Endpunkt nicht gefunden.');
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/download/')) return download(request, env, url);
    const origin = request.headers.get('Origin');
    const headers = cors(env.ALLOWED_ORIGIN || 'null');
    if (!env.ALLOWED_ORIGIN || origin !== env.ALLOWED_ORIGIN) return json({ error: 'Diese Website ist für die API nicht freigeschaltet.' }, 403, headers);
    if (!env.ACCESS_PASSWORD || !env.SESSION_SIGNING_KEY || !env.RESEND_API_KEY || !env.MAIL_FROM || !env.MAIL_TO || !env.DB || !env.UPLOADS) {
      return json({ error: 'Die Backend-Konfiguration ist unvollständig.' }, 503, headers);
    }
    try { return await apiRoute(request, env, headers); }
    catch (error) {
      if (error instanceof ApiError) return json({ error: error.message }, error.status, headers);
      console.error('Worker request failed:', error.message);
      return json({ error: 'Interner Fehler. Bitte versuche es später erneut.' }, 500, headers);
    }
  }
};
