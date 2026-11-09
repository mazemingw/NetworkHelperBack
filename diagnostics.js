const express = require('express');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { promisify } = require('node:util');
const gzip = promisify(zlib.gzip);
const { diagnosticRoot, localLimit, publishDiagnostic } = require('./diagnostic-storage');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SECRET = /^[0-9a-f]{64}$/;
const MAX_BYTES = 512 * 1024;
const CONSOLE_MAX_BYTES = 16 * 1024 * 1024;
const CONSOLE_MAX_ENTRIES = 12800;

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function redact(text) {
  const frames = [];
  const protectedText = String(text).replace(/\bat [\w.$<>]+\(r8-map-id-[a-f0-9]{64}:\d+\)/g, frame => {
    frames.push(frame); return `__DIAGNOSTIC_BUILD_FRAME_${frames.length - 1}__`;
  });
  return protectedText.replace(/(["']?(?:imei\d*|imsi|iccid|meid|serial(?:no|number)?|hardware_serial|password|passwd|secret|vault_secret|token|authorization|cookie|latitude|longitude)["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;，；}\]]+)/gi, '$1"[REDACTED]"')
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, '[REDACTED]')
    .replace(/https?:\/\/[^\s<>"']+/gi, '[REDACTED]')
    .replace(/(?<![0-9])(?:[0-9][ -]?){14,21}(?![0-9])/g, '[REDACTED]')
    .replace(/\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi, '[REDACTED]')
    .replace(/(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])/g, '[REDACTED]')
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '[REDACTED]')
    .replace(/(?<![a-f0-9])[a-f0-9]{32,}(?![a-f0-9])/gi, '[REDACTED]')
    .replace(/__DIAGNOSTIC_BUILD_FRAME_(\d+)__/g, (token, index) => frames[Number(index)] || token);
}
function clean(value, depth = 0, arrayLimit = 400) {
  if (depth > 6) return '[TRUNCATED]';
  if (typeof value === 'string') return redact(value.slice(0, 16000));
  if (Array.isArray(value)) return value.slice(0, arrayLimit).map(v => clean(v, depth + 1, arrayLimit));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).slice(0, 60).map(([key, v]) => [key.slice(0, 100),
    key === 'apkSha256' && typeof v === 'string' && /^[a-f0-9]{64}$/.test(v) ? v :
    /imei|imsi|iccid|meid|secret|token|password|passwd|authorization|cookie|serial|latitude|longitude|android.?id|api.?key|access.?key|private.?key|subscriber.?id|phone.?number|msisdn|session.?id/i.test(key) ||
      /^(?:pwd|phone|lat|lon|lng|ssid|bssid|mac|macaddress|ip|ipaddress|nci|eci|cellid)$/i.test(key.replace(/[^a-z0-9]/gi, '')) ? '[REDACTED]' : clean(v, depth + 1)]));
  return typeof value === 'number' || typeof value === 'boolean' ? value : null;
}
function normalizeReport(body, consoleMode = false) {
  if (!body || body.schema !== 1 || !UUID.test(body.id || '') || !Number.isSafeInteger(body.occurredAt) ||
      body.occurredAt < 0 ||
      !(consoleMode ? ['info'] : ['error', 'fatal']).includes(body.severity) || typeof body.source !== 'string' || !body.source || body.source.length > 100 ||
      typeof body.message !== 'string' || body.message.length > 8000 || !body.device || typeof body.device.model !== 'string') fail(400, 'invalid_diagnostic_report');
  if (Buffer.byteLength(JSON.stringify(body), 'utf8') > (consoleMode ? CONSOLE_MAX_BYTES : MAX_BYTES)) fail(413, 'diagnostic_report_too_large');
  if (consoleMode && (!Array.isArray(body.entries) || !body.entries.length || body.entries.length > CONSOLE_MAX_ENTRIES ||
      body.entries.some(row => !row || !['INFO', 'WARNING', 'ERROR'].includes(row.level) ||
        typeof row.source !== 'string' || row.source.length > 100 || typeof row.message !== 'string' || row.message.length > 1200 ||
        (row.detail != null && (typeof row.detail !== 'string' || row.detail.length > 6000)) ||
        !Number.isSafeInteger(row.firstAt) || !Number.isSafeInteger(row.lastAt) ||
        !Number.isSafeInteger(row.repeats) || row.repeats < 1 || row.repeats > 1000000))) fail(400, 'invalid_console_entries');
  const result = clean({ schema: 1, id: body.id.toLowerCase(), occurredAt: body.occurredAt, source: body.source,
    severity: body.severity, message: body.message, stack: body.stack || '', device: body.device,
    context: body.context || {}, breadcrumbs: body.breadcrumbs || [] });
  // A validated random report UUID is protocol metadata, even when it contains long digit runs.
  result.id = body.id.toLowerCase();
  // IMEI is deliberately retained only here, never in paths, console messages or response bodies.
  const imei = body.device.imei1;
  result.device.imei1 = typeof imei === 'string' && /^[0-9]{15}$/.test(imei) && /[1-9]/.test(imei) ? imei : null;
  result.device.imeiSlot = 0;
  result.device.imeiSource = ['efs_cache', 'diagnostic_cache', 'existing_efs_identity', 'root_phone_service'].includes(body.device.imeiSource) ? body.device.imeiSource : 'unavailable';
  if (consoleMode) { result.kind = 'diagnostic-console'; result.entries = clean(body.entries, 0, CONSOLE_MAX_ENTRIES); }
  return result;
}

function createDiagnosticsRouter(options = {}) {
  const router = express.Router();
  const env = options.env || process.env;
  const root = diagnosticRoot(env);
  const maximum = localLimit(env);
  let lastPressure = 0;
  const windows = new Map();
  const limit = (key, maximum, interval) => {
    const now = Date.now(); let entry = windows.get(key);
    if (!entry || now >= entry.until) { entry = { count: 0, until: now + interval }; windows.set(key, entry); }
    if (++entry.count > maximum) fail(429, 'diagnostic_rate_limited');
    if (windows.size > 4096) for (const [name, value] of windows) if (value.until < now) windows.delete(name);
    if (windows.size > 8192) windows.delete(windows.keys().next().value);
  };
  const wrap = handler => async (req, res) => {
    try { await handler(req, res); }
    catch (error) {
      if (['diagnostic_local_storage_full', 'diagnostic_disk_space_low'].includes(error.message) && Date.now() - lastPressure > 60000) {
        lastPressure = Date.now(); options.onStoragePressure?.();
      }
      if (!error.status) console.error('[diagnostics] storage_failure', /^[A-Z_]+$/.test(error.code || '') ? error.code : 'ERROR');
      if (error.status === 429) res.set('Retry-After', '3600');
      res.status(error.status || 503).json({ ok: false, error: error.status ? error.message : 'diagnostic_storage_unavailable' });
    }
  };
  router.use((req, res, next) => {
    try { limit(`ip:${req.ip}`, 240, 60000); next(); }
    catch (error) { res.status(429).set('Retry-After', '60').json({ ok: false, error: error.message }); }
  });
  // Mount before the legacy parser. Only manual console uploads accept the larger log limit.
  const smallJson = express.json({ limit: MAX_BYTES, strict: true });
  const consoleJson = express.json({ limit: CONSOLE_MAX_BYTES, strict: true });
  router.use((req, res, next) => (req.path === '/console' ? consoleJson : smallJson)(req, res, next));

  router.post('/register', wrap(async (req, res) => {
    const { installationId: id, secret } = req.body || {};
    if (!UUID.test(id || '') || !SECRET.test(secret || '')) fail(400, 'invalid_diagnostic_credentials');
    const directory = path.join(root, 'clients');
    const file = path.join(directory, `${id.toLowerCase()}.json`);
    const digest = crypto.createHash('sha256').update(secret).digest('hex');
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    let stored;
    try { stored = JSON.parse(await fs.readFile(file, 'utf8')); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (!stored) {
      limit(`register:${req.ip}`, 30, 3600000);
      try { await fs.writeFile(file, JSON.stringify({ secretSha256: digest, createdAt: Date.now() }), { flag: 'wx', mode: 0o600 }); }
      catch (error) { if (error.code !== 'EEXIST') throw error; }
      stored = JSON.parse(await fs.readFile(file, 'utf8'));
    }
    if (!SECRET.test(stored.secretSha256 || '') || !crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(stored.secretSha256))) fail(403, 'diagnostic_authorization_failed');
    res.json({ ok: true });
  }));

  async function authorize(req) {
    const match = /^Bearer ([0-9a-f-]{36})\.([0-9a-f]{64})$/i.exec(req.get('authorization') || '');
    if (!match || !UUID.test(match[1])) fail(401, 'diagnostic_authorization_required');
    const id = match[1].toLowerCase();
    let stored;
    try { stored = JSON.parse(await fs.readFile(path.join(root, 'clients', `${id}.json`), 'utf8')); }
    catch (error) { if (error.code === 'ENOENT') fail(401, 'diagnostic_registration_required'); throw error; }
    const digest = crypto.createHash('sha256').update(match[2]).digest('hex');
    if (!SECRET.test(stored.secretSha256 || '') || !crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(stored.secretSha256))) fail(403, 'diagnostic_authorization_failed');
    return id;
  }
  const receive = consoleMode => wrap(async (req, res) => {
    const installationId = await authorize(req);
    limit(`client:${installationId}`, 120, 3600000);
    const report = normalizeReport(req.body, consoleMode);
    // Receipt time controls retention; clients cannot place arbitrary directories in the path.
    const day = new Date().toISOString().slice(0, 10);
    const directory = path.join(root, day);
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    const name = crypto.createHash('sha256').update(`${installationId}:${report.id}`).digest('hex');
    const receiptCode = `NH-${day.replace(/-/g, '')}-${name.slice(0, 16).toUpperCase()}`;
    const file = path.join(directory, `${receiptCode}.json.gz`);
    const document = { ...report, installationId, receiptCode, receivedAt: Date.now() };
    const temporary = path.join(directory, `.${crypto.randomUUID()}.tmp`);
    await publishDiagnostic(root, file, temporary, await gzip(Buffer.from(JSON.stringify(document))), maximum);
    res.json({ ok: true, id: report.id, receiptCode });
  });
  router.post('/reports', receive(false));
  router.post('/console', receive(true));
  router.use((error, req, res, next) => {
    if (error.type === 'entity.too.large') return res.status(413).json({ ok: false, error: 'diagnostic_report_too_large' });
    res.status(400).json({ ok: false, error: 'invalid_diagnostic_json' });
  });
  return router;
}
module.exports = { createDiagnosticsRouter, normalizeReport, redact };
