const fs = require('node:fs/promises');
const nativeFs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const OSS = require('ali-oss');
const { diagnosticRoot, localLimit, reportFiles, cleanDiagnosticReports } = require('./diagnostic-storage');

function archiveConfig(env = process.env) {
  const bucket = env.DIAGNOSTIC_OSS_BUCKET || env.OSS_BUCKET;
  const region = String(env.DIAGNOSTIC_OSS_REGION || env.OSS_REGION || '').replace(/^oss-/, '');
  const prefix = String(env.DIAGNOSTIC_OSS_PREFIX || 'DIAGNOSTICS').replace(/\/$/, '');
  if (!/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(bucket || '') || !/^[a-z0-9-]+$/.test(region) ||
      !/^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(prefix) || !env.OSS_ACCESS_KEY_ID || !env.OSS_ACCESS_KEY_SECRET)
    throw new Error('diagnostic_oss_not_configured');
  return { bucket, region, prefix, accessKeyId: env.OSS_ACCESS_KEY_ID, accessKeySecret: env.OSS_ACCESS_KEY_SECRET,
    ...(env.OSS_SECURITY_TOKEN ? { stsToken: env.OSS_SECURITY_TOKEN } : {}) };
}
function archiveClient(config) { return new OSS({ ...config, region: `oss-${config.region}`, secure: true, timeout: 60000 }); }
function objectKey(config, file) { return `${config.prefix}/${file.day}/${file.name}`; }
async function digest(stream, maximum = Infinity) {
  const hash = crypto.createHash('sha256'); let size = 0;
  try { for await (const chunk of stream) { size += chunk.length; if (size > maximum) throw new Error('diagnostic_archive_size_mismatch'); hash.update(chunk); } }
  finally { stream.destroy(); }
  return { sha256: hash.digest('hex'), size };
}
async function readIndex(root, day) {
  try {
    const file = path.join(root, day, '.oss-index.json');
    if ((await fs.lstat(file)).size > 8 * 1024 * 1024) return {};
    return JSON.parse(await fs.readFile(file, 'utf8'));
  } catch (error) { if (error.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error; return {}; }
}
async function writeIndex(root, day, index) {
  const directory = path.join(root, day);
  const bytes = JSON.stringify(Object.fromEntries(Object.entries(index).slice(-40000)));
  if (Buffer.byteLength(bytes) > 8 * 1024 * 1024) throw new Error('diagnostic_archive_index_limit');
  const temporary = path.join(directory, `.${crypto.randomUUID()}.tmp`);
  try {
    await fs.writeFile(temporary, bytes, { mode: 0o600, flag: 'wx' });
    await fs.rename(temporary, path.join(directory, '.oss-index.json'));
  }
  finally { await fs.unlink(temporary).catch(() => {}); }
}

function createDiagnosticArchive(options = {}) {
  const env = options.env || process.env;
  const root = diagnosticRoot(env), maximum = options.maxLocalBytes || localLimit(env);
  const logger = options.logger || console, now = options.now || Date.now;
  const makeClient = options.clientFor || archiveClient;
  const saveIndex = options.writeIndex || writeIndex;
  let running = null, timer = null, stopped = true, storagePressure = false;

  async function execute() {
    const summary = { at: new Date(now()).toISOString(), uploaded: 0, previouslyArchived: 0, failed: 0,
      deleted: 0, unarchivedExpired: 0, localBytes: 0 };
    const verified = new Set(), indexes = new Map(), dirty = new Set();
    async function flushIndexes() {
      for (const day of dirty) await saveIndex(root, day, indexes.get(day));
      dirty.clear();
    }
    let config, client;
    try { config = archiveConfig(env); client = makeClient(config); }
    catch (_) { summary.configurationError = 'diagnostic_oss_not_configured'; }
    const files = await reportFiles(root);
    let consecutiveCloudFailures = 0, cloudBlocked = false;
    for (const item of files) {
      let attemptingCloud = false;
      try {
        if (!indexes.has(item.day)) indexes.set(item.day, await readIndex(root, item.day));
        const index = indexes.get(item.day);
        const local = await digest(nativeFs.createReadStream(item.file));
        const key = config ? objectKey(config, item) : null;
        const old = index[item.name];
        if (old && old.sha256 === local.sha256 && old.size === local.size &&
            (!config || (old.key === key && old.bucket === config.bucket))) {
          verified.add(item.file); summary.previouslyArchived++; continue;
        }
        if (!client || cloudBlocked) { summary.failed++; continue; }
        attemptingCloud = true;
        try {
          await client.put(key, item.file, { headers: {
            'x-oss-object-acl': 'private', 'x-oss-forbid-overwrite': 'true', 'x-oss-meta-sha256': local.sha256,
            'Content-Type': 'application/gzip',
          } });
        } catch (error) {
          if (error.status !== 409 && error.code !== 'FileAlreadyExists') throw error;
        }
        if ((await client.getACL(key)).acl !== 'private') throw new Error('diagnostic_archive_must_be_private');
        const remote = await client.getStream(key);
        const deadline = setTimeout(() => remote.stream.destroy(new Error('diagnostic_archive_read_timeout')), 60000);
        deadline.unref();
        let saved;
        try { saved = await digest(remote.stream, local.size); } finally { clearTimeout(deadline); }
        if (saved.size !== local.size || saved.sha256 !== local.sha256) throw new Error('diagnostic_archive_checksum_mismatch');
        attemptingCloud = false; consecutiveCloudFailures = 0;
        index[item.name] = { sha256: saved.sha256, size: saved.size, key, bucket: config.bucket, verifiedAt: now() };
        verified.add(item.file); summary.uploaded++; dirty.add(item.day);
        if (summary.uploaded % 50 === 0) await flushIndexes();
      } catch (_) {
        summary.failed++;
        if (attemptingCloud && ++consecutiveCloudFailures >= 3) cloudBlocked = true;
      }
    }
    if (cloudBlocked) summary.cloudCircuitOpen = true;
    try { await flushIndexes(); } catch (_) { summary.indexWriteFailed = true; }
    // Admission stops before the quota is exceeded. Make room for the next request,
    // including when the filesystem reserve (rather than our quota) caused the rejection.
    let cleanupLimit = maximum;
    if (storagePressure) {
      storagePressure = false; summary.storagePressure = true;
      cleanupLimit = Math.max(0, Math.min(Math.floor(maximum * 0.9),
        files.reduce((bytes, item) => bytes + item.size, 0) - 16 * 1024 * 1024));
    }
    Object.assign(summary, await cleanDiagnosticReports(root, verified, cleanupLimit, now()));
    // Remove index entries for files evicted locally; OSS objects are intentionally never deleted.
    const remaining = await reportFiles(root);
    for (const [day, index] of indexes) {
      const names = new Set(remaining.filter(item => item.day === day).map(item => item.name));
      if (!names.size) continue;
      let changed = false;
      for (const name of Object.keys(index)) if (!names.has(name)) { delete index[name]; changed = true; }
      if (changed) {
        try { await saveIndex(root, day, index); } catch (_) { summary.indexWriteFailed = true; }
      }
    }
    const status = path.join(root, 'archive-status.json');
    try { await fs.writeFile(status, JSON.stringify(summary, null, 2), { mode: 0o600 }); }
    catch (_) { summary.statusWriteFailed = true; }
    if (summary.failed || summary.configurationError || summary.unarchivedExpired || summary.indexWriteFailed || summary.statusWriteFailed) logger.warn('[diagnostic-archive]', JSON.stringify(summary));
    else logger.info('[diagnostic-archive]', JSON.stringify(summary));
    return summary;
  }
  function run(options = {}) {
    if (options.storagePressure) storagePressure = true;
    if (!running) running = execute().finally(() => { running = null; });
    return running;
  }
  function schedule() {
    if (stopped) return;
    const delay = 3600000 - (now() % 3600000);
    timer = (options.setTimeout || setTimeout)(() => {
      run().catch(() => logger.warn('[diagnostic-archive] cycle_failed')).finally(schedule);
    }, delay);
    timer?.unref?.();
  }
  function start() {
    if (!stopped) return;
    stopped = false;
    run().catch(() => logger.warn('[diagnostic-archive] startup_failed')).finally(schedule);
  }
  function stop() { stopped = true; if (timer != null) (options.clearTimeout || clearTimeout)(timer); }
  return { start, stop, run };
}
module.exports = { createDiagnosticArchive, archiveConfig, archiveClient, objectKey };
