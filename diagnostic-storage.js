const fs = require('node:fs/promises');
const path = require('node:path');

const DAY = /^\d{4}-\d{2}-\d{2}$/;
const REPORT = /^(?:NH-\d{8}-[A-F0-9]{16}|[a-f0-9]{64})\.json\.gz$/;
const RETENTION_MS = 7 * 86400000;
const states = new Map();
function diagnosticRoot(env = process.env) {
  const root = path.resolve(env.DIAGNOSTIC_REPORT_DIR || path.join(__dirname, 'data', 'diagnostics'));
  if (root === path.parse(root).root) throw new Error('diagnostic_directory_must_not_be_filesystem_root');
  return root;
}
function localLimit(env = process.env) {
  const value = Number(env.DIAGNOSTIC_MAX_LOCAL_BYTES || 1073741824);
  if (!Number.isSafeInteger(value) || value < 16 * 1024 * 1024) throw new Error('invalid_diagnostic_disk_limit');
  return value;
}
function state(root) {
  if (!states.has(root)) states.set(root, { tail: Promise.resolve(), bytes: null, scannedAt: 0 });
  return states.get(root);
}
function withDiagnosticLock(root, operation) {
  const entry = state(root);
  const task = entry.tail.catch(() => {}).then(operation);
  entry.tail = task.catch(() => {});
  return task;
}
async function reportFiles(root) {
  await fs.mkdir(root, { recursive: true, mode: 0o700 });
  const result = [];
  for (const day of await fs.readdir(root, { withFileTypes: true })) {
    if (!DAY.test(day.name) || !day.isDirectory() || day.isSymbolicLink()) continue;
    const directory = path.join(root, day.name);
    const start = Date.parse(`${day.name}T00:00:00.000Z`);
    if (!Number.isFinite(start)) continue;
    for (const item of await fs.readdir(directory, { withFileTypes: true })) {
      if (!REPORT.test(item.name) || !item.isFile() || item.isSymbolicLink()) continue;
      const file = path.join(directory, item.name);
      let stat; try { stat = await fs.lstat(file); } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
      if (!stat.isFile() || stat.isSymbolicLink()) continue;
      const createdAt = stat.mtimeMs >= start && stat.mtimeMs < start + 86400000 ? stat.mtimeMs : start;
      result.push({ file, day: day.name, name: item.name, size: stat.size, createdAt });
    }
  }
  return result.sort((a, b) => a.createdAt - b.createdAt || a.name.localeCompare(b.name));
}
function updateUsage(root, bytes) { const entry = state(root); entry.bytes = bytes; entry.scannedAt = Date.now(); }

/** Serialize admission with retention so simultaneous uploads cannot bypass the disk budget. */
async function publishDiagnostic(root, file, temporary, bytes, maximum) {
  return withDiagnosticLock(root, async () => {
    try { await fs.access(file); return; } catch (error) { if (error.code !== 'ENOENT') throw error; }
    const entry = state(root);
    if (entry.bytes == null || Date.now() - entry.scannedAt > 60000 || entry.bytes + bytes.length > maximum)
      updateUsage(root, (await reportFiles(root)).reduce((sum, item) => sum + item.size, 0));
    if (entry.bytes + bytes.length > maximum) throw Object.assign(new Error('diagnostic_local_storage_full'), { status: 503 });
    if (typeof fs.statfs === 'function') {
      const disk = await fs.statfs(root);
      if (disk.bavail * disk.bsize < bytes.length + 256 * 1024 * 1024)
        throw Object.assign(new Error('diagnostic_disk_space_low'), { status: 503 });
    }
    try {
      await fs.writeFile(temporary, bytes, { flag: 'wx', mode: 0o600 });
      try { await fs.link(temporary, file); entry.bytes += bytes.length; }
      catch (error) { if (error.code !== 'EEXIST') throw error; }
    } finally { await fs.unlink(temporary).catch(() => {}); }
  });
}

/** File-only cleanup; never follows links, recurses through unknown directories or touches clients/. */
async function cleanDiagnosticReports(root, verified, maximum, now = Date.now()) {
  return withDiagnosticLock(root, async () => {
    const files = await reportFiles(root);
    const removed = [], unarchived = [];
    let bytes = files.reduce((sum, file) => sum + file.size, 0);
    for (const item of files) {
      const expired = item.createdAt <= now - RETENTION_MS;
      const archived = verified.has(item.file);
      if (!expired && (bytes <= maximum || !archived)) continue;
      await fs.unlink(item.file);
      bytes -= item.size; removed.push(item);
      if (!archived) unarchived.push(item.name);
    }
    for (const day of await fs.readdir(root, { withFileTypes: true })) {
      if (!DAY.test(day.name) || !day.isDirectory() || day.isSymbolicLink()) continue;
      const directory = path.join(root, day.name);
      for (const name of await fs.readdir(directory)) {
        if (!/^\.[0-9a-f-]{36}\.tmp$/.test(name)) continue;
        const file = path.join(directory, name), stat = await fs.lstat(file);
        if (stat.isFile() && stat.mtimeMs < now - 3600000) await fs.unlink(file);
      }
      const remaining = await fs.readdir(directory);
      if (remaining.every(name => name === '.oss-index.json')) {
        if (remaining.length) {
          const index = path.join(directory, '.oss-index.json'), stat = await fs.lstat(index);
          if (stat.isFile() && !stat.isSymbolicLink()) await fs.unlink(index);
        }
        await fs.rmdir(directory).catch(error => { if (error.code !== 'ENOTEMPTY') throw error; });
      }
    }
    updateUsage(root, bytes);
    return { deleted: removed.length, unarchivedExpired: unarchived.length, localBytes: bytes, unarchivedExamples: unarchived.slice(0, 5) };
  });
}
module.exports = { diagnosticRoot, localLimit, reportFiles, publishDiagnostic, cleanDiagnosticReports, RETENTION_MS };
