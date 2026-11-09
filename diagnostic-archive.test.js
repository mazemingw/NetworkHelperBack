const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const { Readable } = require('node:stream');
const { createDiagnosticArchive } = require('./diagnostic-archive');
const { publishDiagnostic } = require('./diagnostic-storage');
const now = Date.parse('2026-11-10T15:47:00Z');
const day = 86400000;

async function fixture(run) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'nh-archive-test-'));
  const env = { DIAGNOSTIC_REPORT_DIR: root, OSS_BUCKET: 'private-diagnostics', OSS_REGION: 'cn-test',
    OSS_ACCESS_KEY_ID: 'SYNTHETIC', OSS_ACCESS_KEY_SECRET: 'test-only' };
  const objects = new Map(), calls = [];
  const control = { corrupt: false, hold: null };
  const client = {
    async put(key, file, options) {
      calls.push(key); if (control.hold) await control.hold;
      if (objects.has(key)) throw Object.assign(new Error('exists'), { status: 409 });
      assert.equal(options.headers['x-oss-forbid-overwrite'], 'true');
      objects.set(key, { bytes: await fs.readFile(file), acl: options.headers['x-oss-object-acl'] });
    },
    async getACL(key) { return { acl: objects.get(key).acl }; },
    async getStream(key) { const bytes = objects.get(key).bytes; return { stream: Readable.from([control.corrupt ? Buffer.alloc(bytes.length, 1) : bytes]) }; },
  };
  let sequence = 0;
  async function file(daysAgo) {
    const createdAt = now - daysAgo * day, date = new Date(createdAt).toISOString().slice(0, 10);
    const directory = path.join(root, date); await fs.mkdir(directory, { recursive: true });
    const name = `NH-${date.replace(/-/g, '')}-${(++sequence).toString(16).toUpperCase().padStart(16, '0')}.json.gz`;
    const selected = path.join(directory, name);
    const bytes = zlib.gzipSync(Buffer.from(JSON.stringify({ synthetic: true, message: `test ${sequence}` })));
    await fs.writeFile(selected, bytes); await fs.utimes(selected, createdAt / 1000, createdAt / 1000);
    return { file: selected, day: date, name, bytes };
  }
  function archive(options = {}) { return createDiagnosticArchive({ env, now: () => now, clientFor: () => client,
    logger: { info() {}, warn() {} }, ...options }); }
  try { await run({ root, env, file, archive, objects, calls, control }); }
  finally {
    assert.equal(path.dirname(root), path.resolve(os.tmpdir()));
    assert.ok(path.basename(root).startsWith('nh-archive-test-'));
    await fs.rm(root, { recursive: true, force: true });
  }
}

test('hourly archive uploads private immutable bytes, verifies them and skips previously verified files', () => fixture(async f => {
  const saved = await f.file(0); const archive = f.archive();
  const first = await archive.run(); assert.equal(first.uploaded, 1); assert.equal(first.failed, 0);
  const [key] = f.objects.keys(); assert.equal(key, `DIAGNOSTICS/${saved.day}/${saved.name}`);
  assert.deepEqual(f.objects.get(key).bytes, saved.bytes); assert.equal(f.objects.get(key).acl, 'private');
  const second = await archive.run(); assert.equal(second.previouslyArchived, 1); assert.equal(f.calls.length, 1);
}));

test('files older than seven days are archived then removed while recent files and client credentials survive', () => fixture(async f => {
  const old = await f.file(8), recent = await f.file(6);
  const clients = path.join(f.root, 'clients'); await fs.mkdir(clients); await fs.writeFile(path.join(clients, 'synthetic.json'), 'authorization hash');
  const result = await f.archive().run(); assert.equal(result.uploaded, 2); assert.equal(result.deleted, 1);
  assert.equal(result.unarchivedExpired, 0); await assert.rejects(fs.access(old.file)); await fs.access(recent.file);
  await fs.access(path.join(clients, 'synthetic.json')); assert.equal(f.objects.size, 2);
}));

test('bad remote checksums are not verified; the explicit seven-day cap still expires old failed archives', () => fixture(async f => {
  const old = await f.file(8), recent = await f.file(1); f.control.corrupt = true;
  const result = await f.archive().run(); assert.equal(result.failed, 2); assert.equal(result.uploaded, 0);
  assert.equal(result.unarchivedExpired, 1); await assert.rejects(fs.access(old.file)); await fs.access(recent.file);
  try { assert.deepEqual(JSON.parse(await fs.readFile(path.join(f.root, recent.day, '.oss-index.json'), 'utf8')), {}); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
}));

test('storage pressure evicts only archived recent logs and never deletes OSS objects', () => fixture(async f => {
  await f.file(2); await f.file(1);
  const result = await f.archive({ maxLocalBytes: 1 }).run();
  assert.equal(result.uploaded, 2); assert.equal(result.deleted, 2); assert.equal(result.localBytes, 0);
  assert.equal(result.unarchivedExpired, 0); assert.equal(f.objects.size, 2);
}));

test('a rejected admission requests headroom even while local bytes are below the quota', () => fixture(async f => {
  await f.file(1);
  const result = await f.archive().run({ storagePressure: true });
  assert.equal(result.storagePressure, true); assert.equal(result.deleted, 1);
  assert.equal(result.localBytes, 0); assert.equal(f.objects.size, 1);
}));

test('maintenance is single-flight and schedules the next hourly boundary', () => fixture(async f => {
  await f.file(0); let release;
  f.control.hold = new Promise(resolve => { release = resolve; });
  const archive = f.archive(); const first = archive.run(), second = archive.run(); assert.strictEqual(first, second);
  release(); await first; assert.equal(f.calls.length, 1);
  const timers = [], cleared = [];
  const scheduled = f.archive({ setTimeout(callback, delay) { const token = { callback, delay, unref() {} }; timers.push(token); return token; },
    clearTimeout(token) { cleared.push(token); } });
  scheduled.start(); await scheduled.run(); await new Promise(resolve => setImmediate(resolve));
  assert.equal(timers.length, 1); assert.equal(timers[0].delay, 13 * 60000);
  scheduled.stop(); assert.equal(cleared.length, 1);
}));

test('concurrent publication cannot exceed the shared local disk budget', () => fixture(async f => {
  const directory = path.join(f.root, '2026-11-10'); await fs.mkdir(directory);
  const publish = index => publishDiagnostic(f.root, path.join(directory, `NH-20261110-${String(index).padStart(16, '0')}.json.gz`),
    path.join(directory, `.${index}.tmp`), Buffer.alloc(20, 0), 30);
  const results = await Promise.allSettled([publish(1), publish(2)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  const rejected = results.find(result => result.status === 'rejected'); assert.equal(rejected.reason.status, 503);
}));

test('index persistence failures cannot prevent the seven-day cleanup', () => fixture(async f => {
  const old = await f.file(8), recent = await f.file(1);
  const result = await f.archive({ writeIndex: async () => { throw Object.assign(new Error('full'), { code: 'ENOSPC' }); } }).run();
  assert.equal(result.indexWriteFailed, true); assert.equal(result.deleted, 1);
  assert.equal(result.unarchivedExpired, 0); assert.equal(f.objects.size, 2);
  await assert.rejects(fs.access(old.file)); await fs.access(recent.file);
}));

test('an OSS outage stops repeated cloud attempts but still executes retention', () => fixture(async f => {
  for (let index = 0; index < 6; index++) await f.file(8);
  let attempts = 0;
  const result = await f.archive({ clientFor: () => ({ async put() { attempts++; throw new Error('offline'); } }) }).run();
  assert.equal(attempts, 3); assert.equal(result.cloudCircuitOpen, true);
  assert.equal(result.deleted, 6); assert.equal(result.unarchivedExpired, 6);
}));
