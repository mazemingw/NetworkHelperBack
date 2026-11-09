const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const express = require('express');
const { createDiagnosticsRouter } = require('./diagnostics');
const { cleanDiagnosticReports } = require('./diagnostic-storage');

async function fixture(run) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'nh-diagnostics-test-'));
  const app = express();
  app.use('/diagnostics', createDiagnosticsRouter({ env: { DIAGNOSTIC_REPORT_DIR: directory, DIAGNOSTIC_RETENTION_DAYS: '14' } }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}/diagnostics/`;
  const credentials = { installationId: crypto.randomUUID(), secret: crypto.randomBytes(32).toString('hex') };
  async function post(route, body, auth = true) {
    const response = await fetch(base + route, { method: 'POST', headers: { 'content-type': 'application/json',
      ...(auth ? { authorization: `Bearer ${credentials.installationId}.${credentials.secret}` } : {}) }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  }
  async function stored() {
    const days = (await fs.readdir(directory)).filter(name => /^\d{4}-\d{2}-\d{2}$/.test(name));
    const files = (await Promise.all(days.map(async day => (await fs.readdir(path.join(directory, day)))
      .filter(name => name.endsWith('.json.gz')).map(name => path.join(directory, day, name))))).flat();
    return Promise.all(files.map(async file => ({ file, report: JSON.parse(zlib.gunzipSync(await fs.readFile(file))) })));
  }
  const report = () => ({ schema: 1, id: crypto.randomUUID(), occurredAt: Date.now(), source: 'efs', severity: 'error',
    message: '发现尚未纳入备份的基带存储设备：[/dev/block/sdf2, /dev/block/sdf15]', stack: 'synthetic stack',
    device: { model: 'SYNTHETIC-DEVICE', socModel: 'SM8850', osVersion: '17', imei1: '123456789012345', imeiSource: 'efs_cache' },
    context: { storageTopology: '/dev/block/by-name/modemst1 -> /dev/block/sdf2' }, breadcrumbs: [] });
  try { await run({ post, stored, report, credentials, directory, base }); }
  finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await fs.rm(directory, { recursive: true, force: true }); }
}

test('private POST storage preserves useful device diagnostics and only the explicit IMEI field', () => fixture(async f => {
  assert.equal((await f.post('register', f.credentials, false)).status, 200);
  const report = f.report();
  report.message += ' IMEI=123456789012345 token=secret-token https://oss.example/a?signature=secret';
  report.context.secret = 'private-vault-key';
  report.context.nested = { password: 'not-a-hex-secret', SSID: 'private-network', phoneNumber: 'private-number' };
  report.device.apkSha256 = 'e'.repeat(64);
  report.stack = `\tat app.Reader.read(r8-map-id-${'a'.repeat(64)}:71)`;
  const result = await f.post('reports', report);
  assert.equal(result.status, 200); assert.equal(result.body.ok, true); assert.equal(result.body.id, report.id);
  assert.match(result.body.receiptCode, /^NH-\d{8}-[A-F0-9]{16}$/);
  const [saved] = await f.stored();
  assert.equal(path.basename(saved.file), `${result.body.receiptCode}.json.gz`);
  assert.equal(saved.report.device.imei1, '123456789012345');
  assert.equal(saved.report.device.socModel, 'SM8850');
  assert.equal(saved.report.device.apkSha256, report.device.apkSha256);
  assert.equal(saved.report.stack, report.stack);
  assert.ok(saved.report.message.includes('/dev/block/sdf15'));
  assert.ok(!saved.report.message.includes('123456789012345'));
  assert.ok(!saved.report.message.includes('secret-token'));
  assert.ok(!saved.report.message.includes('signature=secret'));
  assert.equal(saved.report.context.secret, '[REDACTED]');
  assert.deepEqual(saved.report.context.nested, { password: '[REDACTED]', SSID: '[REDACTED]', phoneNumber: '[REDACTED]' });
  assert.ok(!saved.file.includes('123456789012345'));
  assert.equal((await fetch(f.base + 'reports')).status, 404);
}));

test('installation secrets authorize uploads; IMEI and installation ID alone never do', () => fixture(async f => {
  const report = f.report();
  assert.equal((await f.post('reports', report, false)).status, 401);
  assert.equal((await f.post('reports', report)).status, 401);
  assert.equal((await f.post('register', f.credentials, false)).status, 200);
  assert.equal((await f.post('register', { ...f.credentials, secret: 'a'.repeat(64) }, false)).status, 403);
  const good = f.credentials.secret; f.credentials.secret = 'b'.repeat(64);
  assert.equal((await f.post('reports', report)).status, 403); f.credentials.secret = good;
  assert.equal((await f.stored()).length, 0);
}));

test('retries cannot replace an accepted report, and missing IMEI does not block reporting', () => fixture(async f => {
  await f.post('register', f.credentials, false);
  const report = f.report(); report.id = '00000000-0000-4000-8000-000000000000'; delete report.device.imei1;
  assert.equal((await f.post('reports', report)).status, 200);
  report.message = 'changed'; assert.equal((await f.post('reports', report)).status, 200);
  const saved = await f.stored(); assert.equal(saved.length, 1);
  assert.equal(saved[0].report.id, report.id);
  assert.notEqual(saved[0].report.message, 'changed'); assert.equal(saved[0].report.device.imei1, null);
}));

test('invalid IDs, JSON and oversized bodies are rejected without storing files', () => fixture(async f => {
  await f.post('register', f.credentials, false);
  assert.equal((await f.post('reports', { ...f.report(), id: '../../escape' })).status, 400);
  assert.equal((await f.post('reports', { ...f.report(), context: { huge: 'x'.repeat(600000) } })).status, 413);
  assert.equal((await f.post('reports', { ...f.report(), device: null })).status, 400);
  const malformed = await fetch(f.base + 'reports', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{broken' });
  assert.equal(malformed.status, 400); assert.equal((await f.stored()).length, 0);
}));

test('scheduled retention removes old reports and preserves client authorization', () => fixture(async f => {
  await f.post('register', f.credentials, false);
  const old = path.join(f.directory, '2020-01-01'); await fs.mkdir(old); await fs.writeFile(path.join(old, 'a'.repeat(64) + '.json.gz'), 'old');
  assert.equal((await f.post('reports', f.report())).status, 200);
  await cleanDiagnosticReports(f.directory, new Set(), 1073741824);
  await assert.rejects(fs.access(old));
  assert.equal((await f.post('register', f.credentials, false)).status, 200);
}));

test('manual console stores three levels with repeat counts and a stable receipt', () => fixture(async f => {
  await f.post('register', f.credentials, false);
  const report = { ...f.report(), severity: 'info', source: 'console/manual', entries: ['INFO', 'WARNING', 'ERROR'].map((level, id) =>
    ({ id, firstAt: 1000, lastAt: 2000, level, source: 'synthetic', message: 'IMEI1=123456789012345', detail: '', repeats: 55 })) };
  const first = await f.post('console', report), second = await f.post('console', report);
  assert.equal(first.status, 200); assert.equal(first.body.receiptCode, second.body.receiptCode);
  const [saved] = await f.stored();
  assert.equal(saved.report.kind, 'diagnostic-console'); assert.equal(saved.report.entries.length, 3);
  assert.equal(saved.report.entries[0].repeats, 55);
  assert.ok(!saved.report.entries[0].message.includes('123456789012345'));
  assert.equal((await f.post('console', { ...report, id: crypto.randomUUID(), entries: Array(12801).fill(report.entries[0]) })).status, 400);
  assert.equal((await f.post('console', { ...report, id: crypto.randomUUID(), entries: [{ ...report.entries[0], level: 'DEBUG' }] })).status, 400);
}));

test('manual logs larger than the old 512 KiB limit are retained without truncating entries', () => fixture(async f => {
  await f.post('register', f.credentials, false);
  const entry = { firstAt: 1000, lastAt: 2000, level: 'INFO', source: 'synthetic', message: 'x'.repeat(800), detail: '', repeats: 1 };
  const report = { ...f.report(), severity: 'info', source: 'console/manual', entries: Array(1000).fill(entry) };
  assert.ok(Buffer.byteLength(JSON.stringify(report)) > 512 * 1024);
  assert.equal((await f.post('console', report)).status, 200);
  const [saved] = await f.stored(); assert.equal(saved.report.entries.length, 1000);
}));
