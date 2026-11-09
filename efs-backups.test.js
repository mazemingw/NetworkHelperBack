const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Readable } = require('node:stream');
const express = require('express');
const { createEfsBackupRouter } = require('./efs-backups');

const env = { OSS_BUCKET: 'private-backups', OSS_REGION: 'cn-test', OSS_ACCESS_KEY_ID: 'TEST', OSS_ACCESS_KEY_SECRET: 'test-secret' };
const model = 'PLK110', imei = '123456789012345'; // synthetic data only
const data = Buffer.from('synthetic partition archive');
const sha = crypto.createHash('sha256').update(data).digest('hex');
async function fixture(run) {
  const vaults = new Map(), backups = new Map();
  const controls = { bytes: data, acl: 'private' };
  const store = {
    async vault(id) { return vaults.get(id); },
    async register(v) { if (!vaults.has(v.vault_id)) vaults.set(v.vault_id, v); },
    async prepare(b) { backups.set(b.backup_id, { ...b, status: 'SIGNED' }); },
    async backup(v, id) { const b = backups.get(id); return b?.vault_id === v ? b : null; },
    async complete(v, id) { (await this.backup(v, id)).status = 'VERIFIED'; },
    async latest(v, id) { return [...backups.values()].find(b => b.vault_id === v && b.status === 'VERIFIED' && (!id || b.backup_id === id)); }
  };
  const app = express(); app.use(express.json());
  app.use('/efs', createEfsBackupRouter(null, { env, store, clientFor: () => ({
    getACL: async () => ({ acl: controls.acl }),
    getStream: async () => ({ stream: Readable.from([controls.bytes]) }),
    signatureUrl: key => 'https://private-backups.oss-cn-test.aliyuncs.com/' + key + '?signed=test'
  }) }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}/efs/`;
  async function post(route, body, credentials) {
    const response = await fetch(base + route, { method: 'POST', headers: { 'content-type': 'application/json',
      ...(credentials ? { authorization: `Bearer ${credentials.id}.${credentials.secret}` } : {}) }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  }
  async function register() {
    const credentials = { id: crypto.randomUUID(), secret: crypto.randomBytes(32).toString('hex') };
    assert.equal((await post('register', { model, imei, vaultId: credentials.id, secret: credentials.secret })).status, 200);
    return credentials;
  }
  async function prepare(credentials) { return post('prepare', { model, imei, size: data.length, sha256: sha }, credentials); }
  try { await run({ post, register, prepare, controls, backups }); }
  finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}

test('private upload has exact scoped key, completes only after server streaming checksum, then downloads', () => fixture(async f => {
  const user = await f.register();
  const signed = await f.prepare(user);
  assert.equal(signed.status, 200);
  assert.match(signed.body.fields.key, new RegExp(`^EFS-BACKUP/${model}/${imei}/${user.id}/`));
  assert.equal(signed.body.fields['x-oss-object-acl'], 'private');
  assert.equal(signed.body.fields['x-oss-forbid-overwrite'], 'true');
  const policy = JSON.parse(Buffer.from(signed.body.fields.policy, 'base64'));
  assert.ok(policy.conditions.some(v => Array.isArray(v) && v[1] === '$key' && v[2] === signed.body.fields.key));
  const id = signed.body.backupId;
  assert.equal((await f.post('download', { model, imei, backupId: id }, user)).status, 404);
  const verified = await f.post('complete', { backupId: id }, user);
  assert.equal(verified.status, 200); assert.equal(verified.body.verified, true); assert.equal(verified.body.sha256, sha);
  const download = await f.post('download', { model, imei, backupId: id }, user);
  assert.equal(download.status, 200); assert.match(download.body.downloadUrl, /^https:/); assert.equal(download.body.expiresInSeconds, 300);
}));
test('IMEI alone cannot read a backup and a different vault cannot complete it', () => fixture(async f => {
  const owner = await f.register(), other = await f.register();
  const signed = await f.prepare(owner);
  assert.equal((await f.post('download', { model, imei })).status, 401);
  assert.equal((await f.post('complete', { backupId: signed.body.backupId }, other)).status, 404);
  assert.equal((await f.post('download', { model, imei: '543210987654321' }, owner)).status, 403);
  assert.equal((await f.post('register', { model, imei, vaultId: owner.id, secret: other.secret })).status, 403);
}));
test('same-length tampering and partial uploads are never verified', () => fixture(async f => {
  const owner = await f.register(); const signed = await f.prepare(owner); const id = signed.body.backupId;
  f.controls.bytes = Buffer.alloc(data.length, 1);
  assert.equal((await f.post('complete', { backupId: id }, owner)).status, 409);
  assert.equal(f.backups.get(id).status, 'SIGNED');
  f.controls.bytes = data.subarray(0, data.length - 1);
  assert.equal((await f.post('complete', { backupId: id }, owner)).status, 409);
}));
test('public object ACL is refused even when checksum matches', () => fixture(async f => {
  const owner = await f.register(); const signed = await f.prepare(owner);
  f.controls.acl = 'public-read';
  assert.equal((await f.post('complete', { backupId: signed.body.backupId }, owner)).status, 409);
}));
test('missing or invalid identity and out-of-range archive metadata are refused', () => fixture(async f => {
  const owner = await f.register();
  assert.equal((await f.post('prepare', { model, imei: '', size: 1, sha256: sha }, owner)).status, 400);
  assert.equal((await f.post('prepare', { model, imei, size: 0, sha256: sha }, owner)).status, 400);
  assert.equal((await f.post('prepare', { model, imei, size: 2147483649, sha256: sha }, owner)).status, 400);
  assert.equal((await f.post('prepare', { model, imei, size: 1, sha256: 'bad' }, owner)).status, 400);
}));
test('default recovery always selects the first verified baseline', () => fixture(async f => {
  const owner = await f.register(); const first = await f.prepare(owner); const second = await f.prepare(owner);
  await f.post('complete', { backupId: first.body.backupId }, owner);
  await f.post('complete', { backupId: second.body.backupId }, owner);
  assert.equal((await f.post('download', { model, imei }, owner)).body.backupId, first.body.backupId);
}));
