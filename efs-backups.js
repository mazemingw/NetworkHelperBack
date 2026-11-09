// Private per-device EFS backup vaults. IMEI is an index, never an access credential.
const express = require('express');
const crypto = require('node:crypto');
const OSS = require('ali-oss');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{64}$/;
function fail(status, message) { const error = new Error(message); error.status = status; throw error; }
function identity(body) {
  const model = String(body.model || '').trim();
  const imei = String(body.imei || '').trim();
  if (!/^[A-Za-z0-9_. -]{1,64}$/.test(model) || !/^\d{15}$/.test(imei) || /^0+$/.test(imei)) fail(400, 'invalid_device_identity');
  return { model, imei };
}
function sameToken(secret, expected) {
  const actual = Buffer.from(hash(secret), 'hex');
  const wanted = Buffer.from(expected || '', 'hex');
  return actual.length === wanted.length && crypto.timingSafeEqual(actual, wanted);
}
function sqlStore(db) {
  return {
    async vault(id) { const [rows] = await db.execute('SELECT * FROM efs_backup_vaults WHERE vault_id = ?', [id]); return rows[0]; },
    async register(v) {
      await db.execute('INSERT IGNORE INTO efs_backup_vaults (vault_id, token_sha256, model, imei) VALUES (?, ?, ?, ?)',
        [v.vault_id, v.token_sha256, v.model, v.imei]);
    },
    async prepare(b) {
      await db.execute(`INSERT INTO efs_partition_backups
        (backup_id, vault_id, oss_bucket, oss_region, object_key, archive_sha256, archive_bytes, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'SIGNED')`,
      [b.backup_id, b.vault_id, b.oss_bucket, b.oss_region, b.object_key, b.archive_sha256, b.archive_bytes]);
    },
    async backup(vault, id) {
      const [rows] = await db.execute('SELECT * FROM efs_partition_backups WHERE vault_id = ? AND backup_id = ?', [vault, id]);
      return rows[0];
    },
    async complete(vault, id) {
      await db.execute("UPDATE efs_partition_backups SET status = 'VERIFIED', verified_at = CURRENT_TIMESTAMP WHERE vault_id = ? AND backup_id = ?", [vault, id]);
    },
    async latest(vault, id) {
      // Default to the first verified baseline, never a newer potentially modified state.
      const [rows] = await db.execute(`SELECT * FROM efs_partition_backups WHERE vault_id = ? AND status = 'VERIFIED'
        ${id ? 'AND backup_id = ?' : ''} ORDER BY created_at ASC, backup_id ASC LIMIT 1`, id ? [vault, id] : [vault]);
      return rows[0];
    }
  };
}

function createEfsBackupRouter(db, options = {}) {
  const router = express.Router();
  const env = options.env || process.env;
  const store = options.store || sqlStore(db);
  const clientFor = options.clientFor || (config => new OSS({ region: 'oss-' + config.region, bucket: config.bucket,
    accessKeyId: config.id, accessKeySecret: config.secret, stsToken: config.token || undefined,
    secure: true, timeout: 10 * 60 * 1000 }));
  const config = () => {
    const result = {
      bucket: env.EFS_OSS_BUCKET || env.OSS_BUCKET,
      region: String(env.EFS_OSS_REGION || env.OSS_REGION || '').replace(/^oss-/, '').replace(/\.aliyuncs\.com$/, ''),
      id: env.OSS_ACCESS_KEY_ID, secret: env.OSS_ACCESS_KEY_SECRET, token: env.OSS_SECURITY_TOKEN,
      maxBytes: Number(env.EFS_BACKUP_MAX_BYTES || 2147483648)
    };
    if (!/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(result.bucket || '') ||
        !/^[a-z0-9-]+$/.test(result.region) || !result.id || !result.secret ||
        !Number.isSafeInteger(result.maxBytes) || result.maxBytes < 1) fail(503, 'efs_oss_not_configured');
    return result;
  };
  const wrap = fn => async (req, res) => {
    try { await fn(req, res); }
    catch (error) {
      // No IMEI, secrets, signed URLs or raw OSS errors in logs/responses.
      if (!error.status) console.error('[efs-backups] operation_failed', error.code || error.name);
      res.status(error.status || 502).json({ ok: false, error: error.status ? error.message : 'efs_storage_operation_failed' });
    }
  };
  async function authorize(req) {
    const match = /^Bearer ([0-9a-f-]{36})\.([0-9a-f]{64})$/.exec(req.get('authorization') || '');
    if (!match || !UUID.test(match[1])) fail(401, 'efs_vault_authorization_required');
    const vault = await store.vault(match[1]);
    if (!vault || !sameToken(match[2], vault.token_sha256)) fail(403, 'efs_vault_authorization_failed');
    return vault;
  }
  function owns(vault, body) {
    const selected = identity(body);
    if (vault.model !== selected.model || vault.imei !== selected.imei) fail(403, 'efs_device_mismatch');
    return selected;
  }
  const receipt = b => ({ backupId: b.backup_id, sha256: b.archive_sha256, size: Number(b.archive_bytes), verified: true });

  router.post('/register', wrap(async (req, res) => {
    config();
    const selected = identity(req.body);
    const id = String(req.body.vaultId || '');
    const secret = String(req.body.secret || '');
    if (!UUID.test(id) || !SHA.test(secret)) fail(400, 'invalid_vault_credentials');
    await store.register({ vault_id: id, token_sha256: hash(secret), ...selected });
    const saved = await store.vault(id);
    if (!saved || !sameToken(secret, saved.token_sha256)) fail(403, 'efs_vault_authorization_failed');
    owns(saved, selected);
    res.json({ ok: true, vaultId: id });
  }));
  router.post('/prepare', wrap(async (req, res) => {
    const vault = await authorize(req); owns(vault, req.body);
    const cfg = config();
    const size = req.body.size;
    const sha256 = String(req.body.sha256 || '');
    if (!Number.isSafeInteger(size) || size < 1 || size > cfg.maxBytes || !SHA.test(sha256)) fail(400, 'invalid_archive_metadata');
    const id = crypto.randomUUID();
    const model = vault.model.replace(/[^A-Za-z0-9_.-]/g, '_');
    const key = `EFS-BACKUP/${model}/${vault.imei}/${vault.vault_id}/${id}.zip`;
    await store.prepare({ backup_id: id, vault_id: vault.vault_id, oss_bucket: cfg.bucket,
      oss_region: cfg.region, object_key: key, archive_sha256: sha256, archive_bytes: size });
    const expiration = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    const conditions = [ ['content-length-range', 1, Math.min(cfg.maxBytes + 65536, size + 65536)], { bucket: cfg.bucket },
      ['eq', '$key', key], ['eq', '$x-oss-object-acl', 'private'], ['eq', '$x-oss-forbid-overwrite', 'true'],
      ['eq', '$x-oss-meta-sha256', sha256], ...(cfg.token ? [['eq', '$x-oss-security-token', cfg.token]] : []) ];
    const policy = Buffer.from(JSON.stringify({ expiration, conditions })).toString('base64');
    res.json({ ok: true, backupId: id, host: `https://${cfg.bucket}.oss-${cfg.region}.aliyuncs.com`,
      fields: { key, policy, OSSAccessKeyId: cfg.id, signature: crypto.createHmac('sha1', cfg.secret).update(policy).digest('base64'),
        'x-oss-object-acl': 'private', 'x-oss-forbid-overwrite': 'true', 'x-oss-meta-sha256': sha256,
        success_action_status: '200', ...(cfg.token ? { 'x-oss-security-token': cfg.token } : {}) } });
  }));
  router.post('/complete', wrap(async (req, res) => {
    const vault = await authorize(req);
    const id = String(req.body.backupId || '');
    if (!UUID.test(id)) fail(400, 'invalid_backup_id');
    const backup = await store.backup(vault.vault_id, id);
    if (!backup) fail(404, 'backup_not_found');
    if (backup.status === 'VERIFIED') return res.json({ ok: true, ...receipt(backup) });
    const cfg = config();
    if (backup.oss_bucket !== cfg.bucket || backup.oss_region !== cfg.region) fail(409, 'storage_configuration_changed');
    const oss = clientFor(cfg);
    const acl = await oss.getACL(backup.object_key);
    if (acl.acl !== 'private') fail(409, 'backup_object_must_be_private');
    const result = await oss.getStream(backup.object_key);
    const digest = crypto.createHash('sha256');
    let bytes = 0;
    try {
      for await (const chunk of result.stream) {
        bytes += chunk.length;
        if (bytes > Number(backup.archive_bytes) || bytes > cfg.maxBytes) fail(409, 'uploaded_size_mismatch');
        digest.update(chunk);
      }
    } finally { result.stream.destroy(); }
    if (bytes !== Number(backup.archive_bytes) || digest.digest('hex') !== backup.archive_sha256) fail(409, 'uploaded_checksum_mismatch');
    await store.complete(vault.vault_id, id);
    res.json({ ok: true, ...receipt(backup) });
  }));
  router.post('/download', wrap(async (req, res) => {
    const vault = await authorize(req); owns(vault, req.body);
    const id = String(req.body.backupId || '');
    if (id && !UUID.test(id)) fail(400, 'invalid_backup_id');
    const backup = await store.latest(vault.vault_id, id || null);
    if (!backup) fail(404, 'verified_backup_not_found');
    const cfg = config();
    if (backup.oss_bucket !== cfg.bucket || backup.oss_region !== cfg.region) fail(409, 'storage_configuration_changed');
    const oss = clientFor(cfg);
    if ((await oss.getACL(backup.object_key)).acl !== 'private') fail(409, 'backup_object_must_be_private');
    const downloadUrl = oss.signatureUrl(backup.object_key, { expires: 300 });
    res.json({ ok: true, ...receipt(backup), downloadUrl, expiresInSeconds: 300 });
  }));
  return router;
}
module.exports = { createEfsBackupRouter, identity, sameToken };
