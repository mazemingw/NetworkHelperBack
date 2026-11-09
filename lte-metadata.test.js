const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const express = require('express');
const { readLteMetadata, lteMetadataChunks } = require('./lte-metadata');

test('metadata accepts both naming conventions, preserves escaped business text and validates station types', () => {
  const extra = '地址=A\\,B楼,厂商=华为';
  assert.equal(readLteMetadata({ extraInfo: extra, stationType: 'NB-IoT' }).extra_info, extra);
  assert.equal(readLteMetadata({ stationType: 'NB-IoT' }).station_type, 'nb-iot');
  assert.equal(readLteMetadata({}).extraProvided, false);
  assert.equal(readLteMetadata({}).stationProvided, false);
  assert.equal(readLteMetadata({ extra_info: null }).extraProvided, true);
  assert.throws(() => readLteMetadata({ extra_info: {} }), /invalid_extra_info/);
  assert.throws(() => readLteMetadata({ station_type: 'macro' }), /invalid_station_type/);
});

test('batch chunks retain original row order and separate omitted fields from explicit clears', () => {
  const rows = [{ eci: 1 }, { eci: 2, extra_info: null }, { eci: 1, extra_info: 'a=b', station_type: 'nb-iot' }, { eci: 3 }]
    .map(row => ({ ...row, ...readLteMetadata(row) }));
  const chunks = [...lteMetadataChunks(rows, 2)];
  assert.deepEqual(chunks.flat().map(row => row.eci), [1, 2, 1, 3]);
  for (const chunk of chunks) assert.ok(chunk.every(row => row.extraProvided === chunk[0].extraProvided && row.stationProvided === chunk[0].stationProvided));
});

// Inject an in-memory database adapter before importing routes: no real database is touched.
const statements = [];
const row = { id: 1, eci: 25601, enodeb_id: 100, cell_id: 1, tac: 9, earfcn: 38650, pci: 10,
  latitude: 31, longitude: 121, site_type: '室分', extra_info: '厂商=华为,地址=A\\,B楼', station_type: 'nb-iot' };
const database = {
  execute: async (sql, values) => {
    statements.push({ sql, values });
    if (sql.includes('UPDATE lte_cell_params')) return [{ affectedRows: 1 }];
    if (sql.includes('nr_cell_params')) return [[]];
    return [/COUNT\(\*\)/.test(sql) ? [{ total: 1 }] : [row]];
  },
  query: async (sql, values) => { statements.push({ sql, values }); return [{ affectedRows: 1 }]; }
};
require.cache[require.resolve('./db')] = { exports: database };
process.env.DEV_AUTH_TOKEN_SECRET = 'cell-metadata-local-test';
const router = require('./routes');

async function withServer(callback) {
  const app = express();
  app.use(express.json()); app.use(router);
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  async function post(path, body) {
    const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    });
    return { status: response.status, data: await response.json() };
  }
  try { await callback(post); }
  finally { await new Promise(resolve => server.close(resolve)); }
}

test('cell, site anchor, site rows and nearby responses retain the new fields', async () => {
  await withServer(async post => {
    const cell = await post('/lte/cell-params/query', { eci: row.eci });
    const site = await post('/lte/site/query', { eci: row.eci });
    const nearby = await post('/cell-params/nearby', { latitude: 31, longitude: 121, radius_km: 1 });
    assert.equal(cell.status, 200); assert.equal(site.status, 200); assert.equal(nearby.status, 200);
    for (const item of [cell.data.data[0], site.data.anchor, site.data.data[0], nearby.data.lte[0]]) {
      assert.equal(item.extra_info, row.extra_info);
      assert.equal(item.station_type, row.station_type);
    }
  });
});

test('batch imports bind metadata and older clients cannot erase existing fields', async () => {
  statements.length = 0;
  await withServer(async post => {
    const result = await post('/lte/cell-params/batch-upsert', { items: [{ eci: 25601 },
      { eci: 25602, extra_info: row.extra_info, station_type: 'nb-iot' }] });
    assert.equal(result.status, 200); assert.equal(result.data.success, 2);
    const inserts = statements.filter(call => call.sql.includes('INSERT INTO lte_cell_params'));
    assert.equal(inserts.length, 2);
    assert.equal(inserts[0].values.length, 17);
    assert.doesNotMatch(inserts[0].sql.split('ON DUPLICATE KEY UPDATE')[1], /extra_info|station_type/);
    assert.match(inserts[1].sql.split('ON DUPLICATE KEY UPDATE')[1], /extra_info = VALUES\(extra_info\)/);
    assert.match(inserts[1].sql.split('ON DUPLICATE KEY UPDATE')[1], /station_type = VALUES\(station_type\)/);
    assert.deepEqual(inserts[1].values.slice(-2), [row.extra_info, 'nb-iot']);
  });
});

test('admin can update or clear extra information without changing omitted fields', async () => {
  const payload = Buffer.from(JSON.stringify({ role: 'super_admin', exp: Date.now() + 60000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', process.env.DEV_AUTH_TOKEN_SECRET).update(payload).digest('base64url');
  statements.length = 0;
  await withServer(async post => {
    const response = await post('/lte/cell-params/update', { id: 1, auth_token: `${payload}.${signature}`, extra_info: null });
    assert.equal(response.status, 200);
    const update = statements.find(call => call.sql.includes('UPDATE lte_cell_params'));
    assert.match(update.sql, /extra_info = \?/);
    assert.doesNotMatch(update.sql, /station_type =/);
    assert.deepEqual(update.values, [null, 1]);
  });
});
