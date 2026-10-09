const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createNearbyRouter, parseQuery, buildNearbyQuery, MAX_ROWS_PER_RAT } = require('./nearby');
const { parseNearbyFilters } = require('./nearby-bands');

test('validates coordinates and the complete 1–10 km range', () => {
  for (const radius of [1, 3, 10]) {
    assert.deepEqual(parseQuery({ latitude: '31.2', longitude: '121.5', radius_km: radius }),
      { latitude: 31.2, longitude: 121.5, radiusKm: radius });
  }
  for (const body of [null, [], {}, { latitude: '', longitude: 0, radius_km: 1 },
    { latitude: 91, longitude: 0, radius_km: 1 }, { latitude: 0, longitude: 181, radius_km: 1 },
    { latitude: 0, longitude: 0, radius_km: 0 }, { latitude: 0, longitude: 0, radius_km: 11 },
    { latitude: true, longitude: 0, radius_km: 1 },
    { latitude: 0, longitude: 0, radius_km: '1; DROP TABLE lte_cell_params' }]) {
    assert.equal(parseQuery(body), null);
  }
});

test('uses bound parameters, exact spherical distance and a bounded response', () => {
  const { sql, parameters } = buildNearbyQuery('lte_cell_params', { latitude: 31.2, longitude: 121.5, radiusKm: 3 });
  assert.match(sql, /ASIN/);
  assert.match(sql, /WHERE distance_km <= \?/);
  assert.match(sql, /ORDER BY distance_km ASC, id ASC/);
  assert.match(sql, new RegExp(`LIMIT ${MAX_ROWS_PER_RAT + 1}`));
  assert.equal(parameters.at(-1), 3);
  assert.ok(parameters[3] < 31.2 && parameters[4] > 31.2);
  assert.ok(parameters[5] < 121.5 && parameters[6] > 121.5);
  assert.throws(() => buildNearbyQuery('untrusted_table', { latitude: 0, longitude: 0, radiusKm: 1 }));
});

test('handles the antimeridian and polar searches', () => {
  for (const longitude of [179.999, -179.999]) {
    const query = buildNearbyQuery('nr_cell_params', { latitude: 0, longitude, radiusKm: 10 });
    assert.match(query.sql, /longitude >= \? OR longitude <= \?/);
    assert.ok(query.parameters[5] > query.parameters[6]);
  }
  const polar = buildNearbyQuery('nr_cell_params', { latitude: 90, longitude: 20, radiusKm: 1 });
  assert.equal(polar.parameters.length, 6);
  assert.ok(polar.parameters.every(Number.isFinite));
});

async function withServer(db, callback) {
  const app = express();
  app.use(express.json());
  app.use('/networkhelp', createNearbyRouter(db));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  try { await callback(`http://127.0.0.1:${server.address().port}/networkhelp/cell-params/nearby`); }
  finally { await new Promise(resolve => server.close(resolve)); }
}

test('returns both RATs and explicitly marks truncated results', async () => {
  const calls = [];
  await withServer({ execute: async (sql, parameters) => {
    calls.push({ sql, parameters });
    return [sql.includes('FROM lte_cell_params')
      ? Array.from({ length: MAX_ROWS_PER_RAT + 1 }, (_, id) => ({ id, latitude: 31.2, longitude: 121.5 }))
      : [{ id: 2, gcell_id: '48063443200', latitude: 31.2, longitude: 121.5 }]];
  } }, async url => {
    const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ latitude: 31.2, longitude: 121.5, radius_km: 10 }) });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.ok, true);
    assert.equal(result.coordinate_system, 'WGS84');
    assert.equal(result.lte.length, MAX_ROWS_PER_RAT);
    assert.equal(result.nr.length, 1);
    assert.equal(result.truncated, true);
    assert.equal(result.lte_truncated, true);
    assert.equal(result.nr_truncated, false);
    assert.equal(calls.length, 2);
  });
});

test('rejects invalid requests before touching the database', async () => {
  await withServer({ execute: async () => { throw new Error('must not query'); } }, async url => {
    const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ latitude: 31.2, longitude: 121.5, radius_km: 20 }) });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).ok, false);
  });
});

test('empty areas return successful empty datasets', async () => {
  await withServer({ execute: async () => [[]] }, async url => {
    const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ latitude: 0, longitude: 0, radius_km: 1 }) });
    const result = await response.json();
    assert.deepEqual(result.lte, []);
    assert.deepEqual(result.nr, []);
    assert.equal(result.truncated, false);
  });
});

test('normalizes independent optional RAT and band filters', () => {
  for (const [input, expected] of [
    [{}, { rat: null, band: null }],
    [{ rat: '', band: '' }, { rat: null, band: null }],
    [{ rat: 'ALL', band: null }, { rat: null, band: null }],
    [{ rat: '4g' }, { rat: 'LTE', band: null }],
    [{ rat: '5g' }, { rat: 'NR', band: null }],
    [{ rat: 'lte', band: 3 }, { rat: 'LTE', band: '3' }],
    [{ rat: 'NR', band: ' N78 ' }, { rat: 'NR', band: 'n78' }],
    [{ band: 'b3' }, { rat: null, band: 'B3' }],
    [{ band: 3 }, { rat: null, band: '3' }]
  ]) assert.deepEqual(parseNearbyFilters(input), expected);
  for (const input of [{ rat: 'GSM' }, { rat: 4 }, { band: true }, { band: [] },
    { band: 3.5 }, { band: 0 }, { band: 'B999' }, { band: '3 OR 1=1' }, { band: 'B3,n78' }]) {
    assert.ok(parseNearbyFilters(input).error);
  }
  assert.equal(parseNearbyFilters({ rat: 'LTE', band: 'n78' }).error, 'band_rat_mismatch');
  assert.equal(parseNearbyFilters({ rat: 'NR', band: 'B3' }).error, 'band_rat_mismatch');
});

test('band restriction is applied in SQL before distance ordering and truncation', () => {
  const base = { latitude: 31.2, longitude: 121.5, radiusKm: 3 };
  for (const [table, filters, column, range] of [
    ['lte_cell_params', { rat: 'LTE', band: 'B3' }, 'earfcn', [1200, 1949]],
    ['nr_cell_params', { rat: 'NR', band: 'n78' }, 'nr_arfcn', [620000, 653333]],
    ['lte_cell_params', { band: '3' }, 'earfcn', [1200, 1949]],
    ['nr_cell_params', { band: '3' }, 'nr_arfcn', [361000, 376000]]
  ]) {
    const { sql, parameters } = buildNearbyQuery(table, { ...base, ...filters });
    assert.ok(sql.indexOf(`AND ${column} BETWEEN ? AND ?`) < sql.indexOf(') AS nearby'));
    assert.deepEqual(parameters.slice(-3), [...range, 3]);
  }
  assert.match(buildNearbyQuery('nr_cell_params', { ...base, rat: 'LTE' }).sql, /AND 1 = 0/);
  assert.match(buildNearbyQuery('lte_cell_params', { ...base, band: 'n78' }).sql, /AND 1 = 0/);
});

test('HTTP supports every RAT/band combination and skips unrelated technology queries', async () => {
  const calls = [];
  await withServer({ execute: async (sql, parameters) => {
    calls.push({ sql, parameters });
    return [[{ id: 1 }]];
  } }, async url => {
    for (const [filters, expectedLte, expectedNr, expectedCalls] of [
      [{}, 1, 1, 2],
      [{ rat: 'LTE' }, 1, 0, 1],
      [{ rat: 'NR' }, 0, 1, 1],
      [{ rat: '4G', band: 3 }, 1, 0, 1],
      [{ rat: '5G', band: 'n78' }, 0, 1, 1],
      [{ band: 3 }, 1, 1, 2],
      [{ band: 'B3' }, 1, 0, 1],
      [{ band: 'n78' }, 0, 1, 1],
      [{ band: 78 }, 0, 1, 1],
      [{ rat: null, band: null }, 1, 1, 2]
    ]) {
      calls.length = 0;
      const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ latitude: 31.2, longitude: 121.5, radius_km: 3, ...filters }) });
      assert.equal(response.status, 200, JSON.stringify(filters));
      const result = await response.json();
      assert.equal(result.lte.length, expectedLte);
      assert.equal(result.nr.length, expectedNr);
      assert.equal(calls.length, expectedCalls);
      if (filters.band) assert.ok(calls.every(call => /(?:earfcn|nr_arfcn) BETWEEN \? AND \?/.test(call.sql)));
    }
  });
});

test('invalid or conflicting filters produce explicit HTTP 400 without querying', async () => {
  await withServer({ execute: async () => { throw new Error('must not query'); } }, async url => {
    for (const [filters, error] of [
      [{ rat: 'GSM' }, 'invalid_rat'],
      [{ band: 'B999' }, 'invalid_band'],
      [{ rat: 'LTE', band: 'n78' }, 'band_rat_mismatch'],
      [{ rat: 'NR', band: 'B3' }, 'band_rat_mismatch']
    ]) {
      const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ latitude: 31.2, longitude: 121.5, radius_km: 3, ...filters }) });
      assert.equal(response.status, 400);
      assert.equal((await response.json()).error, error);
    }
  });
});
