const express = require('express');
const { parseNearbyFilters, selectTableBand } = require('./nearby-bands');

const EARTH_RADIUS_KM = 6371.0088;
const MAX_ROWS_PER_RAT = 1000;

function finiteNumber(value) {
  if (typeof value !== 'number' && typeof value !== 'string') return null;
  if (typeof value === 'string' && !value.trim()) return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function parseQuery(body = {}) {
  if (body == null || typeof body !== 'object' || Array.isArray(body)) return null;
  const latitude = finiteNumber(body.latitude);
  const longitude = finiteNumber(body.longitude);
  const radiusKm = finiteNumber(body.radius_km);
  if (latitude == null || longitude == null || radiusKm == null ||
      Math.abs(latitude) > 90 || Math.abs(longitude) > 180 ||
      radiusKm < 1 || radiusKm > 10) return null;
  const filters = parseNearbyFilters(body);
  if (filters.error) return null;
  return { latitude, longitude, radiusKm,
    ...(filters.rat ? { rat: filters.rat } : {}), ...(filters.band ? { band: filters.band } : {}) };
}

function buildNearbyQuery(table, { latitude, longitude, radiusKm, rat, band }) {
  if (!['lte_cell_params', 'nr_cell_params'].includes(table)) throw new Error('invalid_table');
  const filters = parseNearbyFilters({ rat, band });
  if (filters.error) throw new Error(filters.error);
  const selection = selectTableBand(table, filters);
  const angularRadius = radiusKm / EARTH_RADIUS_KM;
  const deltaLat = angularRadius * 180 / Math.PI;
  const minLat = Math.max(-90, latitude - deltaLat);
  const maxLat = Math.min(90, latitude + deltaLat);
  const parameters = [latitude, latitude, longitude, minLat, maxLat];
  let longitudeFilter = '';
  if (minLat > -90 && maxLat < 90) {
    const deltaLon = Math.asin(Math.min(1, Math.sin(angularRadius) /
      Math.cos(latitude * Math.PI / 180))) * 180 / Math.PI;
    const minLon = longitude - deltaLon;
    const maxLon = longitude + deltaLon;
    if (minLon < -180 || maxLon > 180) {
      longitudeFilter = 'AND (longitude >= ? OR longitude <= ?)';
      parameters.push(minLon < -180 ? minLon + 360 : minLon, maxLon > 180 ? maxLon - 360 : maxLon);
    } else {
      longitudeFilter = 'AND longitude BETWEEN ? AND ?';
      parameters.push(minLon, maxLon);
    }
  }
  let bandFilter = '';
  if (selection.excluded) bandFilter = 'AND 1 = 0';
  else if (selection.range) {
    bandFilter = `AND ${table === 'lte_cell_params' ? 'earfcn' : 'nr_arfcn'} BETWEEN ? AND ?`;
    parameters.push(...selection.range);
  }
  parameters.push(radiusKm);
  return {
    sql: `SELECT * FROM (
      SELECT *, ${EARTH_RADIUS_KM} * 2 * ASIN(SQRT(LEAST(1, GREATEST(0,
        POW(SIN(RADIANS(latitude - ?) / 2), 2) +
        COS(RADIANS(?)) * COS(RADIANS(latitude)) *
        POW(SIN(RADIANS(longitude - ?) / 2), 2)
      )))) AS distance_km
      FROM ${table}
      WHERE latitude BETWEEN ? AND ? ${longitudeFilter} ${bandFilter}
        AND longitude BETWEEN -180 AND 180
    ) AS nearby WHERE distance_km <= ?
    ORDER BY distance_km ASC, id ASC LIMIT ${MAX_ROWS_PER_RAT + 1}`,
    parameters
  };
}

function createNearbyRouter(db) {
  const router = express.Router();
  router.post('/cell-params/nearby', async (req, res) => {
    const query = parseQuery(req.body);
    if (!query) {
      const filters = req.body && typeof req.body === 'object' ? parseNearbyFilters(req.body) : {};
      return res.status(400).json({ ok: false,
        error: filters.error || 'invalid_coordinates_or_radius_1_to_10_km' });
    }
    try {
      const results = await Promise.all(['lte_cell_params', 'nr_cell_params'].map(async table => {
        if (selectTableBand(table, query).excluded) return { rows: [], truncated: false };
        const { sql, parameters } = buildNearbyQuery(table, query);
        const [rows] = await db.execute(sql, parameters);
        return { rows: rows.slice(0, MAX_ROWS_PER_RAT), truncated: rows.length > MAX_ROWS_PER_RAT };
      }));
      res.json({
        ok: true, radius_km: query.radiusKm, coordinate_system: 'WGS84',
        rat: query.rat || null, band: query.band || null,
        lte: results[0].rows, nr: results[1].rows,
        lte_truncated: results[0].truncated, nr_truncated: results[1].truncated,
        truncated: results.some(result => result.truncated)
      });
    } catch (error) {
      console.error('Nearby cell query failed:', error.code || error.message);
      res.status(500).json({ ok: false, error: 'nearby_query_failed' });
    }
  });
  return router;
}

module.exports = { createNearbyRouter, parseQuery, buildNearbyQuery, MAX_ROWS_PER_RAT };
