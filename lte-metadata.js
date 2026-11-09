function invalidMetadata(message) {
  return Object.assign(new Error(message), { statusCode: 400 });
}

function readLteMetadata(raw) {
  const extraProvided = Object.hasOwn(raw, 'extra_info') || Object.hasOwn(raw, 'extraInfo');
  const stationProvided = Object.hasOwn(raw, 'station_type') || Object.hasOwn(raw, 'stationType');
  const extra = Object.hasOwn(raw, 'extra_info') ? raw.extra_info : raw.extraInfo;
  if (extra != null && (typeof extra !== 'string' || Buffer.byteLength(extra, 'utf8') > 16777215)) {
    throw invalidMetadata('invalid_extra_info');
  }
  const stationType = String(raw.station_type ?? raw.stationType ?? 'default').trim().toLowerCase() || 'default';
  if (!['default', 'nb-iot'].includes(stationType)) throw invalidMetadata('invalid_station_type');
  return {
    extra_info: extra == null || extra.trim() === '' ? null : extra,
    station_type: stationType,
    extraProvided,
    stationProvided
  };
}

// Keep input order, including repeated cells. Older uploads must not erase metadata.
function* lteMetadataChunks(rows, size) {
  let chunk = [];
  for (const row of rows) {
    if (chunk.length && (chunk.length >= size || row.extraProvided !== chunk[0].extraProvided ||
        row.stationProvided !== chunk[0].stationProvided)) {
      yield chunk;
      chunk = [];
    }
    chunk.push(row);
  }
  if (chunk.length) yield chunk;
}

module.exports = { readLteMetadata, lteMetadataChunks };
