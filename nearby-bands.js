// Downlink channel envelopes, not a claim that overlapping NR bands are uniquely identifiable.
// LTE: 3GPP TS 36.104 v18.5.0, table 5.7.3-1:
// https://www.etsi.org/deliver/etsi_ts/136100_136199/136104/18.05.00_60/ts_136104v180500p.pdf
// NR: 3GPP TS 38.104 v18.9.0, tables 5.4.2.3-1 and 5.4.2.3-2:
// https://www.etsi.org/deliver/etsi_ts/138100_138199/138104/18.09.00_60/ts_138104v180900p.pdf
const BAND_RANGES = {
  LTE: {
    1: [0, 599], 2: [600, 1199], 3: [1200, 1949], 4: [1950, 2399],
    5: [2400, 2649], 6: [2650, 2749], 7: [2750, 3449], 8: [3450, 3799],
    9: [3800, 4149], 10: [4150, 4749], 11: [4750, 4949], 12: [5010, 5179],
    13: [5180, 5279], 14: [5280, 5379], 17: [5730, 5849], 18: [5850, 5999],
    19: [6000, 6149], 20: [6150, 6449], 21: [6450, 6599], 22: [6600, 7399],
    23: [7500, 7699], 24: [7700, 8039], 25: [8040, 8689], 26: [8690, 9039],
    27: [9040, 9209], 28: [9210, 9659], 29: [9660, 9769], 30: [9770, 9869],
    31: [9870, 9919], 32: [9920, 10359], 33: [36000, 36199], 34: [36200, 36349],
    35: [36350, 36949], 36: [36950, 37549], 37: [37550, 37749], 38: [37750, 38249],
    39: [38250, 38649], 40: [38650, 39649], 41: [39650, 41589], 42: [41590, 43589],
    43: [43590, 45589], 44: [45590, 46589], 45: [46590, 46789], 46: [46790, 54539],
    47: [54540, 55239], 48: [55240, 56739], 49: [56740, 58239], 50: [58240, 59089],
    51: [59090, 59139], 52: [59140, 60139], 53: [60140, 60254], 54: [60255, 60304],
    65: [65536, 66435], 66: [66436, 67335], 67: [67336, 67535], 68: [67536, 67835],
    69: [67836, 68335], 70: [68336, 68585], 71: [68586, 68935], 72: [68936, 68985],
    73: [68986, 69035], 74: [69036, 69465], 75: [69466, 70315], 76: [70316, 70365],
    85: [70366, 70545], 87: [70546, 70595], 88: [70596, 70645], 103: [70646, 70655],
    106: [70656, 70705], 107: [70706, 71105], 108: [71106, 73385]
  },
  NR: {
    1: [422000, 434000], 2: [386000, 398000], 3: [361000, 376000],
    5: [173800, 178800], 7: [524000, 538000], 8: [185000, 192000],
    12: [145800, 149200], 13: [149200, 151200], 14: [151600, 153600],
    18: [172000, 175000], 20: [158200, 164200], 24: [305000, 311800],
    25: [386000, 399000], 26: [171800, 178800], 28: [151600, 160600],
    29: [143400, 145600], 30: [470000, 472000], 31: [92500, 93500],
    34: [402000, 405000], 38: [514000, 524000], 39: [376000, 384000],
    40: [460000, 480000], 41: [499200, 537999], 46: [743334, 795000],
    48: [636667, 646666], 50: [286400, 303400], 51: [285400, 286400],
    53: [496700, 499000], 54: [334000, 335000], 65: [422000, 440000],
    66: [422000, 440000], 67: [147600, 151600], 70: [399000, 404000],
    71: [123400, 130400], 72: [92200, 93200], 74: [295000, 303600],
    75: [286400, 303400], 76: [285400, 286400], 77: [620000, 680000],
    78: [620000, 653333], 79: [693334, 733333], 85: [145600, 149200],
    90: [499200, 538000], 91: [285400, 286400], 92: [286400, 303400],
    93: [285400, 286400], 94: [286400, 303400], 96: [795000, 875000],
    100: [183880, 185000], 101: [380000, 382000], 102: [795000, 828333],
    104: [828334, 875000], 105: [122400, 130400], 106: [187000, 188000],
    109: [286400, 303400], 257: [2054166, 2104165], 258: [2016667, 2070832],
    259: [2270833, 2337499], 260: [2229166, 2279165], 261: [2070833, 2084999],
    262: [2399166, 2415832]
  }
};

function parseNearbyFilters(body = {}) {
  let rat = null;
  if (body.rat != null) {
    if (typeof body.rat !== 'string') return { error: 'invalid_rat' };
    const value = body.rat.trim().toUpperCase();
    const aliases = { LTE: 'LTE', '4G': 'LTE', NR: 'NR', '5G': 'NR' };
    if (value && value !== 'ALL') {
      rat = aliases[value];
      if (!rat) return { error: 'invalid_rat' };
    }
  }
  if (body.band == null || typeof body.band === 'string' && !body.band.trim()) return { rat, band: null };
  if (typeof body.band !== 'string' && typeof body.band !== 'number') return { error: 'invalid_band' };
  const match = /^([bn])?([1-9]\d{0,2})$/i.exec(String(body.band).trim());
  if (!match) return { error: 'invalid_band' };
  const prefixRat = match[1] ? (match[1].toLowerCase() === 'b' ? 'LTE' : 'NR') : null;
  if (rat && prefixRat && rat !== prefixRat) return { error: 'band_rat_mismatch' };
  const number = Number(match[2]);
  const candidates = [rat || prefixRat].filter(Boolean);
  if (!candidates.length) candidates.push('LTE', 'NR');
  if (!candidates.some(candidate => BAND_RANGES[candidate][number])) return { error: 'invalid_band' };
  return { rat, band: (prefixRat === 'LTE' ? 'B' : prefixRat === 'NR' ? 'n' : '') + number };
}

function selectTableBand(table, filters) {
  const rat = table === 'lte_cell_params' ? 'LTE' : 'NR';
  if (filters.rat && filters.rat !== rat) return { excluded: true };
  if (filters.band == null) return { excluded: false, range: null };
  const match = /^([Bn])?(\d+)$/.exec(filters.band);
  const prefixRat = match[1] ? (match[1] === 'B' ? 'LTE' : 'NR') : null;
  if (prefixRat && prefixRat !== rat) return { excluded: true };
  const range = BAND_RANGES[rat][Number(match[2])];
  return { excluded: !range, range };
}

module.exports = { BAND_RANGES, parseNearbyFilters, selectTableBand };
